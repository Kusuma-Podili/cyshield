"""AWS CloudTrail Event Parser and Threat Detection Engine.

Analyzes raw AWS CloudTrail JSON audit event records for high-impact security threats,
IAM privilege escalations, defense evasion, publicly exposed resources, and root compromise.
Produces structured CloudSecurityFinding objects mapped to MITRE ATT&CK Cloud Matrix.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Dict, List, Optional

from cybershield.cloud.schemas import (
    CloudFindingSeverity,
    CloudProvider,
    CloudSecurityFinding,
)

logger = logging.getLogger("cybershield.cloud.cloudtrail")

# Sensitive ports whose exposure to 0.0.0.0/0 indicates high/critical risk
SENSITIVE_PORTS = {
    22: "SSH Management",
    3389: "RDP Management",
    445: "SMB File Sharing",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    3306: "MySQL Database",
    5432: "PostgreSQL Database",
    6379: "Redis In-Memory Store",
    9200: "Elasticsearch REST API",
    27017: "MongoDB Database",
    8080: "HTTP Alternative / Proxy",
    8443: "HTTPS Alternative / Proxy",
}


class CloudTrailParser:
    """Enterprise parser for AWS CloudTrail records detecting security policy breaches."""

    def __init__(self) -> None:
        self.rules = [
            self._check_root_account_usage,
            self._check_cloudtrail_tampering,
            self._check_guardduty_tampering,
            self._check_kms_tampering,
            self._check_iam_privilege_escalation,
            self._check_iam_access_key_creation,
            self._check_s3_public_exposure,
            self._check_security_group_ingress_open,
            self._check_snapshot_public_sharing,
            self._check_config_service_tampering,
        ]

    def parse_and_audit(self, records: List[Dict[str, Any]]) -> List[CloudSecurityFinding]:
        """Audit a batch of CloudTrail records against cloud security rules."""
        findings: List[CloudSecurityFinding] = []
        for rec in records:
            if not isinstance(rec, dict):
                continue
            for rule in self.rules:
                try:
                    res = rule(rec)
                    if res:
                        if isinstance(res, list):
                            findings.extend(res)
                        else:
                            findings.append(res)
                except Exception as e:
                    logger.debug("CloudTrail rule execution error: %s", e)
        return findings

    def _check_root_account_usage(self, rec: Dict[str, Any]) -> Optional[CloudSecurityFinding]:
        user_identity = rec.get("userIdentity", {})
        user_type = user_identity.get("type", "")
        event_name = rec.get("eventName", "")

        if user_type == "Root":
            # Check if console login without MFA
            add_data = rec.get("additionalEventData", {})
            mfa_used = add_data.get("MFAUsed", "No")
            severity = CloudFindingSeverity.CRITICAL if mfa_used != "Yes" else CloudFindingSeverity.HIGH
            
            return CloudSecurityFinding(
                finding_id=f"CT-ROOT-{uuid.uuid4().hex[:8]}",
                provider=CloudProvider.AWS,
                severity=severity,
                title="AWS Root Account Activity Detected",
                description=(
                    f"AWS Root account invoked action '{event_name}' from IP '{rec.get('sourceIPAddress', 'unknown')}'. "
                    f"Console MFA Status: {mfa_used}."
                ),
                resource_id=user_identity.get("arn", "arn:aws:iam::root"),
                mitre_technique="T1078.004 - Valid Accounts: Cloud Accounts",
                remediation="Lock down Root account credentials, enforce hardware MFA, and utilize scoped IAM Identity Center roles.",
            )
        return None

    def _check_cloudtrail_tampering(self, rec: Dict[str, Any]) -> Optional[CloudSecurityFinding]:
        event_name = rec.get("eventName", "")
        if event_name in ("StopLogging", "DeleteTrail", "UpdateTrail"):
            req_params = rec.get("requestParameters", {}) or {}
            trail_name = req_params.get("name", "unknown-trail")
            return CloudSecurityFinding(
                finding_id=f"CT-EVASION-{uuid.uuid4().hex[:8]}",
                provider=CloudProvider.AWS,
                severity=CloudFindingSeverity.CRITICAL,
                title=f"CloudTrail Audit Logging Disabled/Tampered ({event_name})",
                description=(
                    f"User '{rec.get('userIdentity', {}).get('userName', 'unknown')}' called '{event_name}' on trail '{trail_name}'."
                ),
                resource_id=trail_name,
                mitre_technique="T1562.001 - Impair Defenses: Disable or Modify Tools",
                remediation="Immediately re-enable CloudTrail logging, investigate the caller IAM entity, and apply SCP to prevent StopLogging.",
            )
        return None

    def _check_guardduty_tampering(self, rec: Dict[str, Any]) -> Optional[CloudSecurityFinding]:
        event_name = rec.get("eventName", "")
        if event_name in ("DeleteDetector", "DisassociateFromMasterAccount", "ArchiveFindings"):
            return CloudSecurityFinding(
                finding_id=f"CT-GD-TAMPER-{uuid.uuid4().hex[:8]}",
                provider=CloudProvider.AWS,
                severity=CloudFindingSeverity.HIGH,
                title=f"Amazon GuardDuty Tampering Detected ({event_name})",
                description=f"GuardDuty threat detection was impaired via '{event_name}'.",
                resource_id=rec.get("requestParameters", {}).get("detectorId", "guardduty-detector"),
                mitre_technique="T1562.001 - Impair Defenses: Disable or Modify Tools",
                remediation="Re-enable GuardDuty detectors, audit caller credentials for compromise, and establish SCP guardrails.",
            )
        return None

    def _check_kms_tampering(self, rec: Dict[str, Any]) -> Optional[CloudSecurityFinding]:
        event_name = rec.get("eventName", "")
        if event_name in ("DisableKey", "ScheduleKeyDeletion"):
            key_id = rec.get("requestParameters", {}).get("keyId", "unknown-key")
            return CloudSecurityFinding(
                finding_id=f"CT-KMS-TAMPER-{uuid.uuid4().hex[:8]}",
                provider=CloudProvider.AWS,
                severity=CloudFindingSeverity.HIGH,
                title=f"KMS Customer Managed Key Deactivation ({event_name})",
                description=f"Action '{event_name}' was scheduled on encryption key '{key_id}', risking data unavailability.",
                resource_id=key_id,
                mitre_technique="T1486 - Data Encrypted for Impact / Denial of Service",
                remediation="Verify if key deletion was intentional. Cancel key deletion within KMS console before grace period ends.",
            )
        return None

    def _check_iam_privilege_escalation(self, rec: Dict[str, Any]) -> Optional[CloudSecurityFinding]:
        event_name = rec.get("eventName", "")
        if event_name in ("AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"):
            req_params = rec.get("requestParameters", {}) or {}
            policy_arn = req_params.get("policyArn", "")
            target_entity = (
                req_params.get("userName")
                or req_params.get("roleName")
                or req_params.get("groupName")
                or "unknown-principal"
            )
            if "AdministratorAccess" in policy_arn or policy_arn.endswith("/AdministratorAccess"):
                return CloudSecurityFinding(
                    finding_id=f"CT-IAM-ESC-{uuid.uuid4().hex[:8]}",
                    provider=CloudProvider.AWS,
                    severity=CloudFindingSeverity.CRITICAL,
                    title="IAM AdministratorAccess Policy Attached",
                    description=(
                        f"Unrestricted AdministratorAccess policy '{policy_arn}' was attached to '{target_entity}'."
                    ),
                    resource_id=target_entity,
                    mitre_technique="T1098 - Account Manipulation",
                    remediation="Revoke full administrator privileges. Enforce least-privilege IAM policies with specific resource ARNs.",
                )
        return None

    def _check_iam_access_key_creation(self, rec: Dict[str, Any]) -> Optional[CloudSecurityFinding]:
        event_name = rec.get("eventName", "")
        if event_name == "CreateAccessKey":
            req_params = rec.get("requestParameters", {}) or {}
            target_user = req_params.get("userName", "caller")
            caller_user = rec.get("userIdentity", {}).get("userName", "unknown")
            return CloudSecurityFinding(
                finding_id=f"CT-IAM-KEY-{uuid.uuid4().hex[:8]}",
                provider=CloudProvider.AWS,
                severity=CloudFindingSeverity.MEDIUM,
                title="New IAM Long-Lived Access Key Created",
                description=f"IAM access key generated for user '{target_user}' by caller '{caller_user}'.",
                resource_id=target_user,
                mitre_technique="T1098.001 - Account Manipulation: Additional Cloud Credentials",
                remediation="Prefer short-lived STS credentials or IAM roles for applications. Enforce 90-day access key rotation.",
            )
        return None

    def _check_s3_public_exposure(self, rec: Dict[str, Any]) -> Optional[CloudSecurityFinding]:
        event_name = rec.get("eventName", "")
        req_params = rec.get("requestParameters", {}) or {}
        bucket_name = req_params.get("bucketName", "unknown-bucket")

        if event_name in ("PutBucketPolicy", "PutBucketAcl"):
            policy_str = req_params.get("bucketPolicy", "") or json.dumps(req_params)
            # Check for Principal: * or wildcard access
            if '"Principal":"*"' in policy_str or '"Principal": "*"' in policy_str or "AllUsers" in policy_str:
                return CloudSecurityFinding(
                    finding_id=f"CT-S3-PUB-{uuid.uuid4().hex[:8]}",
                    provider=CloudProvider.AWS,
                    severity=CloudFindingSeverity.CRITICAL,
                    title="S3 Bucket Exposed to Public / Wildcard Access",
                    description=f"Bucket '{bucket_name}' policy/ACL allows unrestricted anonymous read/write access (*).",
                    resource_id=f"arn:aws:s3:::{bucket_name}",
                    mitre_technique="T1530 - Data from Cloud Storage Object",
                    remediation="Enable S3 Block Public Access at account and bucket level immediately.",
                )
        return None

    def _check_security_group_ingress_open(self, rec: Dict[str, Any]) -> List[CloudSecurityFinding]:
        findings: List[CloudSecurityFinding] = []
        event_name = rec.get("eventName", "")
        if event_name in ("AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"):
            req_params = rec.get("requestParameters", {}) or {}
            group_id = req_params.get("groupId", "sg-unknown")
            ip_permissions = req_params.get("ipPermissions", {})
            items = ip_permissions.get("items", []) if isinstance(ip_permissions, dict) else []

            for item in items:
                from_port = item.get("fromPort")
                to_port = item.get("toPort")
                ip_ranges = item.get("ipRanges", {}).get("items", []) if isinstance(item.get("ipRanges"), dict) else []

                is_anywhere = any(
                    r.get("cidrIp") == "0.0.0.0/0" for r in ip_ranges if isinstance(r, dict)
                )

                if is_anywhere and from_port is not None:
                    # Check if port matches any sensitive port
                    for port, desc in SENSITIVE_PORTS.items():
                        if from_port <= port <= (to_port or from_port):
                            findings.append(
                                CloudSecurityFinding(
                                    finding_id=f"CT-SG-OPEN-{uuid.uuid4().hex[:8]}",
                                    provider=CloudProvider.AWS,
                                    severity=CloudFindingSeverity.CRITICAL if port in (22, 3389, 445) else CloudFindingSeverity.HIGH,
                                    title=f"Security Group Opens Port {port} ({desc}) to the Internet",
                                    description=(
                                        f"Security Group '{group_id}' grants 0.0.0.0/0 inbound access to {desc} on port {port}."
                                    ),
                                    resource_id=group_id,
                                    mitre_technique="T1046 - Network Service Discovery",
                                    remediation=f"Restrict port {port} ingress to authorized enterprise bastion or VPN IP ranges.",
                                )
                            )
        return findings

    def _check_snapshot_public_sharing(self, rec: Dict[str, Any]) -> Optional[CloudSecurityFinding]:
        event_name = rec.get("eventName", "")
        if event_name == "ModifySnapshotAttribute":
            req_params = rec.get("requestParameters", {}) or {}
            create_vol = req_params.get("createVolumePermission", {})
            adds = create_vol.get("add", {}).get("items", []) if isinstance(create_vol.get("add"), dict) else []
            for item in adds:
                if item.get("group") == "all":
                    snapshot_id = req_params.get("snapshotId", "snap-unknown")
                    return CloudSecurityFinding(
                        finding_id=f"CT-EBS-PUB-{uuid.uuid4().hex[:8]}",
                        provider=CloudProvider.AWS,
                        severity=CloudFindingSeverity.CRITICAL,
                        title="EBS Volume Snapshot Made Publicly Available",
                        description=f"Snapshot '{snapshot_id}' permissions were modified to allow public duplication (group: all).",
                        resource_id=snapshot_id,
                        mitre_technique="T1537 - Transfer Data to Cloud Account",
                        remediation="Revoke public sharing permissions on the EBS snapshot immediately.",
                    )
        return None

    def _check_config_service_tampering(self, rec: Dict[str, Any]) -> Optional[CloudSecurityFinding]:
        event_name = rec.get("eventName", "")
        if event_name in ("StopConfigurationRecorder", "DeleteDeliveryChannel"):
            return CloudSecurityFinding(
                finding_id=f"CT-CFG-TAMPER-{uuid.uuid4().hex[:8]}",
                provider=CloudProvider.AWS,
                severity=CloudFindingSeverity.HIGH,
                title=f"AWS Config Service Impaired ({event_name})",
                description=f"Continuous compliance recording was stopped via '{event_name}'.",
                resource_id="aws-config-recorder",
                mitre_technique="T1562.001 - Impair Defenses: Disable or Modify Tools",
                remediation="Restart the AWS Config recorder to maintain compliance audit trails.",
            )
        return None
