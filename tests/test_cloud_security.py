"""Unit & Integration Tests for Cloud & Container Security (CSPM / CWPP)."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.cloud.aws_cloudtrail_parser import CloudTrailParser
from cybershield.cloud.container_runtime import ContainerRuntimeDetector
from cybershield.cloud.engine import cloud_engine
from cybershield.cloud.k8s_scanner import K8sManifestScanner
from cybershield.cloud.schemas import (
    CloudFindingSeverity,
    CloudProvider,
    ContainerProcessInspectRequest,
)

INSECURE_K8S_YAML = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-workload
  namespace: production
spec:
  replicas: 1
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
            runAsUser: 0
            readOnlyRootFilesystem: false
            capabilities:
              add: ["SYS_ADMIN", "NET_ADMIN"]
          volumeMounts:
            - mountPath: /var/run/docker.sock
              name: dockersock
      volumes:
        - name: dockersock
          hostPath:
            path: /var/run/docker.sock
"""

SECURE_K8S_YAML = """
apiVersion: v1
kind: Pod
metadata:
  name: secure-workload
  namespace: default
spec:
  containers:
    - name: hardened-worker
      image: alpine:3.18
      securityContext:
        privileged: false
        runAsNonRoot: true
        runAsUser: 10001
        readOnlyRootFilesystem: true
        allowPrivilegeEscalation: false
        capabilities:
          drop: ["ALL"]
      resources:
        limits:
          cpu: "500m"
          memory: "512Mi"
        requests:
          cpu: "100m"
          memory: "128Mi"
"""


def test_k8s_scanner_detects_violations():
    scanner = K8sManifestScanner()
    result = scanner.scan_manifest_str(INSECURE_K8S_YAML)
    assert not result.is_compliant
    assert result.total_violations >= 5
    severities = [f.severity for f in result.findings]
    assert CloudFindingSeverity.CRITICAL in severities
    assert any("Privileged Container" in f.title for f in result.findings)
    assert any("Host Process or IPC Namespace" in f.title for f in result.findings)
    assert any("HostPath Volume" in f.title for f in result.findings)


def test_k8s_scanner_hardened_pod():
    scanner = K8sManifestScanner()
    result = scanner.scan_manifest_str(SECURE_K8S_YAML)
    assert result.is_compliant
    assert result.total_violations == 0


def test_cloudtrail_root_login_detection():
    parser = CloudTrailParser()
    records = [
        {
            "eventVersion": "1.08",
            "userIdentity": {"type": "Root", "principalId": "123456789012", "arn": "arn:aws:iam::123456789012:root"},
            "eventName": "ConsoleLogin",
            "sourceIPAddress": "198.51.100.23",
            "additionalEventData": {"MFAUsed": "No"},
        }
    ]
    findings = parser.parse_and_audit(records)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == CloudFindingSeverity.CRITICAL
    assert "Root Account Activity" in f.title
    assert "T1078.004" in f.mitre_technique


def test_cloudtrail_defense_evasion_and_iam_escalation():
    parser = CloudTrailParser()
    records = [
        {
            "eventName": "StopLogging",
            "userIdentity": {"userName": "attacker"},
            "requestParameters": {"name": "main-audit-trail"},
        },
        {
            "eventName": "AttachUserPolicy",
            "userIdentity": {"userName": "attacker"},
            "requestParameters": {
                "userName": "backdoor-user",
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
            },
        },
        {
            "eventName": "AuthorizeSecurityGroupIngress",
            "requestParameters": {
                "groupId": "sg-0123456789abcdef0",
                "ipPermissions": {
                    "items": [
                        {
                            "fromPort": 22,
                            "toPort": 22,
                            "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                        }
                    ]
                },
            },
        },
    ]
    findings = parser.parse_and_audit(records)
    assert len(findings) == 3
    titles = [f.title for f in findings]
    assert any("CloudTrail Audit Logging Disabled" in t for t in titles)
    assert any("IAM AdministratorAccess Policy Attached" in t for t in titles)
    assert any("Security Group Opens Port 22" in t for t in titles)


def test_container_runtime_breakout_detection():
    detector = ContainerRuntimeDetector()
    req = ContainerProcessInspectRequest(
        container_id="c-escape-001",
        image_name="malicious-alpine:latest",
        command_line="nsenter --target 1 --mount --uts --ipc --net --pid /bin/bash",
        working_dir="/",
        mounts=["/var/run/docker.sock"],
        capabilities=["CAP_SYS_ADMIN"],
    )
    alerts = detector.inspect_process(req)
    assert len(alerts) >= 3
    titles = [a.title for a in alerts]
    assert any("Container Breakout Attempt" in t for t in titles)
    assert any("Sensitive Host Path Mounted" in t for t in titles)
    assert any("Excessive Linux Capability Attached" in t for t in titles)


def test_container_runtime_cryptominer():
    detector = ContainerRuntimeDetector()
    req = ContainerProcessInspectRequest(
        container_id="c-miner-002",
        image_name="busybox:latest",
        command_line="/dev/shm/xmrig -o stratum+tcp://xmr-pool.org:3333 -u 48xyz",
        working_dir="/dev/shm",
    )
    alerts = detector.inspect_process(req)
    assert len(alerts) >= 2
    titles = [a.title for a in alerts]
    assert any("Cryptomining Activity Detected" in t for t in titles)
    assert any("Ephemeral/RAM Path" in t for t in titles)


def test_cloud_security_engine_posture():
    cloud_engine.clear()
    # Scan vulnerable manifest
    cloud_engine.scan_k8s_manifest(INSECURE_K8S_YAML, dispatch_events=False)
    posture = cloud_engine.get_posture(provider=CloudProvider.KUBERNETES)
    assert posture.total_findings > 0
    assert posture.compliance_score < 100.0


@pytest.mark.asyncio
async def test_cloud_api_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Authenticate as superadmin
        login_resp = await ac.post(
            "/api/auth/login",
            json={"username_or_email": "superadmin", "password": "CyberShield2026!"},
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Test K8s scan endpoint
        resp = await ac.post(
            "/api/cloud/k8s/scan",
            json={"manifest_raw": SECURE_K8S_YAML},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_compliant"] is True

        # Test CloudTrail audit endpoint
        ct_req = {
            "records": [
                {
                    "eventName": "DeleteTrail",
                    "userIdentity": {"userName": "compromised-admin"},
                    "requestParameters": {"name": "corp-trail"},
                }
            ]
        }
        resp = await ac.post(
            "/api/cloud/aws/cloudtrail",
            json=ct_req,
            headers=headers,
        )
        assert resp.status_code == 200
        findings = resp.json()
        assert len(findings) == 1
        assert "DeleteTrail" in findings[0]["title"]

        # Test Posture endpoint
        resp = await ac.get("/api/cloud/posture", headers=headers)
        assert resp.status_code == 200
        posture = resp.json()
        assert "compliance_score" in posture

        # Test Findings endpoint
        resp = await ac.get("/api/cloud/findings", headers=headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
