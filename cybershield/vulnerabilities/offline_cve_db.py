"""Offline National Vulnerability Database (NVD) & CISA KEV Knowledge Repository.

Provides structured local intelligence on landmark enterprise CVEs, complete with CVSS v3.1
vectors, affected CPE 2.3 expressions, semantic version ranges, and prioritized remediation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class OfflineCVEEntry:
    """Offline vulnerability definition with CPE mapping and exploit metrics."""
    cve_id: str
    title: str
    cwe_id: str
    cvss_base_score: float
    cvss_vector: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    affected_cpes: List[str]
    affected_version_range: str
    is_cisa_kev: bool
    epss_score: float
    summary: str
    remediation: str
    mitre_attack_ids: List[str] = field(default_factory=list)


OFFLINE_CVE_REPOSITORY: Dict[str, OfflineCVEEntry] = {
    "CVE-2021-44228": OfflineCVEEntry(
        cve_id="CVE-2021-44228",
        title="Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        cwe_id="CWE-502",
        cvss_base_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity="CRITICAL",
        affected_cpes=["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
        affected_version_range=">= 2.0.0, <= 2.14.1",
        is_cisa_kev=True,
        epss_score=0.9752,
        summary="Apache Log4j2 JNDI parser processes message lookup substitutions without sanitizing LDAP/RMI endpoints, enabling unrestricted remote code execution.",
        remediation="Upgrade to Apache Log4j 2.17.1 or newer, or remove JndiLookup.class from log4j-core JAR.",
        mitre_attack_ids=["T1190", "T1059"]
    ),
    "CVE-2017-0144": OfflineCVEEntry(
        cve_id="CVE-2017-0144",
        title="Microsoft Windows SMBv1 Remote Code Execution (EternalBlue / MS17-010)",
        cwe_id="CWE-787",
        cvss_base_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        affected_cpes=[
            "cpe:2.3:o:microsoft:windows_7:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_server_2008:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"
        ],
        affected_version_range="< 10.0.15063",
        is_cisa_kev=True,
        epss_score=0.9748,
        summary="Buffer overflow in SMBv1 allows unauthenticated remote attackers to send specially crafted packets and execute code with SYSTEM privileges.",
        remediation="Apply Microsoft security update MS17-010 and completely disable the deprecated SMBv1 protocol.",
        mitre_attack_ids=["T1210", "T1068"]
    ),
    "CVE-2019-0708": OfflineCVEEntry(
        cve_id="CVE-2019-0708",
        title="Microsoft Windows Remote Desktop Services Remote Code Execution (BlueKeep)",
        cwe_id="CWE-416",
        cvss_base_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        affected_cpes=[
            "cpe:2.3:o:microsoft:windows_7:*:*:*:*:*:*:*:*",
            "cpe:2.3:o:microsoft:windows_server_2008_r2:*:*:*:*:*:*:*:*"
        ],
        affected_version_range="< 6.1.7601.24441",
        is_cisa_kev=True,
        epss_score=0.9680,
        summary="Use-after-free vulnerability in Remote Desktop Protocol (RDP) allows unauthenticated remote code execution without user interaction.",
        remediation="Install Microsoft Security Advisory updates and enforce Network Level Authentication (NLA) on RDP.",
        mitre_attack_ids=["T1210"]
    ),
    "CVE-2021-26855": OfflineCVEEntry(
        cve_id="CVE-2021-26855",
        title="Microsoft Exchange Server Pre-Auth SSRF (ProxyLogon)",
        cwe_id="CWE-918",
        cvss_base_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        affected_cpes=["cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"],
        affected_version_range=">= 2013, <= 2019",
        is_cisa_kev=True,
        epss_score=0.9715,
        summary="Server-Side Request Forgery vulnerability allows an unauthenticated remote attacker to bypass authentication and impersonate any user on Microsoft Exchange.",
        remediation="Apply Microsoft Security Updates KB5000871 immediately.",
        mitre_attack_ids=["T1190", "T1078"]
    ),
    "CVE-2021-34527": OfflineCVEEntry(
        cve_id="CVE-2021-34527",
        title="Windows Print Spooler Remote Code Execution (PrintNightmare)",
        cwe_id="CWE-269",
        cvss_base_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        severity="HIGH",
        affected_cpes=["cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"],
        affected_version_range="*",
        is_cisa_kev=True,
        epss_score=0.9650,
        summary="The Windows Print Spooler service improperly performs privileged file operations, enabling authenticated users to install malicious printer drivers with SYSTEM privileges.",
        remediation="Disable Print Spooler service on domain controllers and apply Microsoft KB5004945.",
        mitre_attack_ids=["T1068", "T1547.012"]
    ),
    "CVE-2022-22965": OfflineCVEEntry(
        cve_id="CVE-2022-22965",
        title="Spring Framework Remote Code Execution via DataBinder (Spring4Shell)",
        cwe_id="CWE-94",
        cvss_base_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        affected_cpes=["cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*"],
        affected_version_range=">= 5.3.0, < 5.3.18",
        is_cisa_kev=True,
        epss_score=0.9520,
        summary="Spring MVC or Spring WebFlux application running on JDK 9+ allows ClassLoader property manipulation via parameter binding, resulting in arbitrary webshell dropping.",
        remediation="Upgrade Spring Framework to version 5.3.18 or 5.2.20 or newer.",
        mitre_attack_ids=["T1190", "T1505.003"]
    ),
    "CVE-2023-34362": OfflineCVEEntry(
        cve_id="CVE-2023-34362",
        title="Progress Software MOVEit Transfer SQL Injection Vulnerability",
        cwe_id="CWE-89",
        cvss_base_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        severity="CRITICAL",
        affected_cpes=["cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*"],
        affected_version_range="< 2023.0.1",
        is_cisa_kev=True,
        epss_score=0.9740,
        summary="SQL injection vulnerability in the MOVEit Transfer web application could allow an unauthenticated attacker to gain unauthorized access to the database and execute code.",
        remediation="Apply vendor patch released in May/June 2023 and inspect IIS logs for guestaccess.aspx anomalies.",
        mitre_attack_ids=["T1190", "T1567"]
    ),
    "CVE-2023-4966": OfflineCVEEntry(
        cve_id="CVE-2023-4966",
        title="Citrix NetScaler ADC / Gateway Information Disclosure (Citrix Bleed)",
        cwe_id="CWE-125",
        cvss_base_score=9.4,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        severity="CRITICAL",
        affected_cpes=[
            "cpe:2.3:a:citrix:netscaler_adc:*:*:*:*:*:*:*:*",
            "cpe:2.3:a:citrix:netscaler_gateway:*:*:*:*:*:*:*:*"
        ],
        affected_version_range=">= 13.0, < 13.1-49.13",
        is_cisa_kev=True,
        epss_score=0.9690,
        summary="Out-of-bounds memory read in NetScaler ADC and Gateway allows unauthenticated attackers to dump memory containing valid session tokens and bypass MFA.",
        remediation="Update NetScaler to fixed firmware builds and terminate all existing active ICA/VPN sessions.",
        mitre_attack_ids=["T1190", "T1539"]
    ),
    "CVE-2024-21887": OfflineCVEEntry(
        cve_id="CVE-2024-21887",
        title="Ivanti Connect Secure and Policy Secure Command Injection Vulnerability",
        cwe_id="CWE-78",
        cvss_base_score=9.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
        severity="CRITICAL",
        affected_cpes=["cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"],
        affected_version_range="<= 22.6R2",
        is_cisa_kev=True,
        epss_score=0.9620,
        summary="Command injection in web components of Ivanti Connect Secure allows an authenticated administrator (or chained pre-auth actor) to send crafted requests and execute arbitrary commands.",
        remediation="Import Ivanti mitigation XML and upgrade to patched firmware release.",
        mitre_attack_ids=["T1190", "T1059"]
    ),
    "CVE-2024-3400": OfflineCVEEntry(
        cve_id="CVE-2024-3400",
        title="Palo Alto Networks PAN-OS GlobalProtect Command Injection Zero-Day",
        cwe_id="CWE-78",
        cvss_base_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity="CRITICAL",
        affected_cpes=["cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"],
        affected_version_range=">= 10.2, <= 11.1",
        is_cisa_kev=True,
        epss_score=0.9580,
        summary="Command injection vulnerability in the GlobalProtect gateway feature of PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges.",
        remediation="Apply hotfix updates released for PAN-OS 10.2, 11.0, and 11.1, and enable Threat Prevention signature 95187.",
        mitre_attack_ids=["T1190", "T1059.004"]
    ),
    "CVE-2014-0160": OfflineCVEEntry(
        cve_id="CVE-2014-0160",
        title="OpenSSL TLS Heartbeat Information Disclosure (Heartbleed)",
        cwe_id="CWE-125",
        cvss_base_score=7.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        severity="HIGH",
        affected_cpes=["cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"],
        affected_version_range=">= 1.0.1, <= 1.0.1f",
        is_cisa_kev=True,
        epss_score=0.9410,
        summary="Missing bounds check in TLS heartbeat extension allows attackers to read up to 64KB of server memory per heartbeat, exposing private keys and credentials.",
        remediation="Upgrade OpenSSL to 1.0.1g or newer and revoke/reissue SSL/TLS certificates.",
        mitre_attack_ids=["T1005"]
    ),
    "CVE-2020-1472": OfflineCVEEntry(
        cve_id="CVE-2020-1472",
        title="Microsoft Netlogon Elevation of Privilege (Zerologon)",
        cwe_id="CWE-327",
        cvss_base_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        severity="CRITICAL",
        affected_cpes=["cpe:2.3:o:microsoft:windows_server:*:*:*:*:*:*:*:*"],
        affected_version_range=">= 2008, <= 2019",
        is_cisa_kev=True,
        epss_score=0.9630,
        summary="Insecure initialization vector (IV) in Netlogon AES-CFB8 implementation allows unauthenticated attackers to reset domain controller passwords to blank.",
        remediation="Install August 2020 Microsoft cumulative updates and enable DC enforcement mode.",
        mitre_attack_ids=["T1068", "T1078"]
    )
}


class OfflineCVEDatabase:
    """Offline querying and correlation engine for national vulnerability intelligence."""

    @classmethod
    def get_cve(cls, cve_id: str) -> Optional[OfflineCVEEntry]:
        """Retrieve CVE record by identifier."""
        return OFFLINE_CVE_REPOSITORY.get(cve_id.strip().upper())

    @classmethod
    def list_cves(
        cls,
        severity: Optional[str] = None,
        is_kev_only: bool = False,
    ) -> List[OfflineCVEEntry]:
        """Filter offline vulnerability repository."""
        entries = list(OFFLINE_CVE_REPOSITORY.values())
        if severity:
            entries = [e for e in entries if e.severity.upper() == severity.upper()]
        if is_kev_only:
            entries = [e for e in entries if e.is_cisa_kev]
        return entries

    @classmethod
    def find_vulnerabilities_for_package(
        cls,
        vendor: str,
        product: str,
        version: str,
    ) -> List[OfflineCVEEntry]:
        """Find matching CVEs for an installed vendor, product, and version."""
        from cybershield.vulnerabilities.cpe_matcher import CPEMatcher

        matched: List[OfflineCVEEntry] = []
        for entry in OFFLINE_CVE_REPOSITORY.values():
            for cpe in entry.affected_cpes:
                if CPEMatcher.is_match(
                    pkg_vendor=vendor,
                    pkg_product=product,
                    installed_version=version,
                    target_cpe_str=cpe,
                    affected_version_range=entry.affected_version_range,
                ):
                    matched.append(entry)
                    break
        return matched
