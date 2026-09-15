"""Local Vulnerability Catalog & CVSS v3.1 Calculator for CyberShield Enterprise.

Enables asset vulnerability correlation and dynamic CVSS base score calculation
without reaching out to external NIST / NVD APIs.
"""

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Any

from cybershield.core.models import (
    CVECatalogEntry,
    CVSSMetrics,
    Severity,
)

logger = logging.getLogger("cybershield.intel.cve")


class CVSSv31Calculator:
    """Official FIRST CVSS v3.1 Base Metric Calculator."""

    AV_VALUES = {"NETWORK": 0.85, "ADJACENT": 0.62, "LOCAL": 0.55, "PHYSICAL": 0.20}
    AC_VALUES = {"LOW": 0.77, "HIGH": 0.44}
    PR_UNCHANGED = {"NONE": 0.85, "LOW": 0.62, "HIGH": 0.27}
    PR_CHANGED = {"NONE": 0.85, "LOW": 0.68, "HIGH": 0.50}
    UI_VALUES = {"NONE": 0.85, "REQUIRED": 0.62}
    CIA_VALUES = {"NONE": 0.0, "LOW": 0.22, "HIGH": 0.56}

    @classmethod
    def calculate(
        cls,
        av: str = "NETWORK",
        ac: str = "LOW",
        pr: str = "NONE",
        ui: str = "NONE",
        scope: str = "UNCHANGED",
        conf: str = "HIGH",
        integ: str = "HIGH",
        avail: str = "HIGH",
    ) -> CVSSMetrics:
        """Compute standard CVSS v3.1 Base Score."""
        av_val = cls.AV_VALUES.get(av.upper(), 0.85)
        ac_val = cls.AC_VALUES.get(ac.upper(), 0.77)
        ui_val = cls.UI_VALUES.get(ui.upper(), 0.85)

        is_scope_changed = scope.upper() == "CHANGED"
        pr_dict = cls.PR_CHANGED if is_scope_changed else cls.PR_UNCHANGED
        pr_val = pr_dict.get(pr.upper(), 0.85)

        c_val = cls.CIA_VALUES.get(conf.upper(), 0.56)
        i_val = cls.CIA_VALUES.get(integ.upper(), 0.56)
        a_val = cls.CIA_VALUES.get(avail.upper(), 0.56)

        # ISS = 1 - [ (1 - C) * (1 - I) * (1 - A) ]
        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

        # Impact calculation
        if is_scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss

        # Exploitability calculation
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # Base score rounding
        if impact <= 0:
            base_score = 0.0
        else:
            if not is_scope_changed:
                raw_score = min(impact + exploitability, 10.0)
            else:
                raw_score = min(1.08 * (impact + exploitability), 10.0)
            # Ceiling to 1 decimal place as per CVSS spec
            base_score = math.ceil(raw_score * 10.0) / 10.0

        # Severity classification
        if base_score >= 9.0:
            sev = Severity.CRITICAL
        elif base_score >= 7.0:
            sev = Severity.HIGH
        elif base_score >= 4.0:
            sev = Severity.MEDIUM
        elif base_score > 0.0:
            sev = Severity.LOW
        else:
            sev = Severity.INFORMATIONAL

        vector_str = f"CVSS:3.1/AV:{av[0]}/AC:{ac[0]}/PR:{pr[0]}/UI:{ui[0]}/S:{scope[0]}/C:{conf[0]}/I:{integ[0]}/A:{avail[0]}"

        return CVSSMetrics(
            score=round(base_score, 1),
            severity=sev,
            vector_string=vector_str,
            attack_vector=av.upper(),
            attack_complexity=ac.upper(),
            privileges_required=pr.upper(),
            user_interaction=ui.upper(),
            scope=scope.upper(),
            confidentiality=conf.upper(),
            integrity=integ.upper(),
            availability=avail.upper(),
        )


class CVECatalog:
    """Local repository of critical enterprise vulnerabilities."""

    def __init__(self):
        self._entries: Dict[str, CVECatalogEntry] = {}
        self._seed_catalog()

    def _seed_catalog(self) -> None:
        """Seed high-profile enterprise CVE entries."""
        seeds = [
            (
                "CVE-2024-3094",
                "XZ Utils Liblzma Upstream Backdoor Injection",
                "Malicious backdoor in upstream xz/liblzma packages leading to unauthenticated SSH daemon pre-auth RCE.",
                "CWE-506",
                CVSSv31Calculator.calculate("NETWORK", "LOW", "NONE", "NONE", "CHANGED", "HIGH", "HIGH", "HIGH"),
                ["xz-utils:5.6.0", "xz-utils:5.6.1", "openssh-server"],
                "Downgrade xz-utils immediately to 5.4.6 and rebuild OpenSSH binaries."
            ),
            (
                "CVE-2021-44228",
                "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
                "JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP/RMI requests.",
                "CWE-502",
                CVSSv31Calculator.calculate("NETWORK", "LOW", "NONE", "NONE", "CHANGED", "HIGH", "HIGH", "HIGH"),
                ["apache:log4j-core:2.14.1", "spring-boot:log4j2"],
                "Upgrade to Log4j 2.17.1+ or set log4j2.formatMsgNoLookups=true."
            ),
            (
                "CVE-2023-4966",
                "Citrix Bleed NetScaler ADC/Gateway Sensitive Information Disclosure",
                "Buffer overflow in NetScaler ADC and NetScaler Gateway allows unauthorized session token exfiltration.",
                "CWE-119",
                CVSSv31Calculator.calculate("NETWORK", "LOW", "NONE", "NONE", "UNCHANGED", "HIGH", "HIGH", "NONE"),
                ["citrix:netscaler_adc", "citrix:netscaler_gateway"],
                "Apply Citrix patch and invalidate all active session tokens immediately."
            ),
            (
                "CVE-2020-1472",
                "Microsoft Netlogon Elevation of Privilege (ZeroLogon)",
                "Flaw in AES-CFB8 cryptographic authentication allows unauthenticated attackers to obtain Domain Admin privileges.",
                "CWE-326",
                CVSSv31Calculator.calculate("NETWORK", "LOW", "NONE", "NONE", "CHANGED", "HIGH", "HIGH", "HIGH"),
                ["windows_server:2016", "windows_server:2019", "windows_server:2022"],
                "Enforce Secure RPC for all Netlogon connections via Active Directory GPO."
            ),
            (
                "CVE-2017-0144",
                "SMBv1 Remote Code Execution (EternalBlue)",
                "Buffer overflow vulnerability in Microsoft SMBv1 server allows remote attackers to execute arbitrary code via crafted packets.",
                "CWE-120",
                CVSSv31Calculator.calculate("NETWORK", "LOW", "NONE", "NONE", "UNCHANGED", "HIGH", "HIGH", "HIGH"),
                ["windows_server:2008", "windows_7", "windows_10_prior_1703"],
                "Disable SMBv1 completely and apply Microsoft Security Bulletin MS17-010."
            ),
        ]

        for cve_id, title, desc, cwe, cvss, affected, mit in seeds:
            self._entries[cve_id.upper()] = CVECatalogEntry(
                cve_id=cve_id.upper(),
                title=title,
                description=desc,
                cwe_id=cwe,
                cvss=cvss,
                affected_software=affected,
                mitigation_advice=mit,
            )

    def get_cve(self, cve_id: str) -> Optional[CVECatalogEntry]:
        """Fetch CVE by identifier."""
        return self._entries.get(cve_id.upper())

    def get_all_cves(self) -> List[CVECatalogEntry]:
        """Return all catalog entries."""
        return list(self._entries.values())


# Global singleton CVE catalog
cve_catalog = CVECatalog()
