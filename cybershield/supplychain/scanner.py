"""
Autonomous Software Supply Chain Security Scanner.
Performs typosquatting detection, dependency confusion analysis,
lifecycle script hook inspection, and known poisoned package discovery.
"""

import json
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from cybershield.supplychain.schemas import (
    DependencyPackage,
    PackageEcosystem,
    SupplyChainFinding,
    SupplyChainRiskLevel,
    SupplyChainScanRequest,
    SupplyChainScanResult,
    SupplyChainThreatType,
)


class SupplyChainScanner:
    """
    Evaluates open source package manifests against threat vectors.
    """

    POPULAR_PYPI_PACKAGES = [
        "requests", "urllib3", "numpy", "pandas", "cryptography", "flask",
        "django", "fastapi", "pydantic", "pytest", "boto3", "click",
        "setuptools", "scipy", "colorama", "pyyaml", "certifi", "six"
    ]

    POPULAR_NPM_PACKAGES = [
        "lodash", "express", "react", "axios", "chalk", "commander",
        "async", "moment", "webpack", "typescript", "babel", "debug",
        "dotenv", "uuid", "cors", "body-parser", "next", "redux"
    ]

    KNOWN_POISONED_PACKAGES = {
        PackageEcosystem.PYPI: {
            "reqeusts": "Typosquatting variant targeting 'requests' that exfiltrates environment credentials",
            "colorama-v2": "Malicious payload injecting persistent reverse shells into python startup scripts",
            "ctx-fix": "Compromised maintainer account replacement of ctx package exfiltrating AWS STS tokens",
            "pyperclip-stealer": "Replaces clipboard cryptocurrency addresses with attacker wallet addresses",
            "python-sqlite": "Rogue package dropping backdoor Trojan upon install",
        },
        PackageEcosystem.NPM: {
            "event-stream-3.3.6": "Targeted Copay bitcoin wallet injection attack (flatmap-stream)",
            "ua-parser-js-malicious": "Compromised npm account publishing cryptominer and credential stealer",
            "coa-hijacked": "Hijacked package dropping Windows bat and Linux bash password harvesters",
            "rc-hijacked": "Poisoned release version attempting unauthorized local file exfiltration",
            "flatmap-stream": "Direct cryptocurrency wallet exfiltration trojan embedded in event-stream",
        }
    }

    DANGEROUS_HOOK_PATTERNS = [
        (re.compile(r"(?:curl|wget)\s+.*\|\s*(?:bash|sh)"), "Direct curl-to-shell execution pipeline"),
        (re.compile(r"powershell(?:\.exe)?\s+.*(?:-enc|-e|downloadstring)"), "Encoded PowerShell download and execution"),
        (re.compile(r"nc\s+-[e|c]\s+/bin/(?:ba)?sh"), "Netcat reverse shell spawn command"),
        (re.compile(r"eval\s*\(\s*(?:atob|Buffer\.from|base64)"), "Obfuscated dynamic base64 evaluation"),
        (re.compile(r"child_process\.(?:exec|spawn)\s*\(.*http"), "Remote script execution via node child process"),
    ]

    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Computes Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return SupplyChainScanner.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def check_typosquatting(
        self, package_name: str, ecosystem: PackageEcosystem
    ) -> Optional[SupplyChainFinding]:
        """Detects typosquatting against top popular ecosystem packages."""
        name_lower = package_name.lower().strip()
        popular_list = (
            self.POPULAR_PYPI_PACKAGES
            if ecosystem == PackageEcosystem.PYPI
            else self.POPULAR_NPM_PACKAGES
        )

        for popular in popular_list:
            if name_lower == popular:
                return None  # Exact match with legitimate library
            dist = self.levenshtein_distance(name_lower, popular)
            if dist == 1 or (dist == 2 and len(popular) >= 7):
                return SupplyChainFinding(
                    finding_id=f"TYPO-{uuid.uuid4().hex[:6]}",
                    threat_type=SupplyChainThreatType.TYPOSQUATTING,
                    severity=SupplyChainRiskLevel.HIGH,
                    package_name=package_name,
                    target_legitimate_package=popular,
                    description=f"Package '{package_name}' closely resembles high-traffic legitimate library '{popular}' (Levenshtein distance: {dist}).",
                    remediation=f"Verify if dependency should be replaced with official '{popular}' package."
                )
        return None

    def check_poisoned_database(
        self, package_name: str, ecosystem: PackageEcosystem, version: Optional[str] = None
    ) -> Optional[SupplyChainFinding]:
        """Checks if package matches known malicious/hijacked catalog."""
        poison_map = self.KNOWN_POISONED_PACKAGES.get(ecosystem, {})
        name_lower = package_name.lower().strip()

        if name_lower in poison_map:
            desc = poison_map[name_lower]
            return SupplyChainFinding(
                finding_id=f"POISON-{uuid.uuid4().hex[:6]}",
                threat_type=SupplyChainThreatType.POISONED_PACKAGE,
                severity=SupplyChainRiskLevel.CRITICAL,
                package_name=package_name,
                installed_version=version,
                description=f"Known malicious package detected: {desc}",
                remediation="Immediately remove package and revoke any credentials active on build agents."
            )
        return None

    def inspect_npm_lifecycle_scripts(self, manifest_data: Dict[str, Any]) -> List[SupplyChainFinding]:
        """Audits package.json scripts block for dangerous preinstall/postinstall hooks."""
        findings: List[SupplyChainFinding] = []
        scripts = manifest_data.get("scripts", {})
        hook_names = ["preinstall", "install", "postinstall", "preuninstall", "postuninstall"]

        for hook in hook_names:
            command = scripts.get(hook, "")
            if not command:
                continue
            for pattern, pattern_desc in self.DANGEROUS_HOOK_PATTERNS:
                if pattern.search(command):
                    findings.append(SupplyChainFinding(
                        finding_id=f"HOOK-{uuid.uuid4().hex[:6]}",
                        threat_type=SupplyChainThreatType.MALICIOUS_INSTALL_HOOK,
                        severity=SupplyChainRiskLevel.CRITICAL,
                        package_name=manifest_data.get("name", "root-project"),
                        description=f"Malicious command pattern in '{hook}' script: {pattern_desc} (Command: '{command}')",
                        remediation=f"Remove arbitrary execution script from package.json '{hook}' hook and use sandboxed builds (--ignore-scripts)."
                    ))
        return findings

    def inspect_dependency_confusion(self, package_name: str) -> Optional[SupplyChainFinding]:
        """Flags internal company prefixes lacking private registry qualification."""
        name_lower = package_name.lower().strip()
        internal_indicators = ["@corp-internal/", "@internal/", "@enterprise-private/", "corp-", "internal-"]
        for ind in internal_indicators:
            if name_lower.startswith(ind):
                return SupplyChainFinding(
                    finding_id=f"CONFUSE-{uuid.uuid4().hex[:6]}",
                    threat_type=SupplyChainThreatType.DEPENDENCY_CONFUSION,
                    severity=SupplyChainRiskLevel.HIGH,
                    package_name=package_name,
                    description=f"Package '{package_name}' uses internal organization naming convention without explicit scoped private registry declaration.",
                    remediation="Scope private packages and configure .npmrc / pip.conf with --extra-index-url priority isolation."
                )
        return None

    def scan_requirements_txt(self, content: str) -> Tuple[List[DependencyPackage], List[SupplyChainFinding]]:
        """Parses Python requirements.txt file and evaluates dependencies."""
        packages: List[DependencyPackage] = []
        findings: List[SupplyChainFinding] = []

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Extract package and version specification
            parts = re.split(r"(==|>=|<=|~=|>|<)", line)
            pkg_name = parts[0].strip()
            version = parts[2].strip() if len(parts) >= 3 else "unpinned"

            packages.append(DependencyPackage(
                name=pkg_name,
                version=version,
                ecosystem=PackageEcosystem.PYPI,
                is_direct=True
            ))

            # Unpinned version warning
            if version == "unpinned" or ">=" in line:
                findings.append(SupplyChainFinding(
                    finding_id=f"PIN-{uuid.uuid4().hex[:6]}",
                    threat_type=SupplyChainThreatType.UNPINNED_VERSION,
                    severity=SupplyChainRiskLevel.LOW,
                    package_name=pkg_name,
                    installed_version=version,
                    description=f"Package '{pkg_name}' has unpinned version specification ('{line}'), vulnerable to automated upstream poisoning.",
                    remediation="Pin dependencies strictly with exact versions and hash verification (pip-compile --generate-hashes)."
                ))

            # Typosquatting Check
            typo_finding = self.check_typosquatting(pkg_name, PackageEcosystem.PYPI)
            if typo_finding:
                findings.append(typo_finding)

            # Poisoned package check
            poison_finding = self.check_poisoned_database(pkg_name, PackageEcosystem.PYPI, version)
            if poison_finding:
                findings.append(poison_finding)

            # Dependency confusion check
            confuse_finding = self.inspect_dependency_confusion(pkg_name)
            if confuse_finding:
                findings.append(confuse_finding)

        return packages, findings

    def scan_package_json(self, content: str) -> Tuple[List[DependencyPackage], List[SupplyChainFinding]]:
        """Parses Node.js package.json file and evaluates lifecycle hooks and dependencies."""
        packages: List[DependencyPackage] = []
        findings: List[SupplyChainFinding] = []

        try:
            data = json.loads(content)
        except Exception:
            return packages, findings

        # Check dangerous lifecycle script hooks
        findings.extend(self.inspect_npm_lifecycle_scripts(data))

        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))

        for pkg_name, ver in deps.items():
            packages.append(DependencyPackage(
                name=pkg_name,
                version=str(ver),
                ecosystem=PackageEcosystem.NPM,
                is_direct=True
            ))

            # Typosquatting
            typo_finding = self.check_typosquatting(pkg_name, PackageEcosystem.NPM)
            if typo_finding:
                findings.append(typo_finding)

            # Poisoned
            poison_finding = self.check_poisoned_database(pkg_name, PackageEcosystem.NPM, str(ver))
            if poison_finding:
                findings.append(poison_finding)

            # Dependency Confusion
            confuse_finding = self.inspect_dependency_confusion(pkg_name)
            if confuse_finding:
                findings.append(confuse_finding)

        return packages, findings

    def scan_manifest(self, request: SupplyChainScanRequest) -> SupplyChainScanResult:
        """Performs complete supply chain evaluation on submitted package manifest."""
        packages: List[DependencyPackage] = []
        findings: List[SupplyChainFinding] = []

        if request.ecosystem == PackageEcosystem.PYPI:
            packages, findings = self.scan_requirements_txt(request.manifest_content)
        elif request.ecosystem == PackageEcosystem.NPM:
            packages, findings = self.scan_package_json(request.manifest_content)
        else:
            # Fallback line-by-line scanner for Go/Maven/Cargo
            packages, findings = self.scan_requirements_txt(request.manifest_content)

        # Risk scoring calculation
        risk_score = 10.0
        is_blocked = False
        weights = {
            SupplyChainRiskLevel.CRITICAL: 35.0,
            SupplyChainRiskLevel.HIGH: 20.0,
            SupplyChainRiskLevel.MEDIUM: 10.0,
            SupplyChainRiskLevel.LOW: 3.0,
        }

        for f in findings:
            risk_score += weights.get(f.severity, 5.0)
            if f.severity == SupplyChainRiskLevel.CRITICAL:
                is_blocked = True

        clamped_score = min(100.0, round(risk_score, 1))

        return SupplyChainScanResult(
            scan_id=f"sc-scan-{uuid.uuid4().hex[:8]}",
            ecosystem=request.ecosystem,
            manifest_filename=request.manifest_filename,
            total_packages_identified=len(packages),
            direct_dependencies=len(packages),
            transitive_depth=1 if packages else 0,
            findings=findings,
            risk_score=clamped_score,
            is_build_blocked=is_blocked,
        )
