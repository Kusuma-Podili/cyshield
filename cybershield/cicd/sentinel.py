"""
CyberShield Enterprise - CI/CD Pipeline & Supply Chain Poisoning Sentinel Engine
Audits CI/CD workflows, detects script tampering, identifies package typosquatting,
parses CycloneDX/SPDX SBOMs, and validates SLSA-compliant build attestations.
"""

import re
import json
import uuid
import hashlib
import hmac
import base64
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime

from cybershield.cicd.schemas import (
    PackageEcosystem,
    PipelinePlatform,
    SLSALevel,
    FindingSeverity,
    AttestationStatus,
    SBOMComponent,
    SBOMDocument,
    PipelineTamperFinding,
    TypoSquatFinding,
    ArtifactAttestation,
    PipelineAuditReport,
)


class CICDPipelineSentinel:
    """
    Enterprise-grade CI/CD and Supply Chain Poisoning Sentinel.
    Validates pipeline definitions, dependencies, and build artifacts without external SaaS calls.
    """

    POPULAR_PACKAGES = {
        PackageEcosystem.PYPI: [
            "requests", "urllib3", "numpy", "pandas", "flask", "django",
            "cryptography", "boto3", "pytest", "scipy", "tensorflow",
            "torch", "setuptools", "wheel", "pip", "certifi", "idna",
            "six", "python-dateutil", "pyyaml", "pydantic", "fastapi",
            "httpx", "sqlalchemy", "celery", "redis", "click", "jinja2"
        ],
        PackageEcosystem.NPM: [
            "express", "react", "react-dom", "lodash", "axios", "chalk",
            "webpack", "typescript", "vue", "next", "commander", "moment",
            "async", "dotenv", "fs-extra", "rxjs", "eslint", "prettier",
            "body-parser", "cors", "morgan", "mongoose", "jsonwebtoken"
        ],
        PackageEcosystem.CARGO: [
            "serde", "tokio", "syn", "rand", "clap", "quote", "regex",
            "anyhow", "thiserror", "tracing", "reqwest", "log", "bytes"
        ],
        PackageEcosystem.GOLANG: [
            "gin-gonic/gin", "gorilla/mux", "spf13/cobra", "stretchr/testify",
            "sirupsen/logrus", "go-redis/redis", "gorm.io/gorm", "uber-go/zap"
        ]
    }

    # Known homoglyph confusion table (e.g., Cyrillic to Latin)
    HOMOGLYPH_MAP = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
        '0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b', 'vv': 'w'
    }

    def __init__(self, hmac_secret: str = "cybershield-slsa-attestation-key"):
        self.hmac_secret = hmac_secret.encode('utf-8')

    # --------------------------------------------------------------------------
    # 1. SBOM Parsing & Dependency Auditing
    # --------------------------------------------------------------------------

    def parse_cyclonedx_sbom(self, content: str | dict) -> SBOMDocument:
        """Parse CycloneDX JSON format into structured SBOMDocument."""
        if isinstance(content, str):
            data = json.loads(content)
        else:
            data = content

        metadata = data.get("metadata", {})
        component_data = metadata.get("component", {})
        app_name = component_data.get("name", "unnamed-application")
        spec_ver = str(data.get("specVersion", "1.5"))

        components: List[SBOMComponent] = []
        raw_components = data.get("components", [])

        for rc in raw_components:
            name = rc.get("name", "")
            version = str(rc.get("version", ""))
            purl = rc.get("purl", "")

            ecosystem = PackageEcosystem.PYPI
            if purl:
                if purl.startswith("pkg:npm"):
                    ecosystem = PackageEcosystem.NPM
                elif purl.startswith("pkg:cargo"):
                    ecosystem = PackageEcosystem.CARGO
                elif purl.startswith("pkg:golang"):
                    ecosystem = PackageEcosystem.GOLANG
                elif purl.startswith("pkg:maven"):
                    ecosystem = PackageEcosystem.MAVEN

            hashes = {}
            for h in rc.get("hashes", []):
                alg = h.get("alg", "").lower().replace("-", "")
                val = h.get("content", "")
                if alg and val:
                    hashes[alg] = val

            licenses = []
            for lic in rc.get("licenses", []):
                if "license" in lic and "id" in lic["license"]:
                    licenses.append(lic["license"]["id"])
                elif "expression" in lic:
                    licenses.append(lic["expression"])

            is_pinned = self._is_version_pinned(version)

            components.append(
                SBOMComponent(
                    name=name,
                    version=version,
                    purl=purl or None,
                    ecosystem=ecosystem,
                    licenses=licenses,
                    direct_dependency=True,
                    hashes=hashes,
                    is_pinned=is_pinned,
                )
            )

        dep_graph: Dict[str, List[str]] = {}
        for dep in data.get("dependencies", []):
            ref = dep.get("ref", "")
            depends_on = dep.get("dependsOn", [])
            if ref:
                dep_graph[ref] = depends_on

        return SBOMDocument(
            format="cyclonedx",
            spec_version=spec_ver,
            application_name=app_name,
            total_components=len(components),
            components=components,
            dependency_graph=dep_graph,
        )

    def parse_spdx_sbom(self, content: str | dict) -> SBOMDocument:
        """Parse SPDX JSON format into structured SBOMDocument."""
        if isinstance(content, str):
            data = json.loads(content)
        else:
            data = content

        app_name = data.get("name", "unnamed-spdx-project")
        spec_ver = str(data.get("spdxVersion", "SPDX-2.3"))

        components: List[SBOMComponent] = []
        raw_packages = data.get("packages", [])

        for p in raw_packages:
            name = p.get("name", "")
            version = str(p.get("versionInfo", ""))
            checksums = {}
            for cs in p.get("checksums", []):
                alg = cs.get("algorithm", "").lower()
                val = cs.get("checksumValue", "")
                checksums[alg] = val

            license_concluded = p.get("licenseConcluded")
            licenses = [license_concluded] if license_concluded and license_concluded != "NOASSERTION" else []

            is_pinned = self._is_version_pinned(version)

            components.append(
                SBOMComponent(
                    name=name,
                    version=version,
                    purl=None,
                    ecosystem=PackageEcosystem.PYPI,
                    licenses=licenses,
                    direct_dependency=True,
                    hashes=checksums,
                    is_pinned=is_pinned,
                )
            )

        return SBOMDocument(
            format="spdx",
            spec_version=spec_ver,
            application_name=app_name,
            total_components=len(components),
            components=components,
            dependency_graph={},
        )

    def _is_version_pinned(self, version: str) -> bool:
        """Determine if version expression is strictly pinned to a discrete release."""
        if not version or version in ["*", "latest", "master", "main", "dev"]:
            return False
        if any(version.startswith(prefix) for prefix in ["^", "~", ">=", ">", "<=", "<", "!="]):
            return False
        # Exact SemVer or single release
        return bool(re.match(r"^[vV]?\d+(\.\d+)*(-[a-zA-Z0-9\.]+)?$", version.strip()))

    def detect_unpinned_dependencies(self, sbom: SBOMDocument) -> List[SBOMComponent]:
        """Returns all components that fail strict version pinning requirements."""
        return [c for c in sbom.components if not c.is_pinned]

    # --------------------------------------------------------------------------
    # 2. CI/CD Workflow Script Tampering & Threat Detection
    # --------------------------------------------------------------------------

    def audit_workflow_script(
        self, workflow_content: str, platform: PipelinePlatform = PipelinePlatform.GITHUB_ACTIONS
    ) -> List[PipelineTamperFinding]:
        """
        Statically inspects workflow definitions for malicious patterns,
        insecure practices, and supply chain tampering vectors.
        """
        findings: List[PipelineTamperFinding] = []
        lines = workflow_content.splitlines()

        # Check full workflow flags
        if "permissions: write-all" in workflow_content:
            findings.append(
                PipelineTamperFinding(
                    finding_type="PERMISSIVE_TOKEN_SCOPE",
                    severity=FindingSeverity.HIGH,
                    line_number=self._find_line(lines, "permissions: write-all"),
                    evidence="permissions: write-all",
                    description="Default GITHUB_TOKEN has unrestricted write permissions across all repository resources.",
                    recommendation="Declare minimal required permissions (e.g., contents: read, issues: write).",
                )
            )

        if "pull_request_target" in workflow_content and "ref: ${{ github.event.pull_request.head.sha }}" in workflow_content:
            findings.append(
                PipelineTamperFinding(
                    finding_type="PWN_REQUEST_CODE_EXECUTION",
                    severity=FindingSeverity.CRITICAL,
                    line_number=self._find_line(lines, "pull_request_target"),
                    evidence="pull_request_target + checkout PR head sha",
                    description="Checking out untrusted pull request code with elevated repository secrets token.",
                    recommendation="Do not check out untrusted pull_request_target forks directly into a privileged environment.",
                )
            )

        # Line-by-line checks
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()

            # Curl / Wget pipe to shell
            if re.search(r"(curl\s+[^\|]+\|\s*(ba)?sh|wget\s+[^\|]+\|\s*(ba)?sh)", stripped, re.IGNORECASE):
                findings.append(
                    PipelineTamperFinding(
                        finding_type="CURL_PIPE_SHELL",
                        severity=FindingSeverity.CRITICAL,
                        line_number=idx,
                        evidence=stripped,
                        description="Direct piping of unauthenticated web content into shell execution environment.",
                        recommendation="Download artifact, verify cryptographic hash/GPG signature before execution.",
                    )
                )

            # Secret dumping
            if re.search(r"(env\s*\|\s*base64|printenv\s*\|\s*curl|cat\s+\$GITHUB_ENV\s*\|\s*curl)", stripped):
                findings.append(
                    PipelineTamperFinding(
                        finding_type="SECRET_EXFILTRATION_PATTERN",
                        severity=FindingSeverity.CRITICAL,
                        line_number=idx,
                        evidence=stripped,
                        description="Potential pipeline secret harvesting and outbound exfiltration detected.",
                        recommendation="Remove raw environment dump statements from workflow scripts.",
                    )
                )

            # Unpinned Actions (using branch name instead of full 40-char SHA)
            if stripped.startswith("uses:") or " uses: " in stripped:
                action_match = re.search(r"uses:\s*([^@\s]+)@([^\s]+)", stripped)
                if action_match:
                    action_repo = action_match.group(1)
                    action_ref = action_match.group(2)
                    if not re.match(r"^[0-9a-fA-F]{40}$", action_ref):
                        # Action is not pinned to commit SHA
                        findings.append(
                            PipelineTamperFinding(
                                finding_type="UNPINNED_THIRD_PARTY_ACTION",
                                severity=FindingSeverity.MEDIUM,
                                line_number=idx,
                                evidence=stripped,
                                description=f"Action '{action_repo}' uses mutable tag/branch '{action_ref}' instead of immutable 40-character commit SHA.",
                                recommendation="Pin action to full 40-character commit SHA and append version comment.",
                            )
                        )

            # Reverse shell patterns
            if re.search(r"(nc\s+.*-e\s+/bin/bash|bash\s+-i\s+>&|/dev/tcp/\d+\.\d+\.\d+\.\d+)", stripped):
                findings.append(
                    PipelineTamperFinding(
                        finding_type="OUTBOUND_REVERSE_SHELL",
                        severity=FindingSeverity.CRITICAL,
                        line_number=idx,
                        evidence=stripped,
                        description="Reverse shell invocation pattern detected inside CI/CD script step.",
                        recommendation="Quarantine runner immediately and audit source repository for supply chain breach.",
                    )
                )

            # Sudo without password or password disablement
            if "NOPASSWD: ALL" in stripped or "echo 'ALL ALL=(ALL) NOPASSWD: ALL'" in stripped:
                findings.append(
                    PipelineTamperFinding(
                        finding_type="PRIVILEGE_ESCALATION_HOOK",
                        severity=FindingSeverity.HIGH,
                        line_number=idx,
                        evidence=stripped,
                        description="Sudo passwordless privilege escalation hook configured for runner execution.",
                        recommendation="Run containerized build steps with unprivileged user UID 1000.",
                    )
                )

        return findings

    def _find_line(self, lines: List[str], target: str) -> Optional[int]:
        for idx, line in enumerate(lines, start=1):
            if target in line:
                return idx
        return None

    # --------------------------------------------------------------------------
    # 3. Package Typosquatting & Brandjacking Detection
    # --------------------------------------------------------------------------

    def detect_typosquatting(
        self, package_name: str, ecosystem: PackageEcosystem = PackageEcosystem.PYPI
    ) -> List[TypoSquatFinding]:
        """
        Evaluates candidate package name against catalog of popular reference packages.
        Uses Levenshtein, Damerau, homoglyph normalization, and character repetition.
        """
        findings: List[TypoSquatFinding] = []
        popular_list = self.POPULAR_PACKAGES.get(ecosystem, self.POPULAR_PACKAGES[PackageEcosystem.PYPI])

        pkg_clean = package_name.lower().strip()
        if pkg_clean in [p.lower() for p in popular_list]:
            return []  # Exactly the legitimate package

        normalized_pkg = self._normalize_homoglyphs(pkg_clean)

        for target in popular_list:
            tgt_clean = target.lower()

            # 1. Homoglyph check
            if normalized_pkg == tgt_clean and pkg_clean != tgt_clean:
                findings.append(
                    TypoSquatFinding(
                        target_package=target,
                        suspicious_package=package_name,
                        ecosystem=ecosystem,
                        distance=1,
                        similarity_score=0.98,
                        attack_vector="Homoglyph Substitution",
                        risk_level=FindingSeverity.CRITICAL,
                    )
                )
                continue

            # 2. Levenshtein & Damerau distance
            dist = self._levenshtein_distance(pkg_clean, tgt_clean)
            max_len = max(len(pkg_clean), len(tgt_clean))
            similarity = 1.0 - (dist / max_len)

            # Heuristics: Distance <= 2 on packages of length >= 4
            if 0 < dist <= 2 and max_len >= 4:
                # Classify attack vector
                vector = "Levenshtein Typo"
                if self._is_transposition(pkg_clean, tgt_clean):
                    vector = "Character Transposition"
                elif self._is_repetition(pkg_clean, tgt_clean):
                    vector = "Repeated Character Insertion/Omission"

                findings.append(
                    TypoSquatFinding(
                        target_package=target,
                        suspicious_package=package_name,
                        ecosystem=ecosystem,
                        distance=dist,
                        similarity_score=round(similarity, 3),
                        attack_vector=vector,
                        risk_level=FindingSeverity.HIGH if dist == 1 else FindingSeverity.MEDIUM,
                    )
                )

        return findings

    def _normalize_homoglyphs(self, s: str) -> str:
        res = s
        for h, l in self.HOMOGLYPH_MAP.items():
            res = res.replace(h, l)
        return res

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _is_transposition(self, s1: str, s2: str) -> bool:
        if len(s1) != len(s2):
            return False
        diffs = [i for i in range(len(s1)) if s1[i] != s2[i]]
        return len(diffs) == 2 and s1[diffs[0]] == s2[diffs[1]] and s1[diffs[1]] == s2[diffs[0]]

    def _is_repetition(self, s1: str, s2: str) -> bool:
        # Check if s1 is s2 with a doubled character e.g. "reqeusts" vs "requests" or "pyyaml" vs "pyyyaml"
        if abs(len(s1) - len(s2)) == 1:
            longer = s1 if len(s1) > len(s2) else s2
            shorter = s2 if len(s1) > len(s2) else s1
            for i in range(len(longer) - 1):
                if longer[i] == longer[i + 1]:
                    candidate = longer[:i] + longer[i + 1:]
                    if candidate == shorter:
                        return True
        return False

    # --------------------------------------------------------------------------
    # 4. SLSA Build Attestation & Binary Integrity Verification
    # --------------------------------------------------------------------------

    def verify_build_attestation(
        self,
        artifact_bytes: bytes,
        expected_sha256: str,
        signature: Optional[str] = None,
        source_commit: Optional[str] = None,
    ) -> ArtifactAttestation:
        """
        Validates artifact against reproducible build ledger.
        Computes SHA-256 and HMAC-SHA256 signature to verify SLSA build provenance.
        """
        actual_hash = hashlib.sha256(artifact_bytes).hexdigest()
        is_hash_match = (actual_hash.lower() == expected_sha256.lower())

        sig_valid = False
        if signature:
            computed_sig = hmac.new(self.hmac_secret, artifact_bytes, hashlib.sha256).hexdigest()
            sig_valid = hmac.compare_digest(computed_sig, signature)

        if is_hash_match and sig_valid:
            status = AttestationStatus.VERIFIED
            slsa = SLSALevel.LEVEL_3 if source_commit else SLSALevel.LEVEL_2
            details = "Cryptographic artifact hash and provenance signature verified against secure ledger."
        elif is_hash_match and not signature:
            status = AttestationStatus.VERIFIED
            slsa = SLSALevel.LEVEL_2
            details = "Artifact hash matches expected digest; cryptographic signature was omitted."
        elif is_hash_match and not sig_valid:
            status = AttestationStatus.CORRUPTED
            slsa = SLSALevel.LEVEL_1
            details = "Artifact hash matched, but cryptographic provenance signature failed verification."
        else:
            status = AttestationStatus.TAMPERED
            slsa = SLSALevel.LEVEL_0
            details = f"Artifact digest mismatch! Calculated: {actual_hash[:12]}... != Expected: {expected_sha256[:12]}..."

        return ArtifactAttestation(
            artifact_path="build/bin/target-artifact",
            source_commit_sha=source_commit,
            expected_sha256=expected_sha256,
            calculated_sha256=actual_hash,
            attestation_status=status,
            signature_valid=sig_valid,
            slsa_level=slsa,
            verification_details=details,
        )

    def generate_attestation_signature(self, artifact_bytes: bytes) -> str:
        """Helper to generate HMAC signature for verified build artifacts."""
        return hmac.new(self.hmac_secret, artifact_bytes, hashlib.sha256).hexdigest()

    # --------------------------------------------------------------------------
    # 5. Pipeline Posture & Security Score Evaluation
    # --------------------------------------------------------------------------

    def evaluate_pipeline_posture(
        self,
        workflow_content: str,
        workflow_name: str = "ci.yml",
        platform: PipelinePlatform = PipelinePlatform.GITHUB_ACTIONS,
        sbom: Optional[SBOMDocument] = None,
        package_names_to_check: Optional[List[str]] = None,
    ) -> PipelineAuditReport:
        """Aggregates all CI/CD threat dimensions into a weighted posture assessment."""
        audit_id = str(uuid.uuid4())
        score = 100.0
        recommendations: List[str] = []

        # 1. Audit workflow scripts
        tamper_findings = self.audit_workflow_script(workflow_content, platform=platform)
        for f in tamper_findings:
            if f.severity == FindingSeverity.CRITICAL:
                score -= 25.0
            elif f.severity == FindingSeverity.HIGH:
                score -= 15.0
            elif f.severity == FindingSeverity.MEDIUM:
                score -= 8.0
            else:
                score -= 3.0
            recommendations.append(f.recommendation)

        # 2. Audit typosquats
        typosquats: List[TypoSquatFinding] = []
        pkgs = package_names_to_check or []
        if sbom:
            pkgs.extend([c.name for c in sbom.components])

        for pkg in pkgs:
            found = self.detect_typosquatting(pkg)
            for ts in found:
                typosquats.append(ts)
                score -= 12.0
                recommendations.append(f"Replace suspected typosquatted package '{ts.suspicious_package}' with verified '{ts.target_package}'.")

        # 3. Check unpinned dependencies
        unpinned_count = 0
        if sbom:
            unpinned = self.detect_unpinned_dependencies(sbom)
            unpinned_count = len(unpinned)
            score -= min(unpinned_count * 2.5, 20.0)
            if unpinned_count > 0:
                recommendations.append(f"Pin all {unpinned_count} dependencies in SBOM to exact immutable versions.")

        # Bound score to [0.0, 100.0]
        final_score = max(0.0, min(100.0, round(score, 1)))

        # Determine SLSA level based on score & critical findings
        critical_count = sum(1 for f in tamper_findings if f.severity == FindingSeverity.CRITICAL)
        if critical_count > 0 or final_score < 50.0:
            slsa = SLSALevel.LEVEL_0
            deployable = False
        elif final_score < 70.0:
            slsa = SLSALevel.LEVEL_1
            deployable = False
        elif final_score < 85.0:
            slsa = SLSALevel.LEVEL_2
            deployable = True
        else:
            slsa = SLSALevel.LEVEL_3
            deployable = True

        return PipelineAuditReport(
            audit_id=audit_id,
            timestamp=datetime.utcnow(),
            workflow_name=workflow_name,
            security_score=final_score,
            tamper_findings=tamper_findings,
            typosquat_findings=typosquats,
            unpinned_dependencies_count=unpinned_count,
            slsa_assessment=slsa,
            is_deployable=deployable,
            recommendations=list(dict.fromkeys(recommendations)),
        )
