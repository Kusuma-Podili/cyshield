"""CPE (Common Platform Enumeration) 2.3 Parser & Version Matcher.

Provides NIST CPE 2.3 URI/Formatted String parsing, SBOM component translation,
and robust semantic/lexical version constraint evaluation without external dependencies.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass(frozen=True)
class CPE23:
    """NIST Common Platform Enumeration 2.3 Formatted String representation."""
    part: str  # 'a' (application), 'o' (os), 'h' (hardware)
    vendor: str
    product: str
    version: str
    update: str = "*"
    edition: str = "*"
    language: str = "*"
    sw_edition: str = "*"
    target_sw: str = "*"
    target_hw: str = "*"
    other: str = "*"

    def to_string(self) -> str:
        """Format as standard CPE 2.3 formatted string."""
        return (
            f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{self.version}:"
            f"{self.update}:{self.edition}:{self.language}:{self.sw_edition}:"
            f"{self.target_sw}:{self.target_hw}:{self.other}"
        )


class VersionComparator:
    """Robust version string parser and comparator supporting SemVer and numerical tuples."""

    @classmethod
    def parse_version_tuple(cls, version_str: str) -> Tuple[List[int], str]:
        """Extract numeric components and prerelease/suffix tag from version string."""
        if not version_str or version_str == "*":
            return ([], "")
        
        # Remove leading 'v' e.g. v2.14.1 -> 2.14.1
        cleaned = re.sub(r"^[vV]", "", version_str.strip())
        
        # Split on hyphen or plus to separate prerelease
        parts = re.split(r"[-+]", cleaned, maxsplit=1)
        numeric_part = parts[0]
        suffix = parts[1] if len(parts) > 1 else ""

        # Find all digit sequences
        nums = [int(n) for n in re.findall(r"\d+", numeric_part)]
        return (nums, suffix)

    @classmethod
    def compare(cls, v1: str, v2: str) -> int:
        """Compare two version strings: returns -1 if v1 < v2, 1 if v1 > v2, 0 if v1 == v2."""
        if v1 == v2:
            return 0
        if v1 == "*" or v2 == "*":
            return 0

        t1, s1 = cls.parse_version_tuple(v1)
        t2, s2 = cls.parse_version_tuple(v2)

        # Pad shorter list with zeros
        max_len = max(len(t1), len(t2))
        t1_padded = t1 + [0] * (max_len - len(t1))
        t2_padded = t2 + [0] * (max_len - len(t2))

        for a, b in zip(t1_padded, t2_padded):
            if a < b:
                return -1
            elif a > b:
                return 1

        # Numbers match, compare suffix
        if not s1 and s2:
            return 1  # 1.0.0 is greater than 1.0.0-rc1
        elif s1 and not s2:
            return -1
        elif s1 < s2:
            return -1
        elif s1 > s2:
            return 1
        return 0

    @classmethod
    def satisfies_constraint(cls, version: str, constraint: str) -> bool:
        """Evaluate whether a version satisfies a constraint clause.
        
        Supported formats:
          '< 2.15.0'
          '<= 1.2.3'
          '>= 2.0.0, < 2.4.52'
          '= 1.0.0'
          '*'
        """
        if not constraint or constraint.strip() == "*":
            return True

        clauses = [c.strip() for c in constraint.split(",") if c.strip()]
        for clause in clauses:
            match = re.match(r"^([<>]=?|=)?\s*([a-zA-Z0-9._\-+*]+)$", clause)
            if not match:
                continue
            op, target_ver = match.group(1) or "=", match.group(2)
            if target_ver == "*":
                continue

            cmp = cls.compare(version, target_ver)

            if op == "<" and not (cmp < 0):
                return False
            elif op == "<=" and not (cmp <= 0):
                return False
            elif op == ">" and not (cmp > 0):
                return False
            elif op == ">=" and not (cmp >= 0):
                return False
            elif op == "=" and not (cmp == 0):
                return False

        return True


class CPEMatcher:
    """NIST CPE 2.3 matcher and software package identifier."""

    @classmethod
    def parse_cpe(cls, cpe_str: str) -> Optional[CPE23]:
        """Parse standard CPE 2.3 formatted string."""
        if not cpe_str.startswith("cpe:2.3:"):
            return None

        # Split components by colon, ignoring escaped colons
        tokens = re.split(r"(?<!\\):", cpe_str)
        if len(tokens) < 5:
            return None

        return CPE23(
            part=tokens[2],
            vendor=tokens[3],
            product=tokens[4],
            version=tokens[5] if len(tokens) > 5 else "*",
            update=tokens[6] if len(tokens) > 6 else "*",
            edition=tokens[7] if len(tokens) > 7 else "*",
            language=tokens[8] if len(tokens) > 8 else "*",
            sw_edition=tokens[9] if len(tokens) > 9 else "*",
            target_sw=tokens[10] if len(tokens) > 10 else "*",
            target_hw=tokens[11] if len(tokens) > 11 else "*",
            other=tokens[12] if len(tokens) > 12 else "*",
        )

    @classmethod
    def format_cpe(
        cls,
        vendor: str,
        product: str,
        version: str = "*",
        part: str = "a",
        target_sw: str = "*",
    ) -> str:
        """Create a valid CPE 2.3 string from component metadata."""
        clean_v = re.sub(r"[^a-zA-Z0-9._\-]", "_", vendor.lower())
        clean_p = re.sub(r"[^a-zA-Z0-9._\-]", "_", product.lower())
        clean_ver = re.sub(r"[^a-zA-Z0-9._\-]", "_", version) if version != "*" else "*"
        return CPE23(
            part=part,
            vendor=clean_v,
            product=clean_p,
            version=clean_ver,
            target_sw=target_sw,
        ).to_string()

    @classmethod
    def is_match(
        cls,
        pkg_vendor: str,
        pkg_product: str,
        installed_version: str,
        target_cpe_str: str,
        affected_version_range: Optional[str] = None,
    ) -> bool:
        """Check if an installed software package matches a target CPE and affected range."""
        target_cpe = cls.parse_cpe(target_cpe_str)
        if not target_cpe:
            return False

        # Vendor comparison (allow wildcard or substring match)
        v_clean = pkg_vendor.lower().replace("-", "_")
        t_vendor = target_cpe.vendor.lower().replace("-", "_")
        if target_cpe.vendor != "*" and t_vendor != v_clean and t_vendor not in v_clean and v_clean not in t_vendor:
            return False

        # Product comparison
        p_clean = pkg_product.lower().replace("-", "_")
        t_product = target_cpe.product.lower().replace("-", "_")
        if target_cpe.product != "*" and t_product != p_clean and t_product not in p_clean and p_clean not in t_product:
            return False

        # Version check
        if affected_version_range:
            return VersionComparator.satisfies_constraint(installed_version, affected_version_range)

        if target_cpe.version != "*":
            return VersionComparator.compare(installed_version, target_cpe.version) == 0

        return True
