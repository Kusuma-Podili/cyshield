"""Local Threat Intelligence & IoC Matching Engine for CyberShield Enterprise.

Employs in-memory Bloom Filters and exact Hash Indices for sub-millisecond
Indicators of Compromise (IoC) lookup against malicious IPs, domains, and SHA-256 hashes.
Operates completely offline without external SaaS subscriptions.
"""

from __future__ import annotations

import math
import hashlib
import logging
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timezone

from cybershield.core.models import (
    IoCEntry,
    IoCType,
    Severity,
    generate_id,
    now_utc,
)

logger = logging.getLogger("cybershield.intel.ioc")


class BloomFilter:
    """Bit-array Bloom Filter for fast probabilistic set-membership tests."""

    def __init__(self, capacity: int = 100000, error_rate: float = 0.001):
        self.capacity = capacity
        self.error_rate = error_rate
        # Calculate optimal bit array size: m = - (n * ln(p)) / (ln(2)^2)
        self.size = int(- (capacity * math.log(error_rate)) / (math.log(2) ** 2))
        # Calculate optimal number of hash functions: k = (m / n) * ln(2)
        self.hash_count = int((self.size / capacity) * math.log(2))
        self.bit_array = bytearray((self.size + 7) // 8)

    def _hashes(self, item: str) -> List[int]:
        """Generate k hash indices for a given string item."""
        h1 = int(hashlib.sha256(item.encode("utf-8")).hexdigest()[:16], 16)
        h2 = int(hashlib.md5(item.encode("utf-8")).hexdigest()[:16], 16)
        return [(h1 + i * h2) % self.size for i in range(self.hash_count)]

    def add(self, item: str) -> None:
        """Add item string to bloom filter."""
        for idx in self._hashes(item):
            byte_idx = idx // 8
            bit_idx = idx % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)

    def contains(self, item: str) -> bool:
        """Test if item might be present in the set."""
        for idx in self._hashes(item):
            byte_idx = idx // 8
            bit_idx = idx % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True


class IoCDatabase:
    """Enterprise IoC database holding known threat actor indicators."""

    def __init__(self):
        self._bloom = BloomFilter(capacity=200000, error_rate=0.0005)
        self._entries: Dict[str, IoCEntry] = {}
        self._seed_threat_intel()

    def _seed_threat_intel(self) -> None:
        """Seed realistic enterprise threat intel records."""
        threat_seeds = [
            # Malicious C2 / Command & Control IPs
            ("198.51.100.23", IoCType.IP, "Cobalt Strike C2 Beacon", Severity.CRITICAL, "APT29 Cozy Bear"),
            ("203.0.113.88", IoCType.IP, "QakBot Command Node", Severity.HIGH, "QakBot Infrastructure"),
            ("185.220.101.5", IoCType.IP, "Tor Exit Relay / Proxy", Severity.MEDIUM, "Darknet Gateway"),
            ("45.33.32.156", IoCType.IP, "LockBit Ransomware Exfil Host", Severity.CRITICAL, "LockBit 3.0 Group"),
            ("91.240.118.172", IoCType.IP, "Brute Force Scanning Engine", Severity.HIGH, "Masscan Scanner"),
            
            # Malicious Domains
            ("c2-beacon-update.org", IoCType.DOMAIN, "Emotet C2 Controller", Severity.CRITICAL, "Emotet Gang"),
            ("login-secure-office365-verify.com", IoCType.DOMAIN, "Credential Phishing Site", Severity.HIGH, "EvilProxy Campaign"),
            ("pay-ransom-unlock.cc", IoCType.DOMAIN, "BlackCat Ransom Portal", Severity.CRITICAL, "ALPHV BlackCat"),
            ("api-telemetry-cdn.xyz", IoCType.DOMAIN, "Data Exfiltration Tunnel", Severity.HIGH, "Lazarus Group"),

            # Malicious SHA-256 Hashes
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IoCType.SHA256, "Known EICAR Standard Test Signature", Severity.LOW, "EICAR"),
            ("a8b38749e7b233a7e4e138a8d169c9be740e5362e49c7198539265f04b2a8d3e", IoCType.SHA256, "Mimikatz LSASS Password Dumper", Severity.CRITICAL, "GentilKiwi"),
            ("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", IoCType.SHA256, "WannaCry Ransomware Dropper", Severity.CRITICAL, "WannaCry"),
            ("8f4e5bc6e84f1b8240e61824eb0e134f2d6e4b6d9829e557b5283f6f6980a48e", IoCType.SHA256, "BlackCat Ransomware Encryptor", Severity.CRITICAL, "ALPHV"),
        ]

        for val, ioc_type, threat, sev, source in threat_seeds:
            self.add_entry(
                IoCEntry(
                    type=ioc_type,
                    value=val,
                    threat_name=threat,
                    severity=sev,
                    source=source,
                    tags=[threat.lower().replace(" ", "_"), source.lower().replace(" ", "_")]
                )
            )

    def add_entry(self, entry: IoCEntry) -> None:
        """Register a new threat indicator."""
        lookup_key = entry.value.strip().lower()
        self._entries[lookup_key] = entry
        self._bloom.add(lookup_key)

    def lookup(self, value: str) -> Optional[IoCEntry]:
        """Fast lookup check. Returns IoCEntry if matched, else None."""
        if not value:
            return None
        cleaned = value.strip().lower()
        # Fast filter test
        if not self._bloom.contains(cleaned):
            return None
        # Exact dictionary verification
        return self._entries.get(cleaned)

    def check_indicators(self, indicators: List[str]) -> List[IoCEntry]:
        """Batch evaluate a list of potential indicators."""
        hits = []
        for ind in indicators:
            hit = self.lookup(ind)
            if hit:
                hits.append(hit)
        return hits

    def get_all_entries(self) -> List[IoCEntry]:
        """Return all catalogued indicators."""
        return list(self._entries.values())


# Global singleton IoC database
ioc_database = IoCDatabase()
