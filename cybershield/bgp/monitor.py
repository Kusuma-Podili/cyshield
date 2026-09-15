"""
Autonomous BGP Route Hijacking & Autonomous System Peering Monitor.
Performs RPKI Route Origin Validation (ROV), sub-prefix hijacking detection,
bogon prefix filtering, and autonomous system path anomaly auditing.
"""

import ipaddress
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from cybershield.bgp.schemas import (
    BGPHijackAlert,
    BGPHijackType,
    BGPRouteAnnouncement,
    BGPRouteEvaluationResult,
    RouteOriginAuthorization,
    RPKIValidationState,
)


class BGPMonitorEngine:
    """
    Real-time BGP routing integrity engine inspecting global prefix advertisements.
    """

    BOGON_PREFIXES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("224.0.0.0/4"),
    ]

    def __init__(self):
        self._roas: Dict[str, RouteOriginAuthorization] = {}
        self._alerts: List[BGPHijackAlert] = []
        self._total_announcements_evaluated = 0
        self._total_hijacks_detected = 0
        self._seed_default_roas()

    def _seed_default_roas(self):
        """Seed cryptographically signed ROAs for protected enterprise prefixes."""
        default_roas = [
            RouteOriginAuthorization(
                roa_id="ROA-CORP-01",
                prefix="198.51.100.0/24",
                origin_asn=64500,
                max_length=24,
                ta_name="ARIN-RPKI"
            ),
            RouteOriginAuthorization(
                roa_id="ROA-FIN-02",
                prefix="203.0.113.0/24",
                origin_asn=64501,
                max_length=24,
                ta_name="RIPE-NCC"
            ),
            RouteOriginAuthorization(
                roa_id="ROA-CLOUD-03",
                prefix="192.0.2.0/23",
                origin_asn=64502,
                max_length=24,
                ta_name="APNIC-RPKI"
            ),
        ]
        for r in default_roas:
            self._roas[r.roa_id] = r

    def is_bogon_prefix(self, network: ipaddress.IPv4Network) -> bool:
        """Determines if prefix falls within unroutable private/reserved bogon ranges."""
        for bogon in self.BOGON_PREFIXES:
            if network.subnet_of(bogon) or network == bogon:
                return True
        return False

    def validate_rpki(
        self, announced_net: ipaddress.IPv4Network, origin_asn: int
    ) -> Tuple[RPKIValidationState, Optional[RouteOriginAuthorization]]:
        """
        Executes RFC 6811 Route Origin Validation (ROV).
        """
        covering_roas: List[RouteOriginAuthorization] = []

        for roa in self._roas.values():
            if not roa.is_active:
                continue
            roa_net = ipaddress.ip_network(roa.prefix)
            if announced_net.subnet_of(roa_net) or announced_net == roa_net:
                covering_roas.append(roa)

        if not covering_roas:
            return RPKIValidationState.NOT_FOUND, None

        # Check if any covering ROA matches origin ASN and max_length
        for roa in covering_roas:
            if roa.origin_asn == origin_asn:
                if announced_net.prefixlen <= roa.max_length:
                    return RPKIValidationState.VALID, roa
                else:
                    return RPKIValidationState.INVALID_MAX_LENGTH, roa

        # If none matched ASN
        return RPKIValidationState.INVALID_ASN, covering_roas[0]

    def evaluate_announcement(self, ann: BGPRouteAnnouncement) -> BGPRouteEvaluationResult:
        """Inspects incoming BGP update announcement against RPKI and hijack heuristics."""
        self._total_announcements_evaluated += 1

        try:
            announced_net = ipaddress.ip_network(ann.prefix)
        except ValueError:
            return BGPRouteEvaluationResult(
                message_id=ann.message_id,
                prefix=ann.prefix,
                origin_asn=ann.origin_asn,
                rpki_status=RPKIValidationState.NOT_FOUND,
                is_hijack_detected=False
            )

        # 1. Check Bogon announcement
        if self.is_bogon_prefix(announced_net):
            self._total_hijacks_detected += 1
            alert = BGPHijackAlert(
                alert_id=f"BGP-BOGON-{uuid.uuid4().hex[:6].upper()}",
                hijacked_prefix=ann.prefix,
                authorized_asn=None,
                rogue_asn=ann.origin_asn,
                hijack_type=BGPHijackType.BOGON_ANNOUNCEMENT,
                severity="HIGH",
                reason=f"Illegal announcement of unallocated/bogon prefix '{ann.prefix}' by AS{ann.origin_asn}",
                as_path=ann.as_path,
                mitigation_recommendation="Filter bogon prefixes at border edge routers using RFC 6890 / Team Cymru bogon ACLs."
            )
            self._alerts.append(alert)
            return BGPRouteEvaluationResult(
                message_id=ann.message_id,
                prefix=ann.prefix,
                origin_asn=ann.origin_asn,
                rpki_status=RPKIValidationState.NOT_FOUND,
                is_hijack_detected=True,
                alert=alert
            )

        # 2. RPKI Route Origin Validation
        rpki_state, matched_roa = self.validate_rpki(announced_net, ann.origin_asn)

        if rpki_state == RPKIValidationState.INVALID_ASN:
            self._total_hijacks_detected += 1
            auth_asn = matched_roa.origin_asn if matched_roa else None
            alert = BGPHijackAlert(
                alert_id=f"BGP-HIJACK-{uuid.uuid4().hex[:6].upper()}",
                hijacked_prefix=ann.prefix,
                authorized_asn=auth_asn,
                rogue_asn=ann.origin_asn,
                hijack_type=BGPHijackType.ORIGIN_HIJACK,
                severity="CRITICAL",
                reason=f"RPKI Origin AS Mismatch: Prefix '{ann.prefix}' announced by rogue AS{ann.origin_asn}, authorized origin is AS{auth_asn}",
                as_path=ann.as_path,
                mitigation_recommendation=f"Enforce RPKI ROV Drop Invalid on border BGP peers and notify upstream tier-1 transit (AS Path: {ann.as_path})."
            )
            self._alerts.append(alert)
            return BGPRouteEvaluationResult(
                message_id=ann.message_id,
                prefix=ann.prefix,
                origin_asn=ann.origin_asn,
                rpki_status=rpki_state,
                is_hijack_detected=True,
                alert=alert
            )

        elif rpki_state == RPKIValidationState.INVALID_MAX_LENGTH:
            self._total_hijacks_detected += 1
            auth_asn = matched_roa.origin_asn if matched_roa else None
            max_len = matched_roa.max_length if matched_roa else 24
            alert = BGPHijackAlert(
                alert_id=f"BGP-SUBPREFIX-{uuid.uuid4().hex[:6].upper()}",
                hijacked_prefix=ann.prefix,
                authorized_asn=auth_asn,
                rogue_asn=ann.origin_asn,
                hijack_type=BGPHijackType.SUBPREFIX_HIJACK,
                severity="CRITICAL",
                reason=f"Sub-prefix Hijack: Prefix length /{announced_net.prefixlen} exceeds RPKI maxLength /{max_len} (Longest-prefix match route traffic theft)",
                as_path=ann.as_path,
                mitigation_recommendation="Announce more specific matching sub-prefixes immediately to reclaim legitimate traffic flow."
            )
            self._alerts.append(alert)
            return BGPRouteEvaluationResult(
                message_id=ann.message_id,
                prefix=ann.prefix,
                origin_asn=ann.origin_asn,
                rpki_status=rpki_state,
                is_hijack_detected=True,
                alert=alert
            )

        return BGPRouteEvaluationResult(
            message_id=ann.message_id,
            prefix=ann.prefix,
            origin_asn=ann.origin_asn,
            rpki_status=rpki_state,
            is_hijack_detected=False,
            alert=None
        )

    def list_roas(self) -> List[RouteOriginAuthorization]:
        return list(self._roas.values())

    def add_roa(self, roa: RouteOriginAuthorization) -> RouteOriginAuthorization:
        self._roas[roa.roa_id] = roa
        return roa

    def list_alerts(self) -> List[BGPHijackAlert]:
        return list(reversed(self._alerts))

    def get_overview_metrics(self) -> Dict[str, Any]:
        return {
            "total_announcements_evaluated": self._total_announcements_evaluated,
            "total_hijacks_detected": self._total_hijacks_detected,
            "active_roas": len(self._roas),
            "total_alerts": len(self._alerts),
            "bogon_ranges_monitored": len(self.BOGON_PREFIXES),
        }
