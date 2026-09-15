"""Master Deception Engine & Active Deception Orchestrator.

Manages running decoy trap listeners, evaluates canary token triggers, maintains tripwire
alert history, and automatically dispatches automated containment signals to SOAR and event bus.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from cybershield.deception.schemas import (
    TrapType,
    CanaryType,
    CanaryToken,
    TripwireAlert,
    DecoyServiceStatus,
    DeceptionStatsResponse,
    CanaryGenerateRequest,
)
from cybershield.deception.canary import CanaryManager
from cybershield.deception.traps.service_traps import (
    SSHTrap,
    SMBShareTrap,
    HTTPAdminTrap,
    DatabaseTrap,
)


class DeceptionEngine:
    """Master orchestrator for active deception infrastructure."""

    _traps: Dict[str, Any] = {}
    _tripwire_alerts: List[TripwireAlert] = []

    @classmethod
    def initialize_default_decoys(cls) -> None:
        """Bootstrap default enterprise decoy trap listeners."""
        if not cls._traps:
            cls._traps["ssh-01"] = SSHTrap("ssh-01", 2222)
            cls._traps["smb-01"] = SMBShareTrap("smb-01", 445)
            cls._traps["http-01"] = HTTPAdminTrap("http-01", 8088)
            cls._traps["db-01"] = DatabaseTrap("db-01", 6379)
        CanaryManager.seed_default_canaries_if_empty()

    @classmethod
    def record_alert(cls, alert: TripwireAlert) -> None:
        """Store tripwire alert and propagate to enterprise telemetry bus."""
        cls._tripwire_alerts.append(alert)
        if len(cls._tripwire_alerts) > 500:
            cls._tripwire_alerts = cls._tripwire_alerts[-500:]

        # Asynchronously dispatch to platform event bus
        try:
            from cybershield.tasks.event_bus import global_event_bus
            global_event_bus.publish_sync(
                topic="deception.tripwire.alert",
                data=alert.model_dump(),
                source="DeceptionEngine",
            )
        except Exception:
            pass

    @classmethod
    def get_trap(cls, trap_id: str) -> Optional[Any]:
        return cls._traps.get(trap_id)

    @classmethod
    def list_traps(cls) -> List[DecoyServiceStatus]:
        """Return operational state of all configured decoy traps."""
        cls.initialize_default_decoys()
        return [trap.get_status() for trap in cls._traps.values()]

    @classmethod
    def list_canaries(cls) -> List[CanaryToken]:
        cls.initialize_default_decoys()
        return CanaryManager.list_canaries()

    @classmethod
    def generate_canary(cls, req: CanaryGenerateRequest) -> CanaryToken:
        return CanaryManager.generate_canary(req)

    @classmethod
    def check_canary_trip(cls, input_text: str, source_ip: str = "10.0.0.99") -> Optional[TripwireAlert]:
        alert = CanaryManager.check_value_trip(input_text, source_ip)
        if alert:
            cls.record_alert(alert)
        return alert

    @classmethod
    def trigger_ssh_trap(
        cls,
        username: str,
        password: str,
        source_ip: str = "10.0.0.99",
        client_version: Optional[str] = None,
    ) -> TripwireAlert:
        cls.initialize_default_decoys()
        trap: SSHTrap = cls._traps.get("ssh-01") or SSHTrap()
        alert = trap.handle_auth_attempt(username, password, source_ip, client_version=client_version)
        cls.record_alert(alert)
        return alert

    @classmethod
    def trigger_smb_trap(
        cls,
        share_name: str,
        action: str = "TREE_CONNECT",
        source_ip: str = "10.0.0.99",
        username: Optional[str] = None,
    ) -> TripwireAlert:
        cls.initialize_default_decoys()
        trap: SMBShareTrap = cls._traps.get("smb-01") or SMBShareTrap()
        alert = trap.handle_share_access(share_name, action, source_ip, username)
        cls.record_alert(alert)
        return alert

    @classmethod
    def trigger_http_trap(
        cls,
        path: str,
        method: str = "GET",
        source_ip: str = "10.0.0.99",
        headers: Optional[Dict[str, str]] = None,
    ) -> TripwireAlert:
        cls.initialize_default_decoys()
        trap: HTTPAdminTrap = cls._traps.get("http-01") or HTTPAdminTrap()
        alert = trap.handle_http_probe(path, method, source_ip, headers)
        cls.record_alert(alert)
        return alert

    @classmethod
    def trigger_db_trap(
        cls,
        command_str: str,
        source_ip: str = "10.0.0.99",
    ) -> TripwireAlert:
        cls.initialize_default_decoys()
        trap: DatabaseTrap = cls._traps.get("db-01") or DatabaseTrap()
        alert = trap.handle_command(command_str, source_ip)
        cls.record_alert(alert)
        return alert

    @classmethod
    def get_stats(cls) -> DeceptionStatsResponse:
        """Return aggregated deception defense metrics."""
        cls.initialize_default_decoys()
        canaries = CanaryManager.list_canaries()
        tripped = sum(1 for c in canaries if c.is_tripped)

        return DeceptionStatsResponse(
            total_canaries=len(canaries),
            active_canaries=len(canaries),
            tripped_canaries=tripped,
            total_traps=len(cls._traps),
            active_traps=sum(1 for t in cls._traps.values() if t.is_active),
            total_tripwire_alerts=len(cls._tripwire_alerts),
            recent_alerts=cls._tripwire_alerts[-15:],
        )
