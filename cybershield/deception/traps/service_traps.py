"""Decoy Service Traps (SSH, SMB, HTTP Admin, Database) for Active Intrusion Detection."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybershield.deception.schemas import (
    TrapType,
    TripwireAlert,
    DecoyServiceStatus,
)


class BaseDecoyTrap:
    """Abstract base class for honeypot decoy traps."""

    trap_id: str
    trap_type: TrapType
    name: str
    port: int
    is_active: bool = True
    total_interactions: int = 0
    last_interaction: Optional[datetime] = None

    def get_status(self) -> DecoyServiceStatus:
        return DecoyServiceStatus(
            trap_id=self.trap_id,
            trap_type=self.trap_type,
            name=self.name,
            port=self.port,
            is_active=self.is_active,
            total_interactions=self.total_interactions,
            last_interaction=self.last_interaction,
            details={"description": f"Decoy {self.trap_type.value} Honeypot Listener"},
        )

    def record_interaction(self) -> None:
        self.total_interactions += 1
        self.last_interaction = datetime.now(timezone.utc)


class SSHTrap(BaseDecoyTrap):
    """Decoy SSH Service Honeypot (Port 2222 / 22)."""

    def __init__(self, trap_id: str = "trap-ssh-01", port: int = 2222):
        self.trap_id = trap_id
        self.trap_type = TrapType.SSH
        self.name = "Decoy Enterprise Gateway SSH Server"
        self.port = port
        self.banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"

    def handle_auth_attempt(
        self,
        username: str,
        password: str,
        source_ip: str = "10.0.0.99",
        source_port: int = 51234,
        client_version: Optional[str] = None,
    ) -> TripwireAlert:
        """Process incoming authentication attempt against decoy SSH listener."""
        self.record_interaction()
        now = datetime.now(timezone.utc)
        alert_id = f"TRIP-SSH-{uuid.uuid4().hex[:8].upper()}"

        return TripwireAlert(
            alert_id=alert_id,
            timestamp=now,
            trap_or_canary_id=self.trap_id,
            trap_type="DECOY_SSH",
            source_ip=source_ip,
            source_port=source_port,
            severity="CRITICAL",
            title=f"Decoy SSH Honeypot Intrusion: {username}@{source_ip}",
            description=(
                f"Adversary connected to decoy SSH server on port {self.port} and attempted authentication "
                f"with credentials '{username}:{password[:3]}***'. Client software: '{client_version or 'unknown'}'."
            ),
            attacker_payload={
                "username": username,
                "password_length": len(password),
                "client_banner": client_version,
                "port": self.port,
            },
            mitre_technique="T1021.004",
        )


class SMBShareTrap(BaseDecoyTrap):
    """Decoy SMB File Share Trap (Port 445)."""

    def __init__(self, trap_id: str = "trap-smb-01", port: int = 445):
        self.trap_id = trap_id
        self.trap_type = TrapType.SMB
        self.name = "Decoy Executive Financial File Share"
        self.port = port
        self.shares = ["FINANCE_ARCHIVE$", "CONFIDENTIAL_MERGERS", "BACKUP_PAYROLL$"]

    def handle_share_access(
        self,
        share_name: str,
        action: str,
        source_ip: str = "10.0.0.99",
        username: Optional[str] = None,
    ) -> TripwireAlert:
        """Process connection or file access attempt against decoy share."""
        self.record_interaction()
        now = datetime.now(timezone.utc)
        alert_id = f"TRIP-SMB-{uuid.uuid4().hex[:8].upper()}"

        return TripwireAlert(
            alert_id=alert_id,
            timestamp=now,
            trap_or_canary_id=self.trap_id,
            trap_type="DECOY_SMB",
            source_ip=source_ip,
            severity="CRITICAL",
            title=f"Decoy SMB Share Traversal: {share_name}",
            description=(
                f"Host {source_ip} (user: {username or 'anonymous'}) accessed decoy honeypot share '{share_name}' "
                f"with action '{action}'. Characteristic of lateral reconnaissance or ransomware discovery."
            ),
            attacker_payload={"share_name": share_name, "action": action, "username": username},
            mitre_technique="T1021.002",
        )


class HTTPAdminTrap(BaseDecoyTrap):
    """Decoy HTTP Admin Portal & Sensitive URI Trap (Port 8088 / 80)."""

    def __init__(self, trap_id: str = "trap-http-01", port: int = 8088):
        self.trap_id = trap_id
        self.trap_type = TrapType.HTTP_ADMIN
        self.name = "Decoy Web Admin & Actuator Endpoint"
        self.port = port
        self.monitored_paths = {
            "/phpmyadmin",
            "/actuator/env",
            "/.env",
            "/.git/config",
            "/wp-login.php",
            "/admin/login",
            "/api/v1/debug",
            "/console",
        }

    def handle_http_probe(
        self,
        path: str,
        method: str = "GET",
        source_ip: str = "10.0.0.99",
        headers: Optional[Dict[str, str]] = None,
    ) -> TripwireAlert:
        """Process HTTP probe against decoy admin paths."""
        self.record_interaction()
        now = datetime.now(timezone.utc)
        alert_id = f"TRIP-HTTP-{uuid.uuid4().hex[:8].upper()}"

        ua = (headers or {}).get("user-agent", "Unknown")

        return TripwireAlert(
            alert_id=alert_id,
            timestamp=now,
            trap_or_canary_id=self.trap_id,
            trap_type="DECOY_HTTP",
            source_ip=source_ip,
            severity="HIGH",
            title=f"Decoy Web Portal Intrusion: {method} {path}",
            description=(
                f"Automated probe or adversary targeted honeypot administration endpoint '{path}' "
                f"via {method} request. User-Agent: '{ua}'."
            ),
            attacker_payload={"path": path, "method": method, "user_agent": ua},
            mitre_technique="T1190",
        )


class DatabaseTrap(BaseDecoyTrap):
    """Decoy Redis / Database Honeypot (Port 6379 / 3306)."""

    def __init__(self, trap_id: str = "trap-db-01", port: int = 6379):
        self.trap_id = trap_id
        self.trap_type = TrapType.DATABASE
        self.name = "Decoy Redis In-Memory Cache"
        self.port = port

    def handle_command(
        self,
        command_str: str,
        source_ip: str = "10.0.0.99",
    ) -> TripwireAlert:
        """Process database command against decoy listener."""
        self.record_interaction()
        now = datetime.now(timezone.utc)
        alert_id = f"TRIP-DB-{uuid.uuid4().hex[:8].upper()}"

        return TripwireAlert(
            alert_id=alert_id,
            timestamp=now,
            trap_or_canary_id=self.trap_id,
            trap_type="DECOY_DATABASE",
            source_ip=source_ip,
            severity="CRITICAL",
            title=f"Decoy Database Command Executed: {command_str[:32]}",
            description=(
                f"Unauthenticated connection to decoy database on port {self.port} from {source_ip}. "
                f"Command payload: '{command_str[:120]}'."
            ),
            attacker_payload={"command": command_str, "port": self.port},
            mitre_technique="T1078.001",
        )
