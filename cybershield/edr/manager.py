"""Central EDR Fleet Manager & Response Dispatcher."""

from __future__ import annotations

import logging
import secrets
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from cybershield.edr.behavior_engine import EDRBehaviorEngine
from cybershield.edr.schemas import (
    AgentStatus,
    EDRAgentRegistrationRequest,
    EDRAgentRegistrationResponse,
    EDRBehavioralAlert,
    EDRCommand,
    EDRCommandAction,
    EDRHeartbeatRequest,
    EDRHeartbeatResponse,
    EDRTelemetryBatchRequest,
)
from cybershield.tasks.event_bus import global_event_bus

logger = logging.getLogger("cybershield.edr.manager")


class ManagedAgentRecord:
    """In-memory representation of an enrolled endpoint sensor."""

    def __init__(
        self,
        agent_id: str,
        hostname: str,
        os_platform: str,
        os_version: str,
        architecture: str,
        ip_addresses: List[str],
        mac_addresses: List[str],
        agent_version: str,
        auth_token: str,
    ) -> None:
        self.agent_id = agent_id
        self.hostname = hostname
        self.os_platform = os_platform
        self.os_version = os_version
        self.architecture = architecture
        self.ip_addresses = ip_addresses
        self.mac_addresses = mac_addresses
        self.agent_version = agent_version
        self.auth_token = auth_token
        self.status = AgentStatus.ONLINE
        self.enrolled_at = datetime.now(timezone.utc)
        self.last_seen = datetime.now(timezone.utc)
        self.cpu_usage_pct = 0.0
        self.memory_usage_pct = 0.0
        self.disk_usage_pct = 0.0
        self.active_threats_count = 0
        self.command_queue: List[EDRCommand] = []

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "os_platform": self.os_platform,
            "os_version": self.os_version,
            "architecture": self.architecture,
            "ip_addresses": self.ip_addresses,
            "mac_addresses": self.mac_addresses,
            "agent_version": self.agent_version,
            "status": self.status.value,
            "enrolled_at": self.enrolled_at.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "cpu_usage_pct": self.cpu_usage_pct,
            "memory_usage_pct": self.memory_usage_pct,
            "disk_usage_pct": self.disk_usage_pct,
            "active_threats_count": self.active_threats_count,
            "pending_commands_count": len(self.command_queue),
        }


class EDRFleetManager:
    """Master manager for EDR agent fleet and behavioral telemetry ingestion."""

    def __init__(self) -> None:
        self._agents: Dict[str, ManagedAgentRecord] = {}
        self._alerts: List[EDRBehavioralAlert] = []
        self.behavior_engine = EDRBehaviorEngine()
        self._seed_default_agents_if_empty()

    def _seed_default_agents_if_empty(self) -> None:
        """Seed baseline enterprise endpoint agents for monitoring."""
        if not self._agents:
            self.register_agent(
                EDRAgentRegistrationRequest(
                    hostname="ws-exec-laptop.corp",
                    os_platform="WINDOWS",
                    os_version="Windows 11 Enterprise 23H2",
                    architecture="x86_64",
                    ip_addresses=["10.0.3.15"],
                    mac_addresses=["00:1A:2B:3C:4D:5E"],
                    agent_version="2.4.0",
                )
            )
            self.register_agent(
                EDRAgentRegistrationRequest(
                    hostname="srv-prod-api-01.corp",
                    os_platform="LINUX",
                    os_version="Ubuntu 22.04.4 LTS",
                    architecture="x86_64",
                    ip_addresses=["10.0.1.25"],
                    mac_addresses=["00:50:56:AB:CD:EF"],
                    agent_version="2.4.0",
                )
            )

    def register_agent(self, req: EDRAgentRegistrationRequest) -> EDRAgentRegistrationResponse:
        """Enroll a new endpoint sensor with generated cryptotoken."""
        agent_id = f"AGT-{uuid.uuid4().hex[:8].upper()}"
        auth_token = f"agt_sec_{secrets.token_urlsafe(32)}"

        record = ManagedAgentRecord(
            agent_id=agent_id,
            hostname=req.hostname,
            os_platform=req.os_platform.value if hasattr(req.os_platform, "value") else str(req.os_platform),
            os_version=req.os_version,
            architecture=req.architecture,
            ip_addresses=req.ip_addresses,
            mac_addresses=req.mac_addresses,
            agent_version=req.agent_version,
            auth_token=auth_token,
        )
        self._agents[agent_id] = record
        logger.info("EDR: Enrolled agent '%s' (%s - %s)", agent_id, req.hostname, req.os_platform)

        return EDRAgentRegistrationResponse(
            agent_id=agent_id,
            auth_token=auth_token,
            heartbeat_interval_sec=15,
            enrolled_at=record.enrolled_at,
        )

    def process_heartbeat(self, req: EDRHeartbeatRequest) -> EDRHeartbeatResponse:
        """Process heartbeat, update resource diagnostics, and deliver pending commands."""
        agent = self._agents.get(req.agent_id)
        if not agent:
            # Auto-register if not found
            self.register_agent(
                EDRAgentRegistrationRequest(
                    hostname=f"host-{req.agent_id[:8]}",
                    os_platform="WINDOWS",
                    os_version="Windows 11",
                )
            )
            agent = self._agents.get(req.agent_id)

        if agent:
            agent.last_seen = datetime.now(timezone.utc)
            agent.status = req.status
            agent.cpu_usage_pct = req.cpu_usage_pct
            agent.memory_usage_pct = req.memory_usage_pct
            agent.disk_usage_pct = req.disk_usage_pct
            agent.active_threats_count = req.active_threats_count

            # Pop pending commands to send to agent
            commands_to_send = list(agent.command_queue)
            agent.command_queue.clear()
            for cmd in commands_to_send:
                cmd.status = "DISPATCHED"

            return EDRHeartbeatResponse(
                status="ACK",
                next_heartbeat_sec=15,
                pending_commands=commands_to_send,
            )

        return EDRHeartbeatResponse(status="ERROR", next_heartbeat_sec=60, pending_commands=[])

    def ingest_telemetry(self, batch: EDRTelemetryBatchRequest) -> List[EDRBehavioralAlert]:
        """Process an endpoint telemetry batch through behavioral engines."""
        agent = self._agents.get(batch.agent_id)
        hostname = agent.hostname if agent else "unknown-host"

        new_alerts: List[EDRBehavioralAlert] = []

        # 1. Analyze processes
        if batch.processes:
            p_alerts = self.behavior_engine.analyze_processes(batch.agent_id, hostname, batch.processes)
            new_alerts.extend(p_alerts)

        # 2. Analyze FIM
        if batch.fim_events:
            f_alerts = self.behavior_engine.analyze_fim(batch.agent_id, hostname, batch.fim_events)
            new_alerts.extend(f_alerts)

        # 3. Analyze Network Sockets
        if batch.sockets:
            s_alerts = self.behavior_engine.analyze_network_sockets(batch.agent_id, hostname, batch.sockets)
            new_alerts.extend(s_alerts)

        # Store alerts
        self._alerts.extend(new_alerts)
        if len(self._alerts) > 500:
            self._alerts = self._alerts[-500:]

        if agent:
            agent.active_threats_count += len(new_alerts)

        # Publish critical alerts to global event bus
        for a in new_alerts:
            if a.severity in ("CRITICAL", "HIGH"):
                try:
                    global_event_bus.publish_sync(
                        topic="edr.behavioral.alert",
                        data={
                            "alert_id": a.alert_id,
                            "agent_id": a.agent_id,
                            "hostname": a.hostname,
                            "title": a.title,
                            "severity": a.severity,
                            "mitre_technique": a.mitre_technique,
                        },
                        source="edr_manager",
                    )
                except Exception:
                    pass

        return new_alerts

    def queue_command(
        self,
        agent_id: str,
        action: EDRCommandAction,
        target: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[EDRCommand]:
        """Enqueue an operational response command for an agent."""
        agent = self._agents.get(agent_id)
        if not agent:
            return None

        cmd = EDRCommand(
            command_id=f"CMD-{uuid.uuid4().hex[:8].upper()}",
            action=action,
            target=target,
            parameters=parameters or {},
            status="PENDING",
        )
        agent.command_queue.append(cmd)

        if action == EDRCommandAction.ISOLATE_NETWORK:
            agent.status = AgentStatus.ISOLATED

        logger.warning("EDR: Queued command '%s' for agent '%s'", action.value, agent_id)
        return cmd

    def get_agent(self, agent_id: str) -> Optional[dict]:
        agent = self._agents.get(agent_id)
        return agent.to_dict() if agent else None

    def list_agents(self) -> List[dict]:
        return [a.to_dict() for a in self._agents.values()]

    def list_alerts(self, agent_id: Optional[str] = None) -> List[EDRBehavioralAlert]:
        if agent_id:
            return [a for a in self._alerts if a.agent_id == agent_id]
        return list(self._alerts)

    def clear(self) -> None:
        self._agents.clear()
        self._alerts.clear()
        self._seed_default_agents_if_empty()


# Global singleton instance
edr_manager = EDRFleetManager()
