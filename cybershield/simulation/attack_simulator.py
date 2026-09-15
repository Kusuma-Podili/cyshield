"""Enterprise Cyber Threat & APT Scenario Simulator for CyberShield Enterprise.

Simulates realistic, complex multi-stage cyberattack campaigns:
- Ransomware detonation (Shadow copy purge, file entropy spike, ransom note drop)
- Credential stuffing & distributed brute force
- Advanced Web Exploitation (SQL Injection & Web Shell drops)
- APT29 Lateral movement (Impossible travel, Mimikatz credential dumping, WMI hops)
- Covert data exfiltration burst with high entropy
Permits real-time verification of AI models, Sigma/YARA rules, and SOAR playbooks.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone

from cybershield.core.models import (
    NormalizedEvent,
    NetworkFlow,
    LogSourceType,
    generate_id,
    now_utc,
)
from cybershield.ingestion.collector import collector
from cybershield.engines.static_scanner import static_scanner
from cybershield.engines.yara_engine import yara_engine
from cybershield.soar.playbook import soar_engine

logger = logging.getLogger("cybershield.simulation")


class AttackSimulator:
    """Orchestrates realistic multi-vector cyberattack simulations."""

    @classmethod
    async def simulate_ransomware_detonation(cls, host: str = "ws-finance-08.corp", user: str = "mscott") -> Dict[str, Any]:
        """Detonate simulated Ransomware kill chain."""
        logger.warning("SIMULATION START: Ransomware Detonation on %s", host)

        # 1. Shadow copy deletion command
        evt1 = NormalizedEvent(
            log_source=LogSourceType.SYSMON,
            event_category="endpoint",
            event_action="Process Creation",
            host_name=host,
            user_name=user,
            process_id=4812,
            process_name="vssadmin.exe",
            command_line="vssadmin.exe delete shadows /all /quiet",
            parent_process_name="powershell.exe",
            parent_process_id=2930,
            metadata={"technique": "T1490"}
        )
        await collector.ingest_event(evt1)

        # 2. File modification burst with high entropy
        evt2 = NormalizedEvent(
            log_source=LogSourceType.SYSMON,
            event_category="endpoint",
            event_action="File Created",
            host_name=host,
            user_name=user,
            file_name="HOW_TO_DECRYPT_FILES.txt",
            file_path="C:\\Users\\mscott\\Desktop\\HOW_TO_DECRYPT_FILES.txt",
            payload_content="All your personal documents, photos, databases have been encrypted! Pay the ransom in Bitcoin to get the decrypt key.",
            metadata={"entropy": 7.92}
        )
        await collector.ingest_event(evt2)

        # 3. Static scanner / YARA evaluation on ransom note text
        yara_alerts = yara_engine.scan_and_alert(evt2.payload_content, source_label="Simulated File Drop")
        for ya in yara_alerts:
            await collector._handle_alert(ya)

        # 4. Trigger automated SOAR Ransomware Containment Playbook
        soar_run = await soar_engine.execute_playbook(
            playbook_id="PB-RANSOMWARE-01",
            target_entity=host,
            context_vars={"host": host, "user": user, "source_ip": "45.33.32.156"}
        )

        return {
            "scenario": "Ransomware Detonation",
            "host": host,
            "user": user,
            "events_injected": 2,
            "playbook_execution_id": soar_run.execution_id,
            "playbook_status": soar_run.status,
        }

    @classmethod
    async def simulate_credential_stuffing(cls, target_user: str = "jdoe_dev", attacker_ip: str = "91.240.118.172") -> Dict[str, Any]:
        """Simulate high-velocity brute-force authentication spray."""
        logger.warning("SIMULATION START: Credential Stuffing against user %s from %s", target_user, attacker_ip)

        for i in range(8):
            evt = NormalizedEvent(
                log_source=LogSourceType.WINDOWS_EVENT,
                event_category="identity",
                event_action="Failed Logon Attempt",
                host_name="dc-primary.corp",
                user_name=target_user,
                source_ip=attacker_ip,
                metadata={"sysmon_event_id": 4625, "attempt_index": i + 1}
            )
            await collector.ingest_event(evt)
            await asyncio.sleep(0.05)

        # Trigger SOAR Brute Force Playbook
        soar_run = await soar_engine.execute_playbook(
            playbook_id="PB-BRUTEFORCE-02",
            target_entity=target_user,
            context_vars={"user": target_user, "source_ip": attacker_ip}
        )

        return {
            "scenario": "Credential Stuffing",
            "attacker_ip": attacker_ip,
            "target_user": target_user,
            "attempts": 8,
            "playbook_execution_id": soar_run.execution_id,
            "playbook_status": soar_run.status,
        }

    @classmethod
    async def simulate_web_exploit_sqli(cls, attacker_ip: str = "185.220.101.5") -> Dict[str, Any]:
        """Simulate SQL Injection attack against public portal."""
        logger.warning("SIMULATION START: SQL Injection exploit attempt from %s", attacker_ip)

        sqli_payload = "/portal/login?user=admin' UNION SELECT null, username, password_hash FROM admin_users -- &submit=1"
        evt = NormalizedEvent(
            log_source=LogSourceType.APACHE_NGINX,
            event_category="web",
            event_action="http_request",
            source_ip=attacker_ip,
            destination_ip="10.0.1.10",
            http_method="POST",
            http_url=sqli_payload,
            http_status=200,
            payload_content="user=admin' UNION SELECT null, username, password_hash FROM admin_users --",
            http_user_agent="Mozilla/5.0 (Kali Linux) sqlmap/1.7#stable"
        )
        await collector.ingest_event(evt)

        return {
            "scenario": "SQL Injection Attack",
            "attacker_ip": attacker_ip,
            "injected_url": sqli_payload,
            "event_id": evt.event_id,
        }

    @classmethod
    async def simulate_apt_lateral_movement(cls) -> Dict[str, Any]:
        """Simulate full APT29 credential theft and lateral hop."""
        logger.warning("SIMULATION START: APT29 Lateral Movement Sequence")

        # 1. Impossible travel login
        evt1 = NormalizedEvent(
            log_source=LogSourceType.WINDOWS_EVENT,
            event_category="identity",
            event_action="Successful Logon",
            host_name="vpn-gateway.corp",
            user_name="admin_corp",
            source_ip="103.251.167.20",  # Beijing IP
            metadata={"technique": "T1078"}
        )
        await collector.ingest_event(evt1)

        # 2. Mimikatz LSASS access
        evt2 = NormalizedEvent(
            log_source=LogSourceType.SYSMON,
            event_category="endpoint",
            event_action="Process Creation",
            host_name="jumpbox-01.corp",
            user_name="admin_corp",
            process_name="mimikatz.exe",
            command_line="mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
            parent_process_name="cmd.exe",
            metadata={"technique": "T1003"}
        )
        await collector.ingest_event(evt2)

        # 3. Lateral jump to database server
        evt3 = NormalizedEvent(
            log_source=LogSourceType.SYSMON,
            event_category="network",
            event_action="Network Connection Detected",
            host_name="jumpbox-01.corp",
            user_name="admin_corp",
            source_ip="10.0.1.50",
            destination_ip="10.0.2.100",  # Finance DB
            destination_port=445,  # SMB
            protocol="TCP",
            metadata={"technique": "T1021.002"}
        )
        await collector.ingest_event(evt3)

        # Trigger SOAR Lateral Movement Playbook
        soar_run = await soar_engine.execute_playbook(
            playbook_id="PB-LATERAL-04",
            target_entity="jumpbox-01.corp",
            context_vars={"host": "jumpbox-01.corp", "user": "admin_corp"}
        )

        return {
            "scenario": "APT29 Lateral Movement",
            "host": "jumpbox-01.corp",
            "user": "admin_corp",
            "events_injected": 3,
            "playbook_execution_id": soar_run.execution_id,
            "playbook_status": soar_run.status,
        }

    @classmethod
    async def simulate_data_exfiltration(cls) -> Dict[str, Any]:
        """Simulate high-entropy anomalous egress data flow."""
        logger.warning("SIMULATION START: Data Exfiltration Burst")

        flow = NetworkFlow(
            source_ip="10.0.1.88",
            destination_ip="198.51.100.23",  # Cobalt Strike C2 IP
            source_port=54210,
            destination_port=443,
            protocol="TCP",
            bytes_sent=185000000,  # 185 MB
            bytes_received=4500,
            packets_sent=128000,
            packets_received=600,
            duration_ms=4500.0,
            tcp_flags=["PSH", "ACK"],
            byte_entropy=7.88,  # Highly encrypted archive
        )
        _, alert = await collector.ingest_network_flow(flow)

        # Trigger SOAR Data Exfiltration Playbook
        soar_run = await soar_engine.execute_playbook(
            playbook_id="PB-EXFIL-03",
            target_entity="10.0.1.88",
            context_vars={"host": "ws-engineering-04.corp", "user": "jdoe_dev", "dest_ip": "198.51.100.23"}
        )

        return {
            "scenario": "Data Exfiltration Burst",
            "source_ip": "10.0.1.88",
            "destination_ip": "198.51.100.23",
            "bytes_exfiltrated": flow.bytes_sent,
            "entropy": flow.byte_entropy,
            "alert_generated": alert.alert_id if alert else None,
            "playbook_execution_id": soar_run.execution_id,
        }


# Global singleton simulator
attack_simulator = AttackSimulator()
