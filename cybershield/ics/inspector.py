"""
Industrial Control Systems (ICS) Threat Inspector Engine.
Enforces Purdue model boundaries, detects unauthorized PLC commands, Modbus write abuse, and setpoint anomalies.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from cybershield.ics.schemas import (
    ICSAlert,
    ICSAnomalyType,
    ICSAsset,
    ICSProtocol,
    ICSSeverity,
    ModbusTelemetry,
    PurdueLevel,
    S7CommTelemetry,
)


class ICSThreatInspector:
    """Deep inspection engine for OT, SCADA, and Industrial Control Systems."""

    def __init__(self):
        self._assets: Dict[str, ICSAsset] = {}
        self._ip_to_asset: Dict[str, ICSAsset] = {}
        self._alerts: List[ICSAlert] = []
        self._seed_default_ics_infrastructure()

    def _seed_default_ics_infrastructure(self):
        """Seed representative industrial plant assets."""
        # 1. Critical Safety Instrumented System (SIS)
        sis = ICSAsset(
            asset_id="ICS-SIS-TRICONEX-01",
            name="Plant Safety Instrumented System (Emergency Shutdown)",
            ip_address="192.168.100.10",
            purdue_level=PurdueLevel.LEVEL_1_CONTROL,
            protocol=ICSProtocol.MODBUS_TCP,
            vendor="Schneider Electric Triconex",
            model="Tricon 3008N",
            is_safety_system=True,
            monitored_registers={
                "40001": {"min": 0.0, "max": 100.0},  # Safety Pressure Limit PSI
            },
        )
        self._register_asset(sis)

        # 2. Main Steam Turbine PLC (Siemens S7-1500)
        plc_turbine = ICSAsset(
            asset_id="ICS-PLC-TURBINE-01",
            name="Steam Turbine Main Controller",
            ip_address="192.168.100.20",
            purdue_level=PurdueLevel.LEVEL_1_CONTROL,
            protocol=ICSProtocol.S7COMM,
            vendor="Siemens",
            model="SIMATIC S7-1500",
            is_safety_system=False,
            monitored_registers={
                "40001": {"min": 0.0, "max": 3600.0},  # Rotor RPM Max
                "40002": {"min": 100.0, "max": 550.0}, # Steam Ingress Temp C
            },
        )
        self._register_asset(plc_turbine)

        # 3. SCADA HMI Operator Station (Level 2)
        hmi = ICSAsset(
            asset_id="ICS-HMI-OPERATOR-01",
            name="Control Room Primary HMI",
            ip_address="192.168.50.15",
            purdue_level=PurdueLevel.LEVEL_2_SUPERVISORY,
            protocol=ICSProtocol.MODBUS_TCP,
            vendor="Wonderware / AVEVA",
            model="InTouch 2023",
        )
        self._register_asset(hmi)

    def _register_asset(self, asset: ICSAsset):
        self._assets[asset.asset_id] = asset
        self._ip_to_asset[asset.ip_address] = asset

    def list_assets(self) -> List[ICSAsset]:
        return list(self._assets.values())

    def get_asset(self, asset_id: str) -> Optional[ICSAsset]:
        return self._assets.get(asset_id)

    def inspect_modbus(self, telemetry: ModbusTelemetry) -> Optional[ICSAlert]:
        """Inspect Modbus TCP frame for safety violations, rogue writes, and setpoint anomalies."""
        target_asset = self._ip_to_asset.get(telemetry.dst_ip)
        source_asset = self._ip_to_asset.get(telemetry.src_ip)

        target_name = target_asset.name if target_asset else f"Unmanaged PLC ({telemetry.dst_ip})"
        target_id = target_asset.asset_id if target_asset else "ICS-UNKNOWN-DEVICE"

        # 1. Detect Unauthorized Write to Safety Instrumented System (SIS) - Crown Jewel attack!
        is_write_function = telemetry.function_code in [5, 6, 15, 16]
        if target_asset and target_asset.is_safety_system and is_write_function:
            alert = ICSAlert(
                alert_id=f"ICS-ALT-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.utcnow(),
                protocol=ICSProtocol.MODBUS_TCP,
                anomaly_type=ICSAnomalyType.UNAUTHORIZED_WRITE,
                severity=ICSSeverity.CRITICAL,
                target_asset_id=target_id,
                target_asset_name=target_name,
                src_ip=telemetry.src_ip,
                dst_ip=telemetry.dst_ip,
                title=f"CRITICAL: Unauthorized Modbus Write to Safety Instrumented System (SIS)",
                description=f"Host {telemetry.src_ip} transmitted write command (FC {telemetry.function_code}) to Emergency Shutdown Controller '{target_name}'. Potential Triton/Trisis payload.",
                mitre_attack_ics_id="T0855",
                safety_impact="High risk of disabling emergency plant trip and causing physical equipment rupture.",
                remediation_steps=[
                    "Immediately trip physical air-gap interlock on Safety Instrumented System",
                    "Isolate transmitter IP " + telemetry.src_ip,
                    "Verify physical pressure relief safety valves manually",
                ],
            )
            self._alerts.append(alert)
            return alert

        # 2. Detect Purdue Model Boundary Violation (e.g. IT/DMZ host talking directly to Level 1 PLC)
        is_level1_target = target_asset and target_asset.purdue_level == PurdueLevel.LEVEL_1_CONTROL
        is_external_or_it = not source_asset or source_asset.purdue_level in [PurdueLevel.LEVEL_3_OPERATIONS, PurdueLevel.LEVEL_4_ENTERPRISE]
        if is_level1_target and (telemetry.src_ip.startswith("10.") or is_external_or_it):
            alert = ICSAlert(
                alert_id=f"ICS-ALT-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.utcnow(),
                protocol=ICSProtocol.MODBUS_TCP,
                anomaly_type=ICSAnomalyType.PURDUE_ZONE_VIOLATION,
                severity=ICSSeverity.HIGH,
                target_asset_id=target_id,
                target_asset_name=target_name,
                src_ip=telemetry.src_ip,
                dst_ip=telemetry.dst_ip,
                title="Purdue Model Boundary Violation: Direct IT-to-Control Plane Traffic",
                description=f"Direct communication from IT/DMZ IP {telemetry.src_ip} to Level 1 Controller '{target_name}' without routing through Level 2 supervisory gateway.",
                mitre_attack_ics_id="T0886",
                safety_impact="Bypasses industrial demilitarized zone (IDMZ) and allows unmonitored command injection.",
                remediation_steps=[
                    "Enforce microsegmentation ACLs blocking direct L3 to L1 traffic",
                    "Mandate all control communication through intermediate OT historian proxy",
                ],
            )
            self._alerts.append(alert)
            return alert

        # 3. Detect Setpoint Out of Safe Engineering Bounds
        if target_asset and telemetry.register_address is not None and telemetry.register_value is not None:
            reg_key = str(telemetry.register_address)
            limits = target_asset.monitored_registers.get(reg_key)
            if limits:
                val = telemetry.register_value
                if val < limits["min"] or val > limits["max"]:
                    alert = ICSAlert(
                        alert_id=f"ICS-ALT-{uuid.uuid4().hex[:8].upper()}",
                        timestamp=datetime.utcnow(),
                        protocol=ICSProtocol.MODBUS_TCP,
                        anomaly_type=ICSAnomalyType.SETPOINT_OUT_OF_BOUNDS,
                        severity=ICSSeverity.CRITICAL,
                        target_asset_id=target_id,
                        target_asset_name=target_name,
                        src_ip=telemetry.src_ip,
                        dst_ip=telemetry.dst_ip,
                        title=f"Critical Industrial Process Setpoint Out of Safe Bounds ({val})",
                        description=f"Register {reg_key} setpoint forced to {val}, exceeding safe operational envelope ({limits['min']} - {limits['max']}).",
                        mitre_attack_ics_id="T0836",
                        safety_impact="Process parameter deviation could cause catastrophic thermal or pressure runaway.",
                        remediation_steps=[
                            "Command immediate safe setpoint override to nominal baseline",
                            "Initiate physical operator inspection of field sensor and valve position",
                        ],
                    )
                    self._alerts.append(alert)
                    return alert

        return None

    def inspect_s7comm(self, telemetry: S7CommTelemetry) -> Optional[ICSAlert]:
        """Inspect Siemens S7comm industrial control protocol."""
        target_asset = self._ip_to_asset.get(telemetry.dst_ip)
        target_name = target_asset.name if target_asset else f"Siemens PLC ({telemetry.dst_ip})"
        target_id = target_asset.asset_id if target_asset else "ICS-S7-PLC"

        # Detect CPU Stop Command (Stuxnet / Industroyer pattern)
        if "stop" in telemetry.function_name.lower() or telemetry.function_code == 0x29:
            alert = ICSAlert(
                alert_id=f"ICS-ALT-{uuid.uuid4().hex[:8].upper()}",
                timestamp=datetime.utcnow(),
                protocol=ICSProtocol.S7COMM,
                anomaly_type=ICSAnomalyType.PLC_CPU_STOP,
                severity=ICSSeverity.CRITICAL,
                target_asset_id=target_id,
                target_asset_name=target_name,
                src_ip=telemetry.src_ip,
                dst_ip=telemetry.dst_ip,
                title=f"CRITICAL: Siemens S7 PLC CPU STOP Command Issued",
                description=f"Host {telemetry.src_ip} issued a remote CPU STOP command to Siemens controller '{target_name}'. Attackers halt PLC CPU to shut down protective interlocks.",
                mitre_attack_ics_id="T0816",
                safety_impact="Immediate halting of industrial controller logic causing plant shutdown or unmonitored state.",
                remediation_steps=[
                    "Physically inspect PLC front key switch and set to RUN position",
                    "Block S7comm protocol port 102 from source IP " + telemetry.src_ip,
                    "Verify firmware integrity and compare DB blocks against golden backup",
                ],
            )
            self._alerts.append(alert)
            return alert

        return None

    def list_alerts(self, limit: int = 50) -> List[ICSAlert]:
        return list(reversed(self._alerts))[:limit]

    def get_overview(self) -> Dict[str, Any]:
        """Summary metrics of industrial control security."""
        total = len(self._assets)
        sis_count = sum(1 for a in self._assets.values() if a.is_safety_system)
        alerts_count = len(self._alerts)
        critical_alerts = sum(1 for a in self._alerts if a.severity == ICSSeverity.CRITICAL)

        return {
            "total_ics_assets": total,
            "safety_instrumented_systems_count": sis_count,
            "active_ics_alerts": alerts_count,
            "critical_process_alerts": critical_alerts,
            "monitored_protocols": [p.value for p in ICSProtocol],
        }
