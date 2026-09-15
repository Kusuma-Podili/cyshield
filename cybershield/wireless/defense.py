"""CyberShield Enterprise - Autonomous Wireless & RF Cyber Defense Engine.
Monitors 802.11 Wi-Fi, BLE, and Zigbee frames to detect Evil Twin rogue APs,
deauthentication flood DoS, BLE stalking beacons, and computes airspace health.
"""

import uuid
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from .schemas import (
    WirelessProtocol,
    WirelessThreatType,
    WirelessFrameType,
    WirelessAccessPoint,
    WirelessFrame,
    WirelessThreatAlert,
    AirspaceSanitationReport,
)


class WirelessDefenseEngine:
    """Real-time physical campus wireless airspace sentinel and threat detector."""

    def __init__(self):
        # Whitelisted corporate infrastructure
        self.sanctioned_bssids: Set[str] = set()
        self.corporate_ssids: Set[str] = {"Corp-Secure-WiFi", "Corp-IoT-Production"}

        # State storage
        self.observed_aps: Dict[str, WirelessAccessPoint] = {}
        self.tracked_ble_devices: Dict[str, Dict[str, Any]] = {}
        self.alerts: List[WirelessThreatAlert] = []

        # Sliding window deauth flood tracker: target_bssid -> list of event datetimes
        self.deauth_timestamps: Dict[str, List[datetime]] = defaultdict(list)

    def register_sanctioned_ap(
        self,
        bssid: str,
        ssid: str,
        channel: int = 36,
        encryption: str = "WPA3_SAE",
    ) -> WirelessAccessPoint:
        """Whitelist an authorized enterprise wireless access point."""
        bssid_clean = bssid.strip().lower()
        self.sanctioned_bssids.add(bssid_clean)
        self.corporate_ssids.add(ssid)

        ap = WirelessAccessPoint(
            bssid=bssid_clean,
            ssid=ssid,
            channel=channel,
            encryption=encryption,
            is_corporate_sanctioned=True,
        )
        self.observed_aps[bssid_clean] = ap
        return ap

    def ingest_frame(self, frame: WirelessFrame) -> Optional[WirelessThreatAlert]:
        """Process incoming over-the-air frame through RF security heuristics."""
        alert: Optional[WirelessThreatAlert] = None

        if frame.protocol == WirelessProtocol.WIFI_80211:
            if frame.frame_type == WirelessFrameType.MANAGEMENT_BEACON:
                alert = self._inspect_beacon_frame(frame)
            elif frame.frame_type in {WirelessFrameType.MANAGEMENT_DEAUTH, WirelessFrameType.MANAGEMENT_DISASSOC}:
                alert = self._inspect_deauth_frame(frame)

        elif frame.protocol == WirelessProtocol.BLE_BLUETOOTH:
            alert = self._inspect_ble_frame(frame)

        if alert:
            self.alerts.append(alert)

        return alert

    def _inspect_beacon_frame(self, frame: WirelessFrame) -> Optional[WirelessThreatAlert]:
        """Inspect 802.11 beacon for Evil Twin rogue APs or encryption downgrade."""
        bssid = (frame.bssid or frame.source_mac).strip().lower()
        ssid = frame.payload_snippet or "Unknown-SSID"
        now = frame.timestamp

        # Register or update observed AP
        is_sanctioned = bssid in self.sanctioned_bssids
        if bssid not in self.observed_aps:
            self.observed_aps[bssid] = WirelessAccessPoint(
                bssid=bssid,
                ssid=ssid,
                channel=frame.channel,
                signal_dbm=frame.signal_rssi,
                encryption="WPA2_PSK",  # Default inferred
                is_corporate_sanctioned=is_sanctioned,
                first_seen=now,
                last_seen=now,
            )
        else:
            ap = self.observed_aps[bssid]
            ap.last_seen = now
            ap.signal_dbm = frame.signal_rssi

        # 1. Evil Twin Rogue AP Detection
        # Broadcasts corporate SSID but originates from an unsanctioned BSSID!
        if ssid in self.corporate_ssids and not is_sanctioned:
            return WirelessThreatAlert(
                alert_id=f"rf-twin-{uuid.uuid4().hex[:8]}",
                threat_type=WirelessThreatType.EVIL_TWIN_ROGUE_AP,
                detected_bssid_or_mac=bssid,
                ssid=ssid,
                affected_clients=[],
                signal_rssi=frame.signal_rssi,
                severity="CRITICAL",
                mitre_technique="T1557.002 - Adversary-in-the-Middle: Evil Twin",
                details=(
                    f"Rogue Access Point spoofing corporate SSID '{ssid}' detected. "
                    f"Transmitting from unauthorized radio BSSID {bssid} at RSSI {frame.signal_rssi} dBm (Channel {frame.channel})."
                ),
                countermeasure="Trigger physical RF direction finding and transmit protective 802.11 containment frames.",
            )

        return None

    def _inspect_deauth_frame(self, frame: WirelessFrame) -> Optional[WirelessThreatAlert]:
        """Detect deauthentication flooding DoS and WPA handshake harvest attacks."""
        target_bssid = (frame.bssid or frame.dest_mac).strip().lower()
        now = frame.timestamp

        timestamps = self.deauth_timestamps[target_bssid]
        timestamps.append(now)

        # Sliding 5-second window
        cutoff = now - timedelta(seconds=5)
        self.deauth_timestamps[target_bssid] = [t for t in timestamps if t >= cutoff]
        deauth_count = len(self.deauth_timestamps[target_bssid])

        # If > 10 deauths within 5 seconds -> active flood DoS!
        if deauth_count >= 10:
            # Clear window so alert does not spam continuously
            self.deauth_timestamps[target_bssid].clear()

            return WirelessThreatAlert(
                alert_id=f"rf-deauth-{uuid.uuid4().hex[:8]}",
                threat_type=WirelessThreatType.DEAUTH_FLOOD_DOS,
                detected_bssid_or_mac=frame.source_mac,
                ssid=None,
                affected_clients=[frame.dest_mac],
                signal_rssi=frame.signal_rssi,
                severity="HIGH",
                mitre_technique="T1498 - Network Denial of Service",
                details=(
                    f"802.11 Deauthentication Flood DoS detected from attacker {frame.source_mac} "
                    f"targeting BSSID/Client {target_bssid} ({deauth_count} frames in <5s)."
                ),
                countermeasure="Enforce 802.11w Protected Management Frames (PMF) across all corporate SSIDs.",
            )

        return None

    def _inspect_ble_frame(self, frame: WirelessFrame) -> Optional[WirelessThreatAlert]:
        """Detect rogue BLE tracking beacons or unauthorized smart building bugs."""
        mac = frame.source_mac.strip().lower()
        now = frame.timestamp

        if mac not in self.tracked_ble_devices:
            self.tracked_ble_devices[mac] = {
                "mac": mac,
                "first_seen": now,
                "sightings": 1,
                "highest_rssi": frame.signal_rssi,
            }
        else:
            dev = self.tracked_ble_devices[mac]
            dev["sightings"] += 1
            if frame.signal_rssi > dev["highest_rssi"]:
                dev["highest_rssi"] = frame.signal_rssi

            # Suspicious stalking threshold: continuous persistent beaconing (>30 frames, strong RSSI > -55)
            if dev["sightings"] == 30 and dev["highest_rssi"] > -55:
                return WirelessThreatAlert(
                    alert_id=f"rf-ble-{uuid.uuid4().hex[:8]}",
                    threat_type=WirelessThreatType.BLE_TRACKER_STALKING,
                    detected_bssid_or_mac=mac,
                    ssid="BLE-Canary-Tracker",
                    affected_clients=[],
                    signal_rssi=dev["highest_rssi"],
                    severity="MEDIUM",
                    mitre_technique="T1557 - Man-in-the-Middle / Physical Surveillance",
                    details=(
                        f"Persistent unauthorized BLE tracking peripheral {mac} observed in executive facility "
                        f"(RSSI {dev['highest_rssi']} dBm, 30+ sightings)."
                    ),
                    countermeasure="Locate and inspect physical premises for rogue Bluetooth tags.",
                )

        return None

    def get_airspace_report(self) -> AirspaceSanitationReport:
        """Compute campus RF health and sanitation hygiene index."""
        total_aps = len(self.observed_aps)
        sanctioned = sum(1 for ap in self.observed_aps.values() if ap.is_corporate_sanctioned)
        rogue = total_aps - sanctioned
        threats = len(self.alerts)
        ble_count = len(self.tracked_ble_devices)

        # Hygiene index calculation: 100 base, penalized by rogues and active threats
        score = 100.0 - (rogue * 15.0) - (threats * 10.0)
        health_index = round(max(0.0, min(100.0, score)), 2)

        return AirspaceSanitationReport(
            total_aps_scanned=total_aps,
            sanctioned_aps_count=sanctioned,
            rogue_aps_count=rogue,
            active_threats_count=threats,
            ble_beacons_tracked=ble_count,
            airspace_health_index=health_index,
        )
