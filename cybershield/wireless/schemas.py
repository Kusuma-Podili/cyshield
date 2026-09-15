"""CyberShield Enterprise - Wireless & RF Cyber Defense Schemas.
Data contracts for 802.11 Wi-Fi frames, BLE advertisements, rogue AP detection,
deauthentication flood attacks, and airspace sanitation reports.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class WirelessProtocol(str, Enum):
    WIFI_80211 = "WIFI_80211"
    BLE_BLUETOOTH = "BLE_BLUETOOTH"
    ZIGBEE_802154 = "ZIGBEE_802154"
    LORA_WAN = "LORA_WAN"


class WirelessThreatType(str, Enum):
    EVIL_TWIN_ROGUE_AP = "EVIL_TWIN_ROGUE_AP"
    DEAUTH_FLOOD_DOS = "DEAUTH_FLOOD_DOS"
    KARMA_MANA_ATTACK = "KARMA_MANA_ATTACK"
    BLE_TRACKER_STALKING = "BLE_TRACKER_STALKING"
    WEAK_ENCRYPTION_WEP_WPA1 = "WEAK_ENCRYPTION_WEP_WPA1"
    BEACON_FLOODING = "BEACON_FLOODING"
    ZIGBEE_REPLAY_ATTACK = "ZIGBEE_REPLAY_ATTACK"


class WirelessFrameType(str, Enum):
    MANAGEMENT_BEACON = "MANAGEMENT_BEACON"
    MANAGEMENT_PROBE_REQ = "MANAGEMENT_PROBE_REQ"
    MANAGEMENT_DEAUTH = "MANAGEMENT_DEAUTH"
    MANAGEMENT_DISASSOC = "MANAGEMENT_DISASSOC"
    DATA_FRAME = "DATA_FRAME"
    BLE_ADVERTISEMENT = "BLE_ADVERTISEMENT"


class WirelessAccessPoint(BaseModel):
    """Observed Wi-Fi Access Point radio footprint."""
    bssid: str = Field(..., description="Access Point BSSID MAC address (e.g. 00:14:22:01:23:45)")
    ssid: str = Field(..., description="Service Set Identifier network name")
    channel: int = Field(default=1, ge=1, le=165)
    signal_dbm: int = Field(default=-65, ge=-110, le=0)
    encryption: str = Field(default="WPA3_SAE", description="OPEN, WEP, WPA2_PSK, WPA2_ENTERPRISE, WPA3_SAE")
    vendor_oui: Optional[str] = None
    is_corporate_sanctioned: bool = False
    client_count: int = Field(default=0)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WirelessFrame(BaseModel):
    """Raw 802.11 / BLE / Zigbee over-the-air capture frame."""
    frame_id: str
    protocol: WirelessProtocol = WirelessProtocol.WIFI_80211
    source_mac: str
    dest_mac: str
    bssid: Optional[str] = None
    frame_type: WirelessFrameType = WirelessFrameType.MANAGEMENT_BEACON
    signal_rssi: int = Field(default=-60, ge=-120, le=0)
    channel: int = Field(default=6)
    payload_snippet: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class WirelessThreatAlert(BaseModel):
    """Security alert raised from RF over-the-air monitoring."""
    alert_id: str
    threat_type: WirelessThreatType
    detected_bssid_or_mac: str
    ssid: Optional[str] = None
    affected_clients: List[str] = Field(default_factory=list)
    signal_rssi: int
    severity: str = Field(default="HIGH", description="LOW, MEDIUM, HIGH, CRITICAL")
    mitre_technique: str
    details: str
    countermeasure: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AirspaceSanitationReport(BaseModel):
    """Consolidated physical campus RF airspace hygiene index."""
    total_aps_scanned: int
    sanctioned_aps_count: int
    rogue_aps_count: int
    active_threats_count: int
    ble_beacons_tracked: int
    airspace_health_index: float = Field(..., ge=0.0, le=100.0)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
