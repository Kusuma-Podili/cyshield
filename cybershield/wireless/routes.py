"""CyberShield Enterprise - Wireless & RF Cyber Defense API Routes.
Exposes endpoints for wireless frame ingestion, corporate AP whitelisting,
rogue AP detection, and campus RF airspace sanitation reports.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    WirelessAccessPoint,
    WirelessFrame,
    WirelessThreatAlert,
    AirspaceSanitationReport,
)
from .defense import WirelessDefenseEngine

router = APIRouter(prefix="/api/v1/wireless", tags=["Wireless & RF Cyber Defense"])

# Active singleton wireless engine
_WIRELESS_ENGINE = WirelessDefenseEngine()


@router.post("/frames", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
def ingest_wireless_frame(frame: WirelessFrame):
    """Ingest over-the-air 802.11 / BLE / Zigbee monitor frame."""
    alert = _WIRELESS_ENGINE.ingest_frame(frame)
    return {
        "status": "ingested",
        "frame_id": frame.frame_id,
        "threat_detected": alert is not None,
        "threat_type": alert.threat_type.value if alert else None,
        "alert_id": alert.alert_id if alert else None,
    }


@router.post("/whitelist", response_model=WirelessAccessPoint, status_code=status.HTTP_201_CREATED)
def whitelist_access_point(
    bssid: str = Query(...),
    ssid: str = Query(...),
    channel: int = Query(36, ge=1, le=165),
    encryption: str = Query("WPA3_SAE"),
):
    """Whitelist an authorized corporate wireless access point."""
    return _WIRELESS_ENGINE.register_sanctioned_ap(
        bssid=bssid,
        ssid=ssid,
        channel=channel,
        encryption=encryption,
    )


@router.get("/aps", response_model=List[WirelessAccessPoint])
def list_observed_access_points():
    """Retrieve all Wi-Fi access points observed in campus RF airspace."""
    return list(_WIRELESS_ENGINE.observed_aps.values())


@router.get("/threats", response_model=List[WirelessThreatAlert])
def list_wireless_threats():
    """Retrieve active RF airspace alerts (Evil Twin, Deauth DoS, BLE stalking)."""
    return _WIRELESS_ENGINE.alerts


@router.get("/airspace", response_model=AirspaceSanitationReport)
def get_airspace_sanitation():
    """Calculate and return physical facility RF airspace sanitation report."""
    return _WIRELESS_ENGINE.get_airspace_report()
