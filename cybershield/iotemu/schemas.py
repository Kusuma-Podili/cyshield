"""CyberShield Enterprise - Autonomous Firmware Emulation & IoT Sandbox Schemas.
Data contracts for multi-arch binary emulation (MIPS/ARM), NVRAM hooking,
embedded CGI fuzzing, and zero-day backdoor discovery.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class CpuArchitecture(str, Enum):
    MIPS_32_EB = "MIPS_32_EB"  # MIPS Big Endian
    MIPS_32_EL = "MIPS_32_EL"  # MIPS Little Endian (MIPSEL)
    ARM_V7_A = "ARM_V7_A"      # ARM 32-bit
    AARCH64 = "AARCH64"        # ARM 64-bit
    POWERPC_32 = "POWERPC_32"


class IoTVulnerabilityType(str, Enum):
    COMMAND_INJECTION_CGI = "COMMAND_INJECTION_CGI"
    HARDCODED_BACKDOOR_CREDENTIALS = "HARDCODED_BACKDOOR_CREDENTIALS"
    BUFFER_OVERFLOW_HTTP_HEADER = "BUFFER_OVERFLOW_HTTP_HEADER"
    UPNP_WAN_INTERFACE_LEAK = "UPNP_WAN_INTERFACE_LEAK"
    UNAUTHENTICATED_NVRAM_DUMP = "UNAUTHENTICATED_NVRAM_DUMP"


class EmulateDaemonRequest(BaseModel):
    """Request to emulate an embedded network daemon in the virtual sandbox."""
    daemon_name: str = Field(..., description="e.g. httpd, goahead, miniupnpd")
    architecture: CpuArchitecture = CpuArchitecture.MIPS_32_EL
    firmware_vendor: str = Field(default="Generic-IoT-Router")
    nvram_overrides: Dict[str, str] = Field(default_factory=dict)
    listening_port: int = Field(default=80, ge=1, le=65535)


class FuzzEndpointRequest(BaseModel):
    """Request to dynamically test an embedded CGI endpoint for memory corruption and command injection."""
    endpoint_path: str = Field(..., description="e.g. /apply.cgi, /cgi-bin/system.cgi")
    http_method: str = "POST"
    query_params: Dict[str, str] = Field(default_factory=dict)
    payload_input: str = Field(..., description="Test payload string or fuzz vector")


class IoTVulnerabilityAlert(BaseModel):
    """Vulnerability finding identified during dynamic firmware emulation."""
    finding_id: str
    vulnerability_type: IoTVulnerabilityType
    target_daemon: str
    architecture: CpuArchitecture
    severity: str = "CRITICAL"
    mitre_technique: str
    cve_id: Optional[str] = None
    proof_of_concept: str
    details: str
    remediation: str
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EmulationSessionReport(BaseModel):
    """Status report of an active emulated firmware sandbox session."""
    session_id: str
    daemon_name: str
    architecture: CpuArchitecture
    status: str = "EMULATION_RUNNING"
    simulated_ip: str = "192.168.1.1"
    port: int = 80
    vulnerabilities_found: int = 0
    nvram_keys_hooked: int = 0
    uptime_seconds: float = 0.0


class IoTPlatformStatus(BaseModel):
    """Consolidated IoT emulation lab status."""
    active_sandboxes_count: int
    total_firmware_vulnerabilities: int
    critical_backdoors_identified: int
    supported_architectures: List[CpuArchitecture]
    engine_state: str = "HEADLESS_DYNAMIC_FUZZING_ONLINE"
