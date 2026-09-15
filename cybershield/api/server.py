"""Master FastAPI Application & SOC Server for CyberShield Enterprise.

Binds all REST routers, provides high-frequency WebSockets for analyst consoles,
hosts the dark cybersecurity SOC dashboard, and tracks engine diagnostics.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from cybershield.version import __version__, __build__
from cybershield.config import settings
from cybershield.core.bus import event_bus
from cybershield.api.websocket_hub import ws_hub
from cybershield.api.routes_alerts import router as alerts_router
from cybershield.api.routes_incidents import router as incidents_router
from cybershield.api.routes_telemetry import router as telemetry_router
from cybershield.api.routes_soar import router as soar_router
from cybershield.api.routes_intel import router as intel_router
from cybershield.api.routes_simulation import router as simulation_router
from cybershield.auth.routes import router as auth_router
from cybershield.users.routes import router as users_router
from cybershield.audit.routes import router as audit_router
from cybershield.network.routes import router as network_router
from cybershield.alerts.routes import router as enterprise_alerts_router
from cybershield.events.routes import router as events_router
from cybershield.incidents.routes import router as enterprise_incidents_router
from cybershield.detection.routes import router as detection_router
from cybershield.vulnerabilities.routes import router as vulnerabilities_router
from cybershield.intel.routes import router as enterprise_intel_router
from cybershield.phishing.routes import router as phishing_router
from cybershield.malware.routes import router as malware_router
from cybershield.ml.routes import router as ml_router
from cybershield.ebpf.routes import router as ebpf_router
from cybershield.ml.gnn.routes import router as gnn_router
from cybershield.analytics.routes import router as analytics_router
from cybershield.tasks.routes import router as tasks_router
from cybershield.tasks.manager import task_manager
from cybershield.compliance.routes import router as compliance_router
from cybershield.compliance.engine import ComplianceEngine
from cybershield.audit.vault import AuditVault
from cybershield.reports.routes import router as reports_router
from cybershield.settings.routes import router as settings_router
from cybershield.settings.manager import SettingsManager
from cybershield.health.routes import router as health_router
from cybershield.protocols.routes import router as protocols_router
from cybershield.dfir.routes import router as dfir_router
from cybershield.deception.routes import router as deception_router
from cybershield.cloud.routes import router as cloud_router
from cybershield.mitre.routes import router as mitre_router
from cybershield.ml.advanced.routes import router as advanced_ml_router
from cybershield.edr.routes import router as edr_router
from cybershield.hunting.routes import hunting_router
from cybershield.zerotrust.routes import zerotrust_router
from cybershield.correlation.routes import correlation_router
from cybershield.bas.routes import bas_router
from cybershield.asm.routes import asm_router
from cybershield.lakehouse.routes import lakehouse_router
from cybershield.itdr.routes import itdr_router
from cybershield.taxii.routes import taxii_router
from cybershield.soar.compiler.routes import soar_compiler_router
from cybershield.dlp.routes import dlp_router
from cybershield.c2.routes import c2_router
from cybershield.kms.routes import kms_router
from cybershield.ics.routes import ics_router
from cybershield.microseg.routes import microseg_router
from cybershield.firmware.routes import firmware_router
from cybershield.campaigns.routes import campaigns_router
from cybershield.supplychain.routes import supplychain_router
from cybershield.dnsfw.routes import dnsfw_router
from cybershield.iocdecay.routes import iocdecay_router
from cybershield.multitenant.routes import multitenant_router
from cybershield.ransomware.routes import ransomware_router
from cybershield.bgp.routes import bgp_router
from cybershield.apisec.routes import apisec_router
from cybershield.postquantum.routes import postquantum_router
from cybershield.rca.routes import rca_router
from cybershield.chaos.routes import chaos_router
from cybershield.waf.routes import waf_router
from cybershield.iga.routes import router as iga_router
from cybershield.cart.routes import router as cart_router
from cybershield.honey.routes import router as honey_router
from cybershield.timeline.routes import router as timeline_router
from cybershield.soar.hotreload.routes import router as soar_hotreload_router
from cybershield.vep.routes import router as vep_router
from cybershield.copilot.routes import router as copilot_router
from cybershield.wireless.routes import router as wireless_router
from cybershield.secrets.routes import router as secrets_router
from cybershield.privacy.routes import router as privacy_router
from cybershield.shield.routes import router as shield_router
from cybershield.activedirectory.routes import router as activedirectory_router
from cybershield.surface.routes import router as surface_router
from cybershield.vssvault.routes import router as vssvault_router
from cybershield.biometrics.routes import router as biometrics_router
from cybershield.llmguard.routes import router as llmguard_router
from cybershield.darkweb.routes import router as darkweb_router
from cybershield.iotemu.routes import router as iotemu_router
from cybershield.adversary.routes import router as adversary_router
from cybershield.overlay.routes import router as overlay_router
from cybershield.cicd.routes import router as cicd_router
from cybershield.sspm.routes import router as sspm_router
from cybershield.scadadpi.routes import router as scadadpi_router
from cybershield.threathunt.routes import router as threathunt_router
from cybershield.columnar.routes import router as columnar_router
from cybershield.database.session import init_db, async_session_factory
from cybershield.network.subnet_service import SubnetService
from cybershield.network.device_service import DeviceService
from cybershield.alerts.service import AlertService
from cybershield.events.service import EventsService
from cybershield.incidents.service import incident_service
from cybershield.detection.service import detection_rule_service
from cybershield.vulnerabilities.service import vulnerability_service
from cybershield.intel.feed_service import threat_intel_service
from cybershield.ml.registry.service import ml_service
from cybershield.analytics.service import analytics_service
from cybershield.ingestion.collector import collector
from cybershield.incidents.case_manager import case_manager

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("cybershield.server")

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "web" / "static"
TEMPLATES_DIR = BASE_DIR / "web" / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager initializing background services, DB schema, and bus workers."""
    logger.info("Starting CyberShield Enterprise v%s...", __version__)
    await init_db()
    
    # Auto-seed enterprise subnets, devices, alerts, telemetry events, detection rules, and incidents
    try:
        async with async_session_factory() as session:
            sub_svc = SubnetService(session)
            await sub_svc.seed_enterprise_subnets()
            dev_svc = DeviceService(session)
            await dev_svc.seed_enterprise_devices()
            alt_svc = AlertService(session)
            await alt_svc.seed_default_alerts()
            ev_svc = EventsService(session)
            await ev_svc.seed_default_events()
            await detection_rule_service.seed_rules_if_empty(session)
            await incident_service.seed_sample_incidents_if_empty(session)
            await vulnerability_service.seed_default_vulnerabilities(session)
            await threat_intel_service.seed_threat_intelligence(session)
            await ml_service.seed_default_models(session)
            await analytics_service.seed_default_pipelines(session)
            await ComplianceEngine.seed_frameworks_if_empty(session)
            await AuditVault.initialize_genesis_block(session)
            await SettingsManager.seed_defaults_if_empty(session)
    except Exception as e:
        logger.warning("Startup seeding warning: %s", e)

    await event_bus.start()
    await task_manager.start_pool()
    ws_hub.setup_event_bus_listener()
    yield
    logger.info("Shutting down CyberShield Enterprise services...")
    await task_manager.stop_pool()
    await event_bus.stop()


app = FastAPI(
    title="CyberShield Enterprise",
    description="AI-Powered Cybersecurity and Autonomous Threat Detection Platform",
    version=__version__,
    lifespan=lifespan,
)

# CORS middleware for open enterprise integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static asset directory
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# Register API Routers
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(audit_router)
app.include_router(network_router)
app.include_router(enterprise_alerts_router)
app.include_router(events_router)
app.include_router(enterprise_incidents_router)
app.include_router(detection_router)
app.include_router(vulnerabilities_router)
app.include_router(enterprise_intel_router)
app.include_router(phishing_router)
app.include_router(malware_router)
app.include_router(ml_router)
app.include_router(analytics_router)
app.include_router(tasks_router)
app.include_router(compliance_router)
app.include_router(reports_router)
app.include_router(settings_router)
app.include_router(health_router)
app.include_router(protocols_router)
app.include_router(dfir_router)
app.include_router(deception_router)
app.include_router(cloud_router)
app.include_router(mitre_router)
app.include_router(advanced_ml_router)
app.include_router(edr_router)
app.include_router(hunting_router)
app.include_router(zerotrust_router)
app.include_router(correlation_router)
app.include_router(bas_router)
app.include_router(asm_router)
app.include_router(lakehouse_router)
app.include_router(itdr_router)
app.include_router(taxii_router)
app.include_router(soar_compiler_router)
app.include_router(dlp_router)
app.include_router(c2_router)
app.include_router(kms_router)
app.include_router(ics_router)
app.include_router(microseg_router)
app.include_router(firmware_router)
app.include_router(campaigns_router)
app.include_router(supplychain_router)
app.include_router(dnsfw_router)
app.include_router(iocdecay_router)
app.include_router(multitenant_router)
app.include_router(ransomware_router)
app.include_router(bgp_router)
app.include_router(apisec_router)
app.include_router(postquantum_router)
app.include_router(rca_router)
app.include_router(chaos_router)
app.include_router(waf_router)
app.include_router(gnn_router)
app.include_router(ebpf_router)
app.include_router(iga_router)
app.include_router(cart_router)
app.include_router(honey_router)
app.include_router(timeline_router)
app.include_router(soar_hotreload_router)
app.include_router(vep_router)
app.include_router(copilot_router)
app.include_router(wireless_router)
app.include_router(secrets_router)
app.include_router(privacy_router)
app.include_router(shield_router)
app.include_router(activedirectory_router)
app.include_router(surface_router)
app.include_router(vssvault_router)
app.include_router(biometrics_router)
app.include_router(llmguard_router)
app.include_router(darkweb_router)
app.include_router(iotemu_router)
app.include_router(adversary_router)
app.include_router(overlay_router)
app.include_router(cicd_router)
app.include_router(sspm_router)
app.include_router(scadadpi_router)
app.include_router(threathunt_router)
app.include_router(columnar_router)
app.include_router(alerts_router)
app.include_router(incidents_router)
app.include_router(telemetry_router)
app.include_router(soar_router)
app.include_router(intel_router)
app.include_router(simulation_router)


@app.websocket("/ws/soc")
async def websocket_soc_endpoint(websocket: WebSocket):
    """Duplex real-time WebSocket channel for SOC command center."""
    await ws_hub.connect(websocket)
    try:
        while True:
            # Keep connection open and accept incoming ping/heartbeats
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)
    except Exception:
        ws_hub.disconnect(websocket)


@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serve the primary single-pane-of-glass SOC Glass Cockpit."""
    index_file = TEMPLATES_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h2>CyberShield Enterprise Web UI initializing...</h2>")


@app.get("/api/v1/system/metrics")
async def get_system_metrics():
    """Consolidated operational health and threat telemetry counters."""
    bus_m = event_bus.get_metrics()
    ingest_m = collector.get_metrics()
    incident_m = case_manager.get_metrics()

    return {
        "status": "OPERATIONAL_OPTIMAL",
        "version": __version__,
        "build": __build__,
        "connected_soc_consoles": ws_hub.client_count,
        "event_bus": bus_m,
        "ingestion": ingest_m,
        "incidents": incident_m,
        "engines_online": [
            "IsolationForest_Anomaly_Engine",
            "UEBA_Behavioral_Profiler",
            "NLP_Payload_Classifier",
            "Static_Entropy_Binary_Scanner",
            "Sigma_Condition_Matcher",
            "YARA_Pattern_Scanner",
            "MITRE_Correlation_Graph",
            "SOAR_Playbook_Orchestrator",
            "GNN_GraphSAGE_Threat_Classifier",
            "eBPF_Kernel_Telemetry_Interceptor",
            "Identity_Governance_Administration_Engine",
            "CART_Exploit_Path_Planner",
            "Threat_Deception_Service_Emulators",
            "Forensics_Timeline_Reconstructor",
            "SOAR_Dynamic_HotReload_Sandbox",
            "EPSS_Vulnerability_Exploit_Predictor",
            "Autonomous_AI_SOC_Analyst",
            "Wireless_RF_Cyber_Defense_Engine",
            "Secret_Sprawl_Entropy_Scanner",
            "Differential_Privacy_Federated_Telemetry",
            "ZeroDay_Exploit_Memory_Shield",
            "Active_Directory_Kerberos_Sentinel",
            "Threat_Surface_Shadow_Cloud_Reconciler",
            "Cryptographic_Ransomware_Rollback_Vault",
            "Behavioral_Biometrics_Keystroke_Sentinel",
            "LLM_Guardrail_Prompt_Injection_Sentinel",
            "DarkWeb_Leaked_Credential_Sentinel",
            "Firmware_Emulation_IoT_Dynamic_Sandbox",
            "Adversary_Emulation_MITRE_Planner",
            "ZeroTrust_Mesh_MicroTunnel_Overlay",
            "CICD_SupplyChain_Poisoning_Sentinel",
            "SaaS_Security_Posture_Management_SSPM",
            "SCADA_Modbus_DNP3_DeepPacketInspector",
            "ThreatHunt_Hypothesis_Matrix_Transpiler",
            "Security_Data_Lake_Columnar_Archival",
        ]
    }
