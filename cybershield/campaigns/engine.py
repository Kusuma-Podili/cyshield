"""
Adversary Campaign Correlation & Attribution Engine.
Applies the Diamond Model of Intrusion Analysis to cluster disparate alerts
into cohesive threat campaigns and attributes them to known adversary groups.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from cybershield.campaigns.schemas import (
    AttributionConfidence,
    CampaignGraphEdge,
    CampaignGraphNode,
    CampaignStatus,
    DiamondVertexType,
    ThreatActorProfile,
    ThreatCampaign,
)


class CampaignGraphEngine:
    """
    Intrusion correlation engine tracking threat campaigns and attributing tactics.
    """

    def __init__(self):
        self._actors: Dict[str, ThreatActorProfile] = {}
        self._campaigns: Dict[str, ThreatCampaign] = {}
        self._init_actor_catalog()
        self._seed_active_campaigns()

    def _init_actor_catalog(self):
        """Seed high-fidelity threat actor profiles based on MITRE ATT&CK intelligence."""
        catalog = [
            ThreatActorProfile(
                actor_id="ACTOR-APT29",
                name="APT29",
                aliases=["Cozy Bear", "Nobelium", "Midnight Blizzard", "The Dukes"],
                country_of_origin="Russia",
                motivations=["ESPIONAGE", "STRATEGIC_INTELLIGENCE"],
                target_sectors=["Government", "Defense", "Think Tanks", "Technology", "Cloud Service Providers"],
                signature_ttps=["T1195", "T1078", "T1087", "T1071.001", "T1558", "T1098"],
                known_malware_families=["SUNBURST", "TEARDROP", "GoldFinder", "WellMess"],
                observed_infrastructure_patterns=["*.azureedge.net", "*.trafficmanager.net", "compromised_m365_tenants"]
            ),
            ThreatActorProfile(
                actor_id="ACTOR-APT28",
                name="APT28",
                aliases=["Fancy Bear", "Strontium", "Sednit", "Sofacy"],
                country_of_origin="Russia",
                motivations=["ESPIONAGE", "DISRUPTION"],
                target_sectors=["Defense", "Aerospace", "Government", "Energy"],
                signature_ttps=["T1566", "T1110", "T1059.001", "T1003", "T1021.002"],
                known_malware_families=["X-Agent", "Zebrocy", "Sofacy", "Drovorub"],
                observed_infrastructure_patterns=["dynamic_dns", "bulletproof_hosting_nl"]
            ),
            ThreatActorProfile(
                actor_id="ACTOR-LAZARUS",
                name="Lazarus Group",
                aliases=["HIDDEN COBRA", "Guardians of Peace", "ZINC"],
                country_of_origin="North Korea",
                motivations=["FINANCIAL", "ESPIONAGE", "CRYPTOCURRENCY_THEFT"],
                target_sectors=["Cryptocurrency Exchanges", "Financial Services", "Defense", "Media"],
                signature_ttps=["T1059.003", "T1055", "T1572", "T1071.004", "T1204.002"],
                known_malware_families=["Bankshot", "Fallchill", "AppleJeus", "Manuscrypt"],
                observed_infrastructure_patterns=["fast_flux_dns", "compromised_apac_servers"]
            ),
            ThreatActorProfile(
                actor_id="ACTOR-FIN7",
                name="FIN7",
                aliases=["Carbanak", "Navigator Group"],
                country_of_origin="Eastern Europe",
                motivations=["FINANCIAL_CRIME", "EXTORTION"],
                target_sectors=["Retail", "Hospitality", "Restaurant Chains"],
                signature_ttps=["T1059.005", "T1027", "T1041", "T1053.005", "T1005"],
                known_malware_families=["Carbanak", "Griffon", "Pillowmint", "Tirion"],
                observed_infrastructure_patterns=["legitimate_cdn_spoofs", "stolen_ssl_certs"]
            ),
            ThreatActorProfile(
                actor_id="ACTOR-SANDWORM",
                name="Sandworm Team",
                aliases=["BlackEnergy", "Voodoo Bear", "TeleBots", "Seashell Blizzard"],
                country_of_origin="Russia",
                motivations=["SABOTAGE", "CRITICAL_INFRASTRUCTURE_DISRUPTION"],
                target_sectors=["Energy Grids", "Utilities", "Transportation", "Telecommunications"],
                signature_ttps=["T1485", "T1499", "T1584", "T0807", "T0855"],
                known_malware_families=["BlackEnergy", "Industroyer", "NotPetya", "CaddyWiper"],
                observed_infrastructure_patterns=["tor_exit_relays", "compromised_edge_routers"]
            ),
            ThreatActorProfile(
                actor_id="ACTOR-VOLT-TYPHOON",
                name="Volt Typhoon",
                aliases=["Bronze Silhouette", "Vanguard Panda"],
                country_of_origin="China",
                motivations=["PRE_POSITIONING", "ESPIONAGE", "CRITICAL_INFRASTRUCTURE"],
                target_sectors=["Water", "Power", "Transportation", "Communications", "Maritime Ports"],
                signature_ttps=["T1078", "T1059", "T1046", "T1090.002", "T1070"],
                known_malware_families=["Fast Reverse Proxy (FRP)", "Living-off-the-Land (LOTL)"],
                observed_infrastructure_patterns=["compromised_soho_routers", "cisco_rv_routers", "netgear_prosafe"]
            ),
        ]
        for actor in catalog:
            self._actors[actor.actor_id] = actor

    def _seed_active_campaigns(self):
        """Pre-populate sample active campaigns for immediate SOC tracking."""
        camp_id = "CAMP-2026-081"
        nodes = [
            CampaignGraphNode(
                node_id="NODE-ADV-1",
                vertex_type=DiamondVertexType.ADVERSARY,
                label="APT29 (Cozy Bear)",
                attributes={"confidence": "HIGH", "origin": "Russia"}
            ),
            CampaignGraphNode(
                node_id="NODE-INF-1",
                vertex_type=DiamondVertexType.INFRASTRUCTURE,
                label="198.51.100.44 (C2 Listener)",
                attributes={"ip": "198.51.100.44", "asn": "AS9009", "country": "NL"}
            ),
            CampaignGraphNode(
                node_id="NODE-CAP-1",
                vertex_type=DiamondVertexType.CAPABILITY,
                label="SUNBURST Memory Injected Payload",
                attributes={"technique": "T1055", "sha256": "3253f2e1753663e128b382042e5224987f2e08917755a44dc81f78492022849b"}
            ),
            CampaignGraphNode(
                node_id="NODE-VIC-1",
                vertex_type=DiamondVertexType.VICTIM,
                label="SRV-DC-01 (Domain Controller)",
                attributes={"hostname": "SRV-DC-01", "ip": "10.0.1.10", "role": "Domain Controller"}
            ),
        ]
        edges = [
            CampaignGraphEdge(
                source_id="NODE-ADV-1",
                target_id="NODE-INF-1",
                relation="UTILIZES_INFRASTRUCTURE",
                confidence=0.92,
                evidence="C2 IP associated with known APT29 dynamic DNS pool"
            ),
            CampaignGraphEdge(
                source_id="NODE-ADV-1",
                target_id="NODE-CAP-1",
                relation="DEPLOYS_CAPABILITY",
                confidence=0.88,
                evidence="Payload matching WellMess/SUNBURST in-memory profile"
            ),
            CampaignGraphEdge(
                source_id="NODE-CAP-1",
                target_id="NODE-VIC-1",
                relation="EXECUTES_AGAINST_VICTIM",
                confidence=0.95,
                evidence="Process injection alert ALT-001 observed on SRV-DC-01"
            ),
            CampaignGraphEdge(
                source_id="NODE-VIC-1",
                target_id="NODE-INF-1",
                relation="BEACONS_TO_INFRASTRUCTURE",
                confidence=0.91,
                evidence="Periodic outbound TLS heartbeat to 198.51.100.44:443"
            ),
        ]
        campaign = ThreatCampaign(
            campaign_id=camp_id,
            name="Operation Twilight Beacon",
            description="Active strategic espionage intrusion campaign targeting directory infrastructure and cloud identity connectors.",
            status=CampaignStatus.ACTIVE,
            attributed_actor="APT29",
            attribution_confidence=AttributionConfidence.HIGH,
            attribution_score=84.5,
            kill_chain_phases=["Command and Control", "Credential Access", "Lateral Movement"],
            nodes=nodes,
            edges=edges,
            associated_alert_ids=["ALT-001", "ALT-004", "ALT-007"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        self._campaigns[camp_id] = campaign

    def list_actors(self) -> List[ThreatActorProfile]:
        """Returns all tracked threat actor profiles."""
        return list(self._actors.values())

    def get_actor(self, actor_id: str) -> Optional[ThreatActorProfile]:
        """Returns specific threat actor profile by identifier."""
        return self._actors.get(actor_id)

    def list_campaigns(self) -> List[ThreatCampaign]:
        """Returns all identified adversary campaigns."""
        return list(self._campaigns.values())

    def get_campaign(self, campaign_id: str) -> Optional[ThreatCampaign]:
        """Fetch threat campaign by ID."""
        return self._campaigns.get(campaign_id)

    def compute_attribution(
        self, observed_ttps: Set[str], observed_tools: Set[str]
    ) -> Tuple[Optional[ThreatActorProfile], float, AttributionConfidence]:
        """
        Calculates attribution probability against known threat actors
        using weighted Jaccard index over observed techniques and toolsets.
        """
        if not observed_ttps and not observed_tools:
            return None, 0.0, AttributionConfidence.LOW

        best_actor: Optional[ThreatActorProfile] = None
        best_score = 0.0

        for actor in self._actors.values():
            actor_ttps = set(actor.signature_ttps)
            actor_tools = {t.lower() for t in actor.known_malware_families}

            # Calculate TTP overlap
            ttp_overlap = len(observed_ttps.intersection(actor_ttps))
            ttp_union = len(observed_ttps.union(actor_ttps)) if (observed_ttps or actor_ttps) else 1
            ttp_jaccard = ttp_overlap / ttp_union if ttp_union > 0 else 0.0

            # Calculate Tool overlap
            obs_tools_lower = {t.lower() for t in observed_tools}
            tool_overlap = len(obs_tools_lower.intersection(actor_tools))
            tool_union = len(obs_tools_lower.union(actor_tools)) if (obs_tools_lower or actor_tools) else 1
            tool_jaccard = tool_overlap / tool_union if tool_union > 0 else 0.0

            # Combined weighted score (60% TTPs, 40% known malware/tools)
            combined_score = (ttp_jaccard * 60.0) + (tool_jaccard * 40.0)

            # Bonus for exact signature technique hits
            if ttp_overlap >= 3:
                combined_score += 15.0
            if tool_overlap >= 1:
                combined_score += 20.0

            score_clamped = min(100.0, round(combined_score, 1))

            if score_clamped > best_score:
                best_score = score_clamped
                best_actor = actor

        confidence = AttributionConfidence.LOW
        if best_score >= 80.0:
            confidence = AttributionConfidence.CONFIRMED
        elif best_score >= 60.0:
            confidence = AttributionConfidence.HIGH
        elif best_score >= 35.0:
            confidence = AttributionConfidence.MEDIUM

        return best_actor, best_score, confidence

    def correlate_alerts(
        self,
        alert_data: List[Dict[str, Any]],
        similarity_threshold: float = 0.35,
    ) -> Optional[ThreatCampaign]:
        """
        Synthesizes alerts into a Diamond Model threat campaign.
        Builds graph vertices for Adversary, Capabilities, Infrastructure, and Victims.
        """
        if not alert_data:
            return None

        alert_ids = [str(a.get("id", f"ALT-{uuid.uuid4().hex[:4]}")) for a in alert_data]
        observed_ttps: Set[str] = set()
        observed_tools: Set[str] = set()
        observed_ips: Set[str] = set()
        observed_victims: Set[str] = set()

        for a in alert_data:
            if "mitre_technique" in a and a["mitre_technique"]:
                observed_ttps.add(a["mitre_technique"])
            if "malware_family" in a and a["malware_family"]:
                observed_tools.add(a["malware_family"])
            if "source_ip" in a and a["source_ip"]:
                observed_ips.add(a["source_ip"])
            if "destination_ip" in a and a["destination_ip"]:
                observed_victims.add(a["destination_ip"])
            if "target_host" in a and a["target_host"]:
                observed_victims.add(a["target_host"])

        actor, score, confidence = self.compute_attribution(observed_ttps, observed_tools)

        camp_id = f"CAMP-{datetime.utcnow().year}-{str(uuid.uuid4())[:6].upper()}"
        actor_name = actor.name if actor else "Unattributed Cluster (UNC-Tracked)"

        # Construct Diamond Graph Nodes
        nodes: List[CampaignGraphNode] = []
        adv_node_id = f"ADV-{uuid.uuid4().hex[:6]}"
        nodes.append(CampaignGraphNode(
            node_id=adv_node_id,
            vertex_type=DiamondVertexType.ADVERSARY,
            label=f"Threat Actor: {actor_name}",
            attributes={"attribution_score": score, "confidence": confidence.value}
        ))

        # Infrastructure Nodes
        inf_node_ids = []
        for ip in observed_ips:
            node_id = f"INF-{uuid.uuid4().hex[:6]}"
            nodes.append(CampaignGraphNode(
                node_id=node_id,
                vertex_type=DiamondVertexType.INFRASTRUCTURE,
                label=f"C2 Node: {ip}",
                attributes={"ip": ip}
            ))
            inf_node_ids.append(node_id)

        # Capability Nodes
        cap_node_ids = []
        for ttp in observed_ttps:
            node_id = f"CAP-{uuid.uuid4().hex[:6]}"
            nodes.append(CampaignGraphNode(
                node_id=node_id,
                vertex_type=DiamondVertexType.CAPABILITY,
                label=f"MITRE TTP: {ttp}",
                attributes={"technique_id": ttp}
            ))
            cap_node_ids.append(node_id)

        for tool in observed_tools:
            node_id = f"CAP-{uuid.uuid4().hex[:6]}"
            nodes.append(CampaignGraphNode(
                node_id=node_id,
                vertex_type=DiamondVertexType.CAPABILITY,
                label=f"Payload: {tool}",
                attributes={"tool_name": tool}
            ))
            cap_node_ids.append(node_id)

        # Victim Nodes
        vic_node_ids = []
        for vic in observed_victims:
            node_id = f"VIC-{uuid.uuid4().hex[:6]}"
            nodes.append(CampaignGraphNode(
                node_id=node_id,
                vertex_type=DiamondVertexType.VICTIM,
                label=f"Asset: {vic}",
                attributes={"target": vic}
            ))
            vic_node_ids.append(node_id)

        # Edges
        edges: List[CampaignGraphEdge] = []
        for inf_id in inf_node_ids:
            edges.append(CampaignGraphEdge(
                source_id=adv_node_id,
                target_id=inf_id,
                relation="UTILIZES_INFRASTRUCTURE",
                confidence=0.85,
                evidence="C2 traffic correlation"
            ))
        for cap_id in cap_node_ids:
            edges.append(CampaignGraphEdge(
                source_id=adv_node_id,
                target_id=cap_id,
                relation="DEPLOYS_CAPABILITY",
                confidence=0.80,
                evidence="TTP/malware signature attribution"
            ))
        for cap_id in cap_node_ids:
            for vic_id in vic_node_ids:
                edges.append(CampaignGraphEdge(
                    source_id=cap_id,
                    target_id=vic_id,
                    relation="TARGETS_VICTIM",
                    confidence=0.90,
                    evidence="Host execution artifact"
                ))

        campaign = ThreatCampaign(
            campaign_id=camp_id,
            name=f"Campaign {actor_name} Incident Cluster",
            description=f"Automated Diamond Model intrusion cluster correlating {len(alert_ids)} alerts across {len(observed_victims)} targets.",
            status=CampaignStatus.ACTIVE,
            attributed_actor=actor.name if actor else None,
            attribution_confidence=confidence,
            attribution_score=score,
            kill_chain_phases=list(observed_ttps),
            nodes=nodes,
            edges=edges,
            associated_alert_ids=alert_ids,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )

        self._campaigns[camp_id] = campaign
        return campaign

    def get_overview_metrics(self) -> Dict[str, Any]:
        """Returns executive metrics on active campaigns and adversary distribution."""
        total_campaigns = len(self._campaigns)
        active_count = sum(1 for c in self._campaigns.values() if c.status == CampaignStatus.ACTIVE)
        actor_distribution: Dict[str, int] = {}
        confidence_distribution: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CONFIRMED": 0}

        for c in self._campaigns.values():
            actor = c.attributed_actor or "Unattributed"
            actor_distribution[actor] = actor_distribution.get(actor, 0) + 1
            conf = c.attribution_confidence.value
            confidence_distribution[conf] = confidence_distribution.get(conf, 0) + 1

        return {
            "total_campaigns": total_campaigns,
            "active_campaigns": active_count,
            "tracked_actors": len(self._actors),
            "actor_distribution": actor_distribution,
            "confidence_distribution": confidence_distribution,
        }
