"""
Multi-Tenant Architecture & Virtual SOC Isolation Service.
Provides strict partition boundaries, quota gating, and tenant-scoped role assignment.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from cybershield.multitenant.schemas import (
    TenantCreateRequest,
    TenantProfile,
    TenantQuota,
    TenantRole,
    TenantTier,
    TenantUsageMetrics,
    TenantUserMapping,
)


class TenantManager:
    """
    Central orchestration service for multi-tenant isolation and vSOC capacity.
    """

    def __init__(self):
        self._tenants: Dict[str, TenantProfile] = {}
        self._user_mappings: Dict[str, TenantUserMapping] = {}
        self._seed_default_tenants()

    def _seed_default_tenants(self):
        """Seed primary enterprise organization tenants."""
        hq = TenantProfile(
            tenant_id="TENANT-CORP-HQ",
            name="Global Enterprise Headquarters",
            slug="corp-hq",
            tier=TenantTier.ENTERPRISE,
            quota=TenantQuota(max_devices=2500, max_eps=5000, data_retention_days=365, storage_gb=1000),
            current_device_count=420,
            current_eps=680,
            contact_email="sec-ops@enterprise.global"
        )
        fin = TenantProfile(
            tenant_id="TENANT-FIN-DIV",
            name="Financial Services Division",
            slug="fin-div",
            tier=TenantTier.PROFESSIONAL,
            quota=TenantQuota(max_devices=800, max_eps=1500, data_retention_days=180, storage_gb=400),
            current_device_count=195,
            current_eps=240,
            contact_email="fin-sec@enterprise.global"
        )
        health = TenantProfile(
            tenant_id="TENANT-HEALTH-SUB",
            name="Healthcare & Clinical Subsidiary",
            slug="health-sub",
            tier=TenantTier.ENTERPRISE,
            quota=TenantQuota(max_devices=1500, max_eps=3000, data_retention_days=365, storage_gb=800),
            current_device_count=610,
            current_eps=890,
            contact_email="hipaa-sec@health-sub.org"
        )

        for t in [hq, fin, health]:
            self._tenants[t.tenant_id] = t

        # Seed sample user mapping
        mapping = TenantUserMapping(
            mapping_id="MAP-001",
            user_id="sec-admin",
            tenant_id="TENANT-CORP-HQ",
            role=TenantRole.TENANT_ADMIN
        )
        self._user_mappings[mapping.mapping_id] = mapping

    def create_tenant(self, req: TenantCreateRequest) -> TenantProfile:
        """Provision a new isolated tenant boundary."""
        tenant_id = f"TENANT-{req.slug.upper().replace('-', '_')}"
        quota = req.custom_quota or TenantQuota()

        tenant = TenantProfile(
            tenant_id=tenant_id,
            name=req.name,
            slug=req.slug,
            tier=req.tier,
            quota=quota,
            contact_email=req.contact_email,
        )
        self._tenants[tenant_id] = tenant
        return tenant

    def get_tenant(self, tenant_id: str) -> Optional[TenantProfile]:
        return self._tenants.get(tenant_id)

    def list_tenants(self) -> List[TenantProfile]:
        return list(self._tenants.values())

    def assign_user_to_tenant(
        self, user_id: str, tenant_id: str, role: TenantRole
    ) -> TenantUserMapping:
        """Grant a user scoped access within a specific tenant."""
        if tenant_id not in self._tenants:
            raise ValueError(f"Tenant '{tenant_id}' does not exist")

        mapping_id = f"MAP-{uuid.uuid4().hex[:8]}"
        mapping = TenantUserMapping(
            mapping_id=mapping_id,
            user_id=user_id,
            tenant_id=tenant_id,
            role=role,
        )
        self._user_mappings[mapping_id] = mapping
        return mapping

    def get_tenant_users(self, tenant_id: str) -> List[TenantUserMapping]:
        """List all users mapped to a tenant organization."""
        return [m for m in self._user_mappings.values() if m.tenant_id == tenant_id]

    def verify_tenant_access(self, user_id: str, tenant_id: str) -> bool:
        """Validates that a user holds legitimate access within the target tenant boundary."""
        # Super-admins bypass via system role or specific mapping
        if user_id in ("sec-admin", "admin"):
            return True
        for m in self._user_mappings.values():
            if m.user_id == user_id and m.tenant_id == tenant_id:
                return True
        return False

    def check_eps_quota(self, tenant_id: str, incoming_eps: int) -> bool:
        """Verify if additional incoming event throughput violates tenant EPS cap."""
        tenant = self.get_tenant(tenant_id)
        if not tenant or not tenant.is_active:
            return False
        return (tenant.current_eps + incoming_eps) <= tenant.quota.max_eps

    def check_device_quota(self, tenant_id: str) -> bool:
        """Verify if adding a new device is within the licensed quota."""
        tenant = self.get_tenant(tenant_id)
        if not tenant or not tenant.is_active:
            return False
        return tenant.current_device_count < tenant.quota.max_devices

    def get_tenant_usage(self, tenant_id: str) -> Optional[TenantUsageMetrics]:
        """Calculates resource consumption percentages against allocated limits."""
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            return None

        dev_pct = round((tenant.current_device_count / max(1, tenant.quota.max_devices)) * 100.0, 1)
        eps_pct = round((tenant.current_eps / max(1, tenant.quota.max_eps)) * 100.0, 1)
        is_over = dev_pct >= 100.0 or eps_pct >= 100.0

        return TenantUsageMetrics(
            tenant_id=tenant.tenant_id,
            name=tenant.name,
            device_count=tenant.current_device_count,
            max_devices=tenant.quota.max_devices,
            device_utilization_pct=dev_pct,
            current_eps=tenant.current_eps,
            max_eps=tenant.quota.max_eps,
            eps_utilization_pct=eps_pct,
            is_over_quota=is_over,
        )

    def get_overview_metrics(self) -> Dict[str, Any]:
        """Consolidated multi-tenant ecosystem statistics."""
        total = len(self._tenants)
        active = sum(1 for t in self._tenants.values() if t.is_active)
        total_devices = sum(t.current_device_count for t in self._tenants.values())
        total_eps = sum(t.current_eps for t in self._tenants.values())

        tier_counts: Dict[str, int] = {}
        for t in self._tenants.values():
            tier_name = t.tier.value
            tier_counts[tier_name] = tier_counts.get(tier_name, 0) + 1

        return {
            "total_tenants": total,
            "active_tenants": active,
            "total_devices_across_tenants": total_devices,
            "total_eps_ingestion_rate": total_eps,
            "tier_distribution": tier_counts,
            "total_user_assignments": len(self._user_mappings),
        }
