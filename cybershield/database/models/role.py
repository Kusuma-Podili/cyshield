"""Role-Based Access Control (RBAC) Definitions & Permissions Matrix.

Provides explicit granular permission boundaries across all 6 enterprise roles.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Set, List


class UserRole(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SECURITY_ANALYST = "SECURITY_ANALYST"
    NETWORK_ANALYST = "NETWORK_ANALYST"
    INCIDENT_RESPONDER = "INCIDENT_RESPONDER"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    # User and Identity Management
    USERS_VIEW = "users:view"
    USERS_CREATE = "users:create"
    USERS_EDIT = "users:edit"
    USERS_DELETE = "users:delete"
    ROLES_MANAGE = "roles:manage"

    # Security Alerts & Triage
    ALERTS_VIEW = "alerts:view"
    ALERTS_TRIAGE = "alerts:triage"
    ALERTS_DELETE = "alerts:delete"

    # Incidents & Forensic Custody
    INCIDENTS_VIEW = "incidents:view"
    INCIDENTS_CREATE = "incidents:create"
    INCIDENTS_UPDATE = "incidents:update"
    EVIDENCE_SEAL = "evidence:seal"
    EVIDENCE_EXPORT = "evidence:export"

    # SOAR Containment Playbooks
    SOAR_VIEW = "soar:view"
    SOAR_EXECUTE = "soar:execute"
    SOAR_CONFIG = "soar:config"

    # Threat Intel, Rules & MITRE
    INTEL_VIEW = "intel:view"
    INTEL_EDIT = "intel:edit"
    RULES_VIEW = "rules:view"
    RULES_MANAGE = "rules:manage"

    # Vulnerabilities & Threat Surface
    VULN_VIEW = "vuln:view"
    VULN_SCAN = "vuln:scan"
    VULN_MANAGE = "vuln:manage"

    # Deep Inspection & Analysis
    MALWARE_ANALYZE = "malware:analyze"
    PHISHING_ANALYZE = "phishing:analyze"

    # Network & Devices
    NETWORK_VIEW = "network:view"
    NETWORK_CONTROL = "network:control"

    # ML & Simulation
    ML_VIEW = "ml:view"
    ML_PREDICT = "ml:predict"
    ML_TRAIN = "ml:train"
    SIMULATION_RUN = "simulation:run"

    # Data Pipelines & Analytics
    PIPELINES_VIEW = "pipelines:view"
    PIPELINES_RUN = "pipelines:run"
    ANALYTICS_VIEW = "analytics:view"

    # Distributed Tasks & Background Workers
    TASKS_VIEW = "tasks:view"
    TASKS_SUBMIT = "tasks:submit"
    TASKS_CANCEL = "tasks:cancel"

    # Regulatory Compliance & Standards
    COMPLIANCE_VIEW = "compliance:view"
    COMPLIANCE_ASSESS = "compliance:assess"

    # Cryptographic Audit Vault (WORM Ledger)
    VAULT_VIEW = "vault:view"
    VAULT_VERIFY = "vault:verify"

    # Automated Reports & Forensics Dossiers
    REPORTS_VIEW = "reports:view"
    REPORTS_GENERATE = "reports:generate"
    REPORTS_DOWNLOAD = "reports:download"

    # Audit & Compliance Logs
    AUDIT_VIEW = "audit:view"

    # Platform Settings & Runtime Configuration
    SETTINGS_VIEW = "settings:view"
    SETTINGS_EDIT = "settings:edit"
    SETTINGS_MANAGE = "settings:manage"

    # System Health, Diagnostics & Disaster Recovery
    HEALTH_VIEW = "health:view"
    BACKUP_MANAGE = "backup:manage"


# Granular Permission Matrix for all 6 Roles
ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.SUPER_ADMIN: set(Permission),  # All permissions

    UserRole.SECURITY_ADMIN: {
        Permission.USERS_VIEW, Permission.USERS_CREATE, Permission.USERS_EDIT, Permission.ROLES_MANAGE,
        Permission.ALERTS_VIEW, Permission.ALERTS_TRIAGE,
        Permission.INCIDENTS_VIEW, Permission.INCIDENTS_CREATE, Permission.INCIDENTS_UPDATE,
        Permission.SOAR_VIEW, Permission.SOAR_EXECUTE, Permission.SOAR_CONFIG,
        Permission.INTEL_VIEW, Permission.INTEL_EDIT,
        Permission.RULES_VIEW, Permission.RULES_MANAGE,
        Permission.VULN_VIEW, Permission.VULN_SCAN, Permission.VULN_MANAGE,
        Permission.MALWARE_ANALYZE, Permission.PHISHING_ANALYZE,
        Permission.NETWORK_VIEW, Permission.NETWORK_CONTROL,
        Permission.ML_VIEW, Permission.ML_PREDICT, Permission.ML_TRAIN, Permission.SIMULATION_RUN,
        Permission.PIPELINES_VIEW, Permission.PIPELINES_RUN, Permission.ANALYTICS_VIEW,
        Permission.TASKS_VIEW, Permission.TASKS_SUBMIT, Permission.TASKS_CANCEL,
        Permission.COMPLIANCE_VIEW, Permission.COMPLIANCE_ASSESS,
        Permission.VAULT_VIEW, Permission.VAULT_VERIFY,
        Permission.REPORTS_VIEW, Permission.REPORTS_GENERATE, Permission.REPORTS_DOWNLOAD,
        Permission.AUDIT_VIEW, Permission.SETTINGS_VIEW, Permission.SETTINGS_EDIT, Permission.SETTINGS_MANAGE,
        Permission.HEALTH_VIEW, Permission.BACKUP_MANAGE,
    },

    UserRole.SECURITY_ANALYST: {
        Permission.USERS_VIEW,
        Permission.ALERTS_VIEW, Permission.ALERTS_TRIAGE,
        Permission.INCIDENTS_VIEW, Permission.INCIDENTS_CREATE, Permission.INCIDENTS_UPDATE,
        Permission.EVIDENCE_SEAL, Permission.EVIDENCE_EXPORT,
        Permission.SOAR_VIEW, Permission.SOAR_EXECUTE,
        Permission.INTEL_VIEW,
        Permission.RULES_VIEW, Permission.RULES_MANAGE,
        Permission.VULN_VIEW, Permission.VULN_SCAN,
        Permission.MALWARE_ANALYZE, Permission.PHISHING_ANALYZE,
        Permission.NETWORK_VIEW,
        Permission.ML_VIEW, Permission.ML_PREDICT, Permission.SIMULATION_RUN,
        Permission.PIPELINES_VIEW, Permission.ANALYTICS_VIEW,
        Permission.TASKS_VIEW, Permission.TASKS_SUBMIT,
        Permission.COMPLIANCE_VIEW, Permission.COMPLIANCE_ASSESS,
        Permission.VAULT_VIEW, Permission.VAULT_VERIFY,
        Permission.REPORTS_VIEW, Permission.REPORTS_GENERATE, Permission.REPORTS_DOWNLOAD,
        Permission.AUDIT_VIEW, Permission.SETTINGS_VIEW,
        Permission.HEALTH_VIEW,
    },

    UserRole.INCIDENT_RESPONDER: {
        Permission.ALERTS_VIEW, Permission.ALERTS_TRIAGE,
        Permission.INCIDENTS_VIEW, Permission.INCIDENTS_CREATE, Permission.INCIDENTS_UPDATE,
        Permission.EVIDENCE_SEAL, Permission.EVIDENCE_EXPORT,
        Permission.SOAR_VIEW, Permission.SOAR_EXECUTE,
        Permission.VULN_VIEW, Permission.MALWARE_ANALYZE,
        Permission.NETWORK_VIEW, Permission.NETWORK_CONTROL,
        Permission.ANALYTICS_VIEW,
        Permission.TASKS_VIEW, Permission.TASKS_SUBMIT,
        Permission.COMPLIANCE_VIEW,
        Permission.VAULT_VIEW,
        Permission.REPORTS_VIEW, Permission.REPORTS_GENERATE, Permission.REPORTS_DOWNLOAD,
        Permission.AUDIT_VIEW, Permission.SETTINGS_VIEW,
        Permission.HEALTH_VIEW,
    },

    UserRole.NETWORK_ANALYST: {
        Permission.NETWORK_VIEW, Permission.NETWORK_CONTROL,
        Permission.ALERTS_VIEW,
        Permission.INTEL_VIEW,
        Permission.VULN_VIEW,
        Permission.ANALYTICS_VIEW,
        Permission.TASKS_VIEW,
        Permission.COMPLIANCE_VIEW,
        Permission.VAULT_VIEW,
        Permission.REPORTS_VIEW, Permission.REPORTS_DOWNLOAD,
        Permission.AUDIT_VIEW, Permission.SETTINGS_VIEW,
        Permission.HEALTH_VIEW,
    },

    UserRole.VIEWER: {
        Permission.ALERTS_VIEW,
        Permission.INCIDENTS_VIEW,
        Permission.INTEL_VIEW,
        Permission.VULN_VIEW,
        Permission.NETWORK_VIEW,
        Permission.ML_VIEW,
        Permission.PIPELINES_VIEW,
        Permission.ANALYTICS_VIEW,
        Permission.TASKS_VIEW,
        Permission.COMPLIANCE_VIEW,
        Permission.VAULT_VIEW,
        Permission.REPORTS_VIEW,
        Permission.SETTINGS_VIEW,
        Permission.HEALTH_VIEW,
    },
}


def get_role_permissions(role: str | UserRole) -> List[str]:
    """Return all granted permission strings for a given role."""
    try:
        r = UserRole(role.upper())
        return sorted([p.value for p in ROLE_PERMISSIONS.get(r, set())])
    except ValueError:
        return []


def has_permission(role: str | UserRole, required_permission: str | Permission) -> bool:
    """Check whether a given user role possesses a specific permission."""
    try:
        r = UserRole(role.upper())
        p = Permission(required_permission)
        return p in ROLE_PERMISSIONS.get(r, set())
    except ValueError:
        return False
