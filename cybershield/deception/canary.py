"""Canary Token & Honeytoken Management Engine.

Generates and tracks tripwire canaries across API tokens, honeyfiles,
database honey-records, decoy Active Directory user accounts, and canary DNS domains.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from cybershield.deception.schemas import (
    CanaryType,
    CanaryToken,
    TripwireAlert,
    CanaryGenerateRequest,
)


class CanaryManager:
    """Manages creation, deployment, and tripwire verification of canary tokens."""

    _tokens_store: Dict[str, CanaryToken] = {}

    @classmethod
    def generate_canary(cls, req: CanaryGenerateRequest) -> CanaryToken:
        """Create a new specialized deception canary token."""
        token_id = f"cny-{uuid.uuid4().hex[:10]}"
        now = datetime.now(timezone.utc)

        meta: Dict[str, Any] = {}
        canary_val = ""

        if req.canary_type == CanaryType.API_KEY:
            fake_key_id = f"AKIA{secrets.token_hex(8).upper()}"
            fake_secret = f"cs_sec_{secrets.token_urlsafe(32)}"
            canary_val = f"{fake_key_id}:{fake_secret}"
            meta["key_id"] = fake_key_id
            meta["format"] = "AWS/Cloud IAM Credentials"

        elif req.canary_type == CanaryType.HONEYFILE:
            canary_id = uuid.uuid4().hex[:12]
            filename = req.target_path_or_host or f"Enterprise_Confidential_Credentials_{canary_id[:4]}.xlsx"
            canary_val = f"HONEYFILE_TAG::{canary_id}::{filename}"
            meta["filename"] = filename
            meta["fingerprint"] = canary_id

        elif req.canary_type == CanaryType.DATABASE_RECORD:
            username = req.target_path_or_host or f"backup_admin_{secrets.token_hex(3)}"
            fake_pw = f"Pass_{secrets.token_hex(6)}!"
            canary_val = f"DB_USER::{username}::{fake_pw}"
            meta["username"] = username
            meta["table"] = "auth_users_backup"

        elif req.canary_type == CanaryType.DNS_TOKEN:
            unique_sub = f"cny-{uuid.uuid4().hex[:8]}"
            domain = f"{unique_sub}.canary.cybershield.corp"
            canary_val = domain
            meta["domain"] = domain
            meta["subdomain"] = unique_sub

        elif req.canary_type == CanaryType.CANARY_USER:
            user_name = req.target_path_or_host or f"svc_legacy_sql_{secrets.token_hex(2)}"
            canary_val = f"USER::{user_name}"
            meta["ad_account"] = user_name
            meta["spn"] = f"MSSQLSvc/{user_name}.corp.internal:1433"

        token = CanaryToken(
            token_id=token_id,
            canary_type=req.canary_type,
            name=req.name,
            description=req.description or "Active deception honeytoken",
            canary_value=canary_val,
            created_at=now,
            is_tripped=False,
            trip_count=0,
            metadata=meta,
        )

        cls._tokens_store[token_id] = token
        return token

    @classmethod
    def check_value_trip(cls, input_text: str, source_ip: str = "10.0.0.99") -> Optional[TripwireAlert]:
        """Inspect string/query and trigger alert if it contains any active canary token."""
        for token in cls._tokens_store.values():
            trigger = False
            # Check full canary value or key parts
            if token.canary_type == CanaryType.API_KEY:
                key_id = token.metadata.get("key_id", "")
                if key_id and key_id in input_text:
                    trigger = True
            elif token.canary_type == CanaryType.HONEYFILE:
                fp = token.metadata.get("fingerprint", "")
                fn = token.metadata.get("filename", "")
                if (fp and fp in input_text) or (fn and fn in input_text):
                    trigger = True
            elif token.canary_type == CanaryType.DATABASE_RECORD:
                u = token.metadata.get("username", "")
                if u and u in input_text:
                    trigger = True
            elif token.canary_type == CanaryType.DNS_TOKEN:
                dom = token.metadata.get("domain", "")
                sub = token.metadata.get("subdomain", "")
                if (dom and dom in input_text) or (sub and sub in input_text):
                    trigger = True
            elif token.canary_type == CanaryType.CANARY_USER:
                acct = token.metadata.get("ad_account", "")
                if acct and acct in input_text:
                    trigger = True
            elif token.canary_value in input_text:
                trigger = True

            if trigger:
                now = datetime.now(timezone.utc)
                token.is_tripped = True
                token.trip_count += 1
                token.last_tripped_at = now
                token.trip_source_ip = source_ip

                alert_id = f"TRIP-{uuid.uuid4().hex[:8].upper()}"
                return TripwireAlert(
                    alert_id=alert_id,
                    timestamp=now,
                    trap_or_canary_id=token.token_id,
                    trap_type=f"CANARY_{token.canary_type.value}",
                    source_ip=source_ip,
                    severity="CRITICAL",
                    title=f"Deception Honeytoken Tripped: {token.name}",
                    description=(
                        f"Adversary interacted with deceptive honeytoken '{token.name}' ({token.canary_type.value}). "
                        f"Definitive high-fidelity intrusion indicator from IP {source_ip}."
                    ),
                    attacker_payload={"input_sample": input_text[:200], "canary_id": token.token_id},
                    mitre_technique="T1078.001",
                )

        return None

    @classmethod
    def list_canaries(cls) -> List[CanaryToken]:
        """Return all registered canary tokens."""
        return list(cls._tokens_store.values())

    @classmethod
    def seed_default_canaries_if_empty(cls) -> None:
        """Seed baseline enterprise canaries."""
        if not cls._tokens_store:
            cls.generate_canary(
                CanaryGenerateRequest(
                    canary_type=CanaryType.API_KEY,
                    name="AWS Production Deployment Honeykey",
                    description="Decoy AWS IAM secret deployed in developer git repositories",
                )
            )
            cls.generate_canary(
                CanaryGenerateRequest(
                    canary_type=CanaryType.HONEYFILE,
                    name="Q3 Payroll & Executive Bonuses",
                    description="Decoy Excel spreadsheet placed on file shares",
                    target_path_or_host="Executive_Payroll_Q3_Confidential.xlsx",
                )
            )
            cls.generate_canary(
                CanaryGenerateRequest(
                    canary_type=CanaryType.CANARY_USER,
                    name="Legacy MSSQL Service Account",
                    description="Decoy Active Directory account to detect Kerberoasting / password spraying",
                    target_path_or_host="svc_sql_prod_archive",
                )
            )
