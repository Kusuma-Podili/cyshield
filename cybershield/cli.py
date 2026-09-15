"""Enterprise Command-Line Administrative Interface (CLI) for CyberShield.

Provides robust command-line operations for system status, database initialization,
user management, WORM vault verification, disaster recovery backups, and report compilation.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import json
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select, func, text
from cybershield.version import __version__
from cybershield.database.session import async_session_factory, init_db
from cybershield.database.models.user import User
from cybershield.database.models.role import UserRole
from cybershield.auth.security import get_password_hash
from cybershield.audit.vault import AuditVault
from cybershield.health.service import HealthService
from cybershield.core.backup import BackupService


def print_banner():
    """Display enterprise ASCII banner."""
    print("=" * 70)
    print(f"  CYBERSHIELD ENTERPRISE v{__version__} - ADMINISTRATIVE CLI")
    print("  Privacy-First Autonomous Cybersecurity & Threat Detection Platform")
    print("=" * 70)


async def cmd_status():
    """Query and display system operational telemetry and database counters."""
    print_banner()
    print("\n[*] Sampling System Health & Telemetry...")
    hw = HealthService.get_hardware_metrics()
    print(f"  • Platform:        {hw.platform}")
    print(f"  • Python:          {hw.python_version}")
    print(f"  • Process PID:     {hw.process_pid}")
    print(f"  • Memory:          {hw.memory_used_mb:.1f} MB / {hw.memory_total_mb:.1f} MB ({hw.memory_percent:.1f}% used)")
    print(f"  • Disk:            {hw.disk_used_gb:.1f} GB / {hw.disk_total_gb:.1f} GB ({hw.disk_percent:.1f}% used)")
    print(f"  • CPU Estimate:    {hw.cpu_percent:.1f}%")

    print("\n[*] Querying Database & Telemetry State...")
    try:
        async with async_session_factory() as session:
            # Users
            u_res = await session.execute(select(func.count(User.id)))
            users_count = u_res.scalar() or 0

            # Devices
            try:
                from cybershield.database.models.device import Device
                d_res = await session.execute(select(func.count(Device.id)))
                devices_count = d_res.scalar() or 0
            except Exception:
                devices_count = 0

            # Incidents
            try:
                from cybershield.database.models.incident import IncidentModel
                i_res = await session.execute(select(func.count(IncidentModel.id)))
                incidents_count = i_res.scalar() or 0
            except Exception:
                incidents_count = 0

            # Vault Blocks
            try:
                from cybershield.database.models.vault import AuditVaultBlockModel
                v_res = await session.execute(select(func.count(AuditVaultBlockModel.id)))
                vault_count = v_res.scalar() or 0
            except Exception:
                vault_count = 0

            print(f"  • Database State:  ONLINE (Active)")
            print(f"  • Total Users:     {users_count}")
            print(f"  • Managed Devices: {devices_count}")
            print(f"  • Total Incidents: {incidents_count}")
            print(f"  • WORM Vault:      {vault_count} cryptographically sealed blocks")
            print("\n[+] Status: HEALTHY - Platform is ready for operations.\n")
    except Exception as e:
        print(f"\n[-] Database connection error: {e}\n")


async def cmd_db_init():
    """Initialize database tables and seed baseline enterprise datasets."""
    print_banner()
    print("\n[*] Initializing Database Schema...")
    await init_db()
    print("[+] Tables and indices created successfully.")

    print("[*] Seeding enterprise baseline datasets...")
    async with async_session_factory() as session:
        from cybershield.network.subnet_service import SubnetService
        from cybershield.network.device_service import DeviceService
        from cybershield.alerts.service import AlertService
        from cybershield.events.service import EventsService
        from cybershield.detection.service import detection_rule_service
        from cybershield.incidents.service import incident_service
        from cybershield.vulnerabilities.service import vulnerability_service
        from cybershield.intel.service import threat_intel_service
        from cybershield.ml.service import ml_service
        from cybershield.analytics.service import analytics_service
        from cybershield.compliance.engine import ComplianceEngine
        from cybershield.settings.manager import SettingsManager

        await SubnetService(session).seed_enterprise_subnets()
        await DeviceService(session).seed_enterprise_devices()
        await AlertService(session).seed_default_alerts()
        await EventsService(session).seed_default_events()
        await detection_rule_service.seed_rules_if_empty(session)
        await incident_service.seed_sample_incidents_if_empty(session)
        await vulnerability_service.seed_default_vulnerabilities(session)
        await threat_intel_service.seed_threat_intelligence(session)
        await ml_service.seed_default_models(session)
        await analytics_service.seed_default_pipelines(session)
        await ComplianceEngine.seed_frameworks_if_empty(session)
        await AuditVault.initialize_genesis_block(session)
        await SettingsManager.seed_defaults_if_empty(session)

    print("[+] Database initialized and seeded with enterprise defaults.\n")


async def cmd_user_create(username: str, email: str, password: str, role_str: str, full_name: Optional[str] = None):
    """Provision a new user account with assigned RBAC role."""
    print_banner()
    try:
        role = UserRole(role_str.upper())
    except ValueError:
        print(f"[-] Invalid role: '{role_str}'. Valid roles: {[r.value for r in UserRole]}")
        return

    async with async_session_factory() as session:
        # Check existing
        res = await session.execute(select(User).where(User.username == username))
        if res.scalar_one_or_none():
            print(f"[-] User '{username}' already exists.")
            return

        new_user = User(
            username=username,
            email=email,
            hashed_password=get_password_hash(password),
            role=role.value,
            full_name=full_name or username.capitalize(),
            is_active=True,
            is_verified=True,
            is_locked=False,
        )
        session.add(new_user)
        await session.commit()
        print(f"[+] Successfully created user '{username}' ({role.value}) with email <{email}>.\n")


async def cmd_vault_verify():
    """Verify cryptographic chain continuity of the WORM Audit Vault."""
    print_banner()
    print("\n[*] Verifying Cryptographic Audit Vault SHA-256 Merkle Chain...")
    async with async_session_factory() as session:
        ver = await AuditVault.verify_chain(session)
        if ver.get("is_valid"):
            print(f"[+] CRYPTOGRAPHIC INTEGRITY VERIFIED")
            print(f"  • Total Blocks:    {ver.get('total_blocks')}")
            print(f"  • Genesis Hash:    {ver.get('genesis_hash')}")
            print(f"  • Tip Hash:        {ver.get('latest_block_hash')}")
            print(f"  • Status:          100% Intact - Zero tampering or retrofitting detected.\n")
        else:
            print(f"[-] CRITICAL ALERT: Tampering Detected!")
            print(f"  • Broken Block:    #{ver.get('tampered_block_index')}")
            print(f"  • Error:           {ver.get('error_message')}\n")


async def cmd_backup_create(note: Optional[str] = None):
    """Execute point-in-time database snapshotting."""
    print_banner()
    print("\n[*] Creating Database Snapshot...")
    async with async_session_factory() as session:
        meta = await BackupService.create_snapshot(session, note=note, actor_id="cli-admin")
        print(f"[+] Backup successfully generated:")
        print(f"  • Archive File:    {meta.filename}")
        print(f"  • Size:            {meta.size_bytes:,} bytes")
        print(f"  • Timestamp:       {meta.created_at}")
        print(f"  • SHA-256 Digest:  {meta.checksum_sha256}")
        print(f"  • Audit Seal:      Sealed in Cryptographic WORM Vault\n")


def cmd_backup_list():
    """List available database backups."""
    print_banner()
    res = BackupService.list_snapshots()
    print(f"\n[*] Available Database Snapshots ({res.total} total):")
    if not res.backups:
        print("  (No backups found in data/backups/)")
    else:
        for b in res.backups:
            print(f"  • [{b.created_at.strftime('%Y-%m-%d %H:%M:%S')}] {b.filename:<32} ({b.size_bytes:>9,} B) SHA256: {b.checksum_sha256[:16]}... {f'({b.note})' if b.note else ''}")
    print()


def cmd_backup_verify(filename: str):
    """Verify archive integrity."""
    print_banner()
    print(f"\n[*] Verifying SHA-256 checksum for '{filename}'...")
    res = BackupService.verify_snapshot(filename)
    if res.verified:
        print(f"[+] {res.message}")
        print(f"  • Checksum: {res.calculated_sha256}\n")
    else:
        print(f"[-] {res.message}\n")


async def cmd_report_generate(report_type: str, output_path: Optional[str] = None):
    """Generate a compliance or executive posture report directly to file."""
    print_banner()
    print(f"\n[*] Compiling '{report_type}' Report...")
    from cybershield.reports.service import ReportService
    from cybershield.reports.schemas import ReportType, ReportFormat, ReportGenerateRequest

    try:
        rtype = ReportType(report_type.upper())
    except ValueError:
        print(f"[-] Invalid report type. Valid options: {[r.value for r in ReportType]}")
        return

    async with async_session_factory() as session:
        req = ReportGenerateRequest(report_type=rtype, report_format=ReportFormat.HTML, title=f"CLI Compiled {rtype.value}")
        rep = await ReportService.generate_report(session, req, actor_id="cli-admin")

        if output_path is None:
            output_path = f"{rtype.value.lower()}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rep.html_content or "")

        print(f"[+] Report compiled successfully:")
        print(f"  • Report ID:   {rep.id}")
        print(f"  • Title:       {rep.title}")
        print(f"  • Saved File:  {output_path}")
        print(f"  • Size:        {os.path.getsize(output_path):,} bytes\n")


def main():
    """Main CLI entry point parser."""
    parser = argparse.ArgumentParser(
        prog="cybershield",
        description="CyberShield Enterprise Administrative Command-Line Interface",
    )
    subparsers = parser.add_subparsers(dest="command", help="Operational commands")

    # status
    subparsers.add_parser("status", help="Display platform health, telemetry, and system statistics")

    # db-init
    subparsers.add_parser("db-init", help="Initialize database schema and seed baseline enterprise datasets")

    # user-create
    p_user = subparsers.add_parser("user-create", help="Create an enterprise user account")
    p_user.add_argument("--username", required=True, help="Login username")
    p_user.add_argument("--email", required=True, help="User email address")
    p_user.add_argument("--password", required=True, help="Account password")
    p_user.add_argument("--role", default="SECURITY_ANALYST", help="Assigned RBAC role")
    p_user.add_argument("--full-name", default=None, help="User full name")

    # vault-verify
    subparsers.add_parser("vault-verify", help="Verify cryptographic SHA-256 chain integrity of the WORM Audit Vault")

    # backup-create
    p_bk = subparsers.add_parser("backup-create", help="Create an immediate database backup snapshot")
    p_bk.add_argument("--note", default="CLI on-demand backup", help="Descriptive annotation")

    # backup-list
    subparsers.add_parser("backup-list", help="List all database snapshots and cryptographic digests")

    # backup-verify
    p_bv = subparsers.add_parser("backup-verify", help="Verify SHA-256 checksum of an archive")
    p_bv.add_argument("--filename", required=True, help="Backup file name")

    # report-generate
    p_rg = subparsers.add_parser("report-generate", help="Compile and export an executive or compliance report")
    p_rg.add_argument("--type", default="EXECUTIVE_POSTURE", help="Report template type")
    p_rg.add_argument("--output", default=None, help="Output destination file path")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "status":
        asyncio.run(cmd_status())
    elif args.command == "db-init":
        asyncio.run(cmd_db_init())
    elif args.command == "user-create":
        asyncio.run(cmd_user_create(args.username, args.email, args.password, args.role, args.full_name))
    elif args.command == "vault-verify":
        asyncio.run(cmd_vault_verify())
    elif args.command == "backup-create":
        asyncio.run(cmd_backup_create(args.note))
    elif args.command == "backup-list":
        cmd_backup_list()
    elif args.command == "backup-verify":
        cmd_backup_verify(args.filename)
    elif args.command == "report-generate":
        asyncio.run(cmd_report_generate(args.type, args.output))


if __name__ == "__main__":
    main()
