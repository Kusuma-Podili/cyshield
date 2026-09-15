"""Database Engine & Asynchronous Session Management for CyberShield Enterprise.

Supports PostgreSQL via asyncpg with seamless SQLite/aiosqlite fallback for
immediate zero-configuration local execution and development.
"""

from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
    AsyncEngine,
)
from sqlalchemy.orm import DeclarativeBase
from cybershield.config import settings

logger = logging.getLogger("cybershield.database")

# Ensure data directory exists
DB_DIR = settings.data_dir
DB_DIR.mkdir(parents=True, exist_ok=True)
SQLITE_PATH = DB_DIR / "cybershield.db"

# Read DATABASE_URL or default to SQLite fallback for instant local run
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    # Use SQLite async driver
    DATABASE_URL = f"sqlite+aiosqlite:///{SQLITE_PATH}"
    logger.info("Using embedded SQLite database: %s", SQLITE_PATH)
else:
    logger.info("Configured database URL: %s", DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL)

# Engine configuration
engine_kwargs = {"echo": False, "future": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs["pool_size"] = 20
    engine_kwargs["max_overflow"] = 10
    engine_kwargs["pool_pre_ping"] = True

engine: AsyncEngine = create_async_engine(DATABASE_URL, **engine_kwargs)
async_session_factory = async_sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    """Base declarative class for all SQLAlchemy ORM models."""
    pass


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency yielding database session with automatic transaction management."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Initialize database schema and seed default administrative account."""
    import cybershield.database.models  # Register all models on Base.metadata
    from cybershield.database.models import User
    from cybershield.auth.security import get_password_hash

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables verified/created successfully.")

    # Seed initial Super Admin if database is empty
    async with async_session_factory() as session:
        from sqlalchemy import select
        result = await session.execute(select(User).where(User.username == "superadmin"))
        existing_admin = result.scalar_one_or_none()

        if not existing_admin:
            admin_user = User(
                username="superadmin",
                email="admin@cybershield.corp",
                full_name="Enterprise Security Lead",
                hashed_password=get_password_hash("CyberShield2026!"),
                role="SUPER_ADMIN",
                is_active=True,
                is_verified=True,
            )
            session.add(admin_user)

            # Seed standard analyst user
            analyst_user = User(
                username="analyst_sarah",
                email="sarah.analyst@cybershield.corp",
                full_name="Sarah Connor",
                hashed_password=get_password_hash("AnalystPass2026!"),
                role="SECURITY_ANALYST",
                is_active=True,
                is_verified=True,
            )
            session.add(analyst_user)

            await session.commit()
            logger.info("Default enterprise accounts seeded ('superadmin', 'analyst_sarah').")
