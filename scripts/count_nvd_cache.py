#!/usr/bin/env python3
"""
Count / clear rows in NVDServiceLookupCache.

Usage:
    python3 scripts/count_nvd_cache.py              # count + show sample rows
    python3 scripts/count_nvd_cache.py --clear       # delete all rows
"""
import os
import sys
import asyncio
from datetime import datetime, timezone

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from cybersec.database.models import NVDServiceLookupCache

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://postgres:postgres@localhost:5432/cybersec",
)


async def main():
    engine = create_async_engine(DATABASE_URL)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    do_clear = "--clear" in sys.argv

    async with async_session() as db:
        # --- before count ---
        count_result = await db.execute(
            select(func.count()).select_from(NVDServiceLookupCache)
        )
        before = count_result.scalar()
        print(f"Total rows in NVDServiceLookupCache: {before}")

        if not do_clear and before and before > 0:
            rows_result = await db.execute(
                select(NVDServiceLookupCache)
                .order_by(NVDServiceLookupCache.fetched_at.desc())
                .limit(20)
            )
            rows = rows_result.scalars().all()
            print(f"\n--- Up to 20 most recent entries ---")
            print(f"{'service_name':<20} {'service_version':<20} {'fetched_at'}")
            print("-" * 60)
            for r in rows:
                print(f"{r.service_name:<20} {r.service_version:<20} {r.fetched_at}")

        # --- clear ---
        if do_clear:
            print("\nDeleting all rows...")
            await db.execute(NVDServiceLookupCache.__table__.delete())
            await db.commit()

            after_result = await db.execute(
                select(func.count()).select_from(NVDServiceLookupCache)
            )
            after = after_result.scalar()
            print(f"Rows after delete: {after}")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
