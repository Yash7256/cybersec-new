"""Add FK / hot-path indexes that previously only existed via the hand-run SQL file

Historically the following indexes were created manually via
infrastructure/db/supabase_tables.sql (CREATE INDEX IF NOT EXISTS), never via
Alembic. Any fresh environment built purely with `alembic upgrade head` was
missing them. This migration makes Alembic the single source of truth:

  idx_scans_user_id                    scans(user_id)
  idx_scans_status                     scans(status)
  idx_scans_created_at                 scans(created_at DESC)
  idx_scan_results_scan_id             scan_results(scan_id)
  idx_tool_results_user_id             tool_results(user_id)
  idx_reports_scan_id                  reports(scan_id)
  idx_reports_user_id                  reports(user_id)
  idx_nvd_cve_cache_expires_at         nvd_cve_cache(expires_at)
  idx_worker_heartbeats_last_heartbeat worker_heartbeats(last_heartbeat)

All creates use IF NOT EXISTS (if_not_exists=True), so the migration is a
no-op wherever the SQL file already ran and additive everywhere else.

Housekeeping: migration 2026_4_24_1645 created the index under the Alembic
name ix_nvd_cve_cache_expires_at while the SQL file used
idx_nvd_cve_cache_expires_at — in environments where both ran, the table
carries two identical indexes on expires_at. We keep the idx_ name (the one
matching prod's manual state) and drop the redundant ix_ duplicate. A fresh
env therefore ends up with exactly one index, same as prod.

Note: nvd_service_lookup_cache.cache_key is NOT created here — it already
exists via migration add_nvd_service_lookup_cache
(ix_nvd_service_lookup_cache_cache_key).

Revision ID: add_fk_indexes
Revises: add_tool_usage_events
Create Date: 2026-08-03 04:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "add_fk_indexes"
down_revision: Union[str, None] = "add_tool_usage_events"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -- FK columns ------------------------------------------------------
    op.create_index(op.f("idx_scans_user_id"), "scans", ["user_id"], unique=False, if_not_exists=True)
    op.create_index(op.f("idx_scan_results_scan_id"), "scan_results", ["scan_id"], unique=False, if_not_exists=True)
    op.create_index(op.f("idx_tool_results_user_id"), "tool_results", ["user_id"], unique=False, if_not_exists=True)
    op.create_index(op.f("idx_reports_scan_id"), "reports", ["scan_id"], unique=False, if_not_exists=True)
    op.create_index(op.f("idx_reports_user_id"), "reports", ["user_id"], unique=False, if_not_exists=True)
    op.create_index(op.f("idx_worker_heartbeats_last_heartbeat"), "worker_heartbeats", ["last_heartbeat"], unique=False, if_not_exists=True)

    # -- Hot query paths ------------------------------------------------
    op.create_index(op.f("idx_scans_status"), "scans", ["status"], unique=False, if_not_exists=True)
    op.create_index(
        op.f("idx_scans_created_at"),
        "scans",
        [sa.text("created_at DESC")],
        unique=False,
        if_not_exists=True,
    )
    op.create_index(op.f("idx_nvd_cve_cache_expires_at"), "nvd_cve_cache", ["expires_at"], unique=False, if_not_exists=True)

    # Drop the redundant duplicate created by migration 2026_4_24_1645
    # (ix_nvd_cve_cache_expires_at) — identical predicate to idx_ above.
    op.drop_index(op.f("ix_nvd_cve_cache_expires_at"), table_name="nvd_cve_cache", if_exists=True)


def downgrade() -> None:
    # Recreate the duplicate dropped in upgrade() so downgrade returns the
    # schema to the state produced by migration 2026_4_24_1645.
    op.create_index(op.f("ix_nvd_cve_cache_expires_at"), "nvd_cve_cache", ["expires_at"], unique=False, if_not_exists=True)

    op.drop_index(op.f("idx_nvd_cve_cache_expires_at"), table_name="nvd_cve_cache", if_exists=True)
    op.drop_index(op.f("idx_scans_created_at"), table_name="scans", if_exists=True)
    op.drop_index(op.f("idx_scans_status"), table_name="scans", if_exists=True)
    op.drop_index(op.f("idx_worker_heartbeats_last_heartbeat"), table_name="worker_heartbeats", if_exists=True)
    op.drop_index(op.f("idx_reports_user_id"), table_name="reports", if_exists=True)
    op.drop_index(op.f("idx_reports_scan_id"), table_name="reports", if_exists=True)
    op.drop_index(op.f("idx_tool_results_user_id"), table_name="tool_results", if_exists=True)
    op.drop_index(op.f("idx_scan_results_scan_id"), table_name="scan_results", if_exists=True)
    op.drop_index(op.f("idx_scans_user_id"), table_name="scans", if_exists=True)
