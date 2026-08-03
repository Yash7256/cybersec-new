"""Add lifecycle/status tracking to tool_results

tool_results rows are currently written atomically after a run finishes and
carry no status or timing columns, while scans has a full lifecycle
(pending/running/completed/failed/cancelled/timed_out + worker recovery
fields). Give tool_results the same lifecycle so both tables share one
status vocabulary (the same scan_status_enum Postgres type) and the recovery
machinery can later be reused for long-running/streaming tools.

Backward compatibility: this is purely ADDITIVE — new nullable columns plus a
server default. No data is dropped or recreated. Existing rows are backfilled
in place:

  - status       -> 'completed' (via the ADD COLUMN server default; these rows
                    were persisted only after their run had finished)
  - started_at   -> created_at (approximation: true start time was never
                    recorded historically)
  - completed_at -> created_at (accurate: the row was written on completion)

Revision ID: add_tool_results_lifecycle
Revises: fix_user_fk_ondelete
Create Date: 2026-08-03 02:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "add_tool_results_lifecycle"
down_revision: Union[str, None] = "fix_user_fk_ondelete"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The full shared status vocabulary; matches Scan.status and the ORM model.
_STATUS_VALUES = ("pending", "running", "completed", "failed", "cancelled", "timed_out")


def upgrade() -> None:
    # The shared enum type should already exist with all values (initial
    # migration + add_scan_recovery), but environments that drifted to a
    # VARCHAR scans.status may not have it. Create/repair defensively so
    # tool_results.status can always reference the type.
    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE scan_status_enum AS ENUM ('pending', 'running', 'completed', 'failed');
        EXCEPTION WHEN duplicate_object THEN null;
        END $$;
        """
    )
    op.execute("ALTER TYPE scan_status_enum ADD VALUE IF NOT EXISTS 'cancelled'")
    op.execute("ALTER TYPE scan_status_enum ADD VALUE IF NOT EXISTS 'timed_out'")

    # Lifecycle columns — all nullable so existing insert paths keep working
    # unchanged. server_default='completed' backfills existing rows and covers
    # inserts that don't set status explicitly (accurate: today rows are only
    # written after the run has finished).
    op.add_column(
        "tool_results",
        sa.Column(
            "status",
            sa.Enum(*_STATUS_VALUES, name="scan_status_enum"),
            nullable=True,
            server_default="completed",
        ),
    )
    op.add_column("tool_results", sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True))
    op.add_column("tool_results", sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True))
    op.add_column("tool_results", sa.Column("error_message", sa.Text(), nullable=True))

    # Distributed state tracking — mirrors scans; for long-running/streaming tools only
    op.add_column("tool_results", sa.Column("heartbeat_at", sa.TIMESTAMP(timezone=True), nullable=True))
    op.add_column("tool_results", sa.Column("worker_id", sa.String(100), nullable=True))
    op.add_column("tool_results", sa.Column("progress_pct", sa.Integer(), nullable=True))

    # Backfill timing on pre-existing rows (no-op on fresh databases).
    op.execute(
        "UPDATE tool_results "
        "SET started_at = created_at, completed_at = created_at "
        "WHERE started_at IS NULL AND completed_at IS NULL"
    )


def downgrade() -> None:
    # Drop only the added columns. The shared scan_status_enum type stays —
    # scans.status still references it.
    op.drop_column("tool_results", "progress_pct")
    op.drop_column("tool_results", "worker_id")
    op.drop_column("tool_results", "heartbeat_at")
    op.drop_column("tool_results", "error_message")
    op.drop_column("tool_results", "completed_at")
    op.drop_column("tool_results", "started_at")
    op.drop_column("tool_results", "status")
