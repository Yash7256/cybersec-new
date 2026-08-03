"""Create unified tool_runs parent entity for all tool executions

scans and tool_results are two unrelated run tables with no common lineage:
port scans + web scans live in scans/scan_results, the other tools live in a
flat tool_results with no FK to anything. This migration introduces a single
parent table, tool_runs, and re-points all three children at it:

    tool_runs (new)
    ├── scan_results.tool_run_id  (new nullable FK, backfilled from scan_id)
    ├── tool_results.tool_run_id  (new nullable FK, backfilled from id)
    └── reports.tool_run_id       (new nullable FK, backfilled from scan_id)

Design: tool_runs.id REUSES the legacy scans.id / tool_results.id, so the
backfill is a plain INSERT ... SELECT with no mapping table and zero data
loss. tool_name is normalized to the tier vocabulary ('port'/'full' ->
'port_scan', 'web' -> 'webapp').

Backward compatibility: this pass is strictly additive — scans, tool_results,
scan_results and reports keep every existing column and row, and the new
tool_run_id columns are nullable. Existing route/worker code keeps working
unchanged; a follow-up pass repoints the writers (tools.py, webapp.py,
cli/main.py, recovery.py) to create tool_runs rows, after which the legacy
columns can be dropped.

Revision ID: add_tool_runs_parent
Revises: add_fk_indexes
Create Date: 2026-08-03 05:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "add_tool_runs_parent"
down_revision: Union[str, None] = "add_fk_indexes"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Unified parent table — superset of scans + tool_results parent fields.
    op.create_table(
        "tool_runs",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.Column("tool_name", sa.String(length=50), nullable=False),
        sa.Column("target", sa.String(length=255), nullable=False),
        # create_type=False: scan_status_enum already exists (initial migration
        # + add_scan_recovery), SQLAlchemy would otherwise re-emit CREATE TYPE.
        sa.Column("status", postgresql.ENUM("pending", "running", "completed", "failed", "cancelled", "timed_out", name="scan_status_enum", create_type=False), nullable=True),
        sa.Column("port_range", sa.String(length=100), nullable=True),
        sa.Column("options", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("completed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("heartbeat_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("worker_id", sa.String(length=100), nullable=True),
        sa.Column("progress_pct", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    # 2. Backfill from scans (id reuse => tool_runs.id == legacy scans.id).
    op.execute(
        """
        INSERT INTO tool_runs
            (id, user_id, tool_name, target, status, port_range, options,
             started_at, completed_at, error_message, heartbeat_at, worker_id,
             progress_pct, created_at, updated_at)
        SELECT
            id, user_id,
            CASE scan_type
                WHEN 'port' THEN 'port_scan'
                WHEN 'full' THEN 'port_scan'
                WHEN 'web' THEN 'webapp'
                ELSE scan_type
            END,
            target, status, port_range, options,
            started_at, completed_at, error_message, heartbeat_at, worker_id,
            progress_pct, created_at, updated_at
        FROM scans
        ON CONFLICT (id) DO NOTHING
        """
    )

    # 3. Backfill from tool_results (id reuse => tool_runs.id == legacy tool_results.id).
    op.execute(
        """
        INSERT INTO tool_runs
            (id, user_id, tool_name, target, status,
             started_at, completed_at, error_message, heartbeat_at, worker_id,
             progress_pct, created_at, updated_at)
        SELECT
            id, user_id, tool_name, target, status,
            started_at, completed_at, error_message, heartbeat_at, worker_id,
            progress_pct, created_at, updated_at
        FROM tool_results
        ON CONFLICT (id) DO NOTHING
        """
    )

    # 4. Children get a nullable tool_run_id FK (nullable => routes keep working).
    op.add_column("scan_results", sa.Column("tool_run_id", sa.UUID(), nullable=True))
    op.add_column("tool_results", sa.Column("tool_run_id", sa.UUID(), nullable=True))
    op.add_column("reports", sa.Column("tool_run_id", sa.UUID(), nullable=True))

    # 5. Backfill the FK columns via the id-reuse property.
    op.execute("UPDATE scan_results SET tool_run_id = scan_id WHERE tool_run_id IS NULL")
    op.execute("UPDATE tool_results SET tool_run_id = id WHERE tool_run_id IS NULL")
    op.execute("UPDATE reports SET tool_run_id = scan_id WHERE tool_run_id IS NULL")

    # 6. FK constraints + covering indexes.
    op.create_foreign_key(
        "scan_results_tool_run_id_fkey", "scan_results", "tool_runs",
        ["tool_run_id"], ["id"], ondelete="CASCADE",
    )
    op.create_foreign_key(
        "tool_results_tool_run_id_fkey", "tool_results", "tool_runs",
        ["tool_run_id"], ["id"], ondelete="CASCADE",
    )
    op.create_foreign_key(
        "reports_tool_run_id_fkey", "reports", "tool_runs",
        ["tool_run_id"], ["id"], ondelete="CASCADE",
    )
    op.create_index(op.f("ix_scan_results_tool_run_id"), "scan_results", ["tool_run_id"], unique=False, if_not_exists=True)
    op.create_index(op.f("ix_tool_results_tool_run_id"), "tool_results", ["tool_run_id"], unique=False, if_not_exists=True)
    op.create_index(op.f("ix_reports_tool_run_id"), "reports", ["tool_run_id"], unique=False, if_not_exists=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_reports_tool_run_id"), table_name="reports", if_exists=True)
    op.drop_index(op.f("ix_tool_results_tool_run_id"), table_name="tool_results", if_exists=True)
    op.drop_index(op.f("ix_scan_results_tool_run_id"), table_name="scan_results", if_exists=True)

    op.drop_constraint("reports_tool_run_id_fkey", "reports", type_="foreignkey")
    op.drop_constraint("tool_results_tool_run_id_fkey", "tool_results", type_="foreignkey")
    op.drop_constraint("scan_results_tool_run_id_fkey", "scan_results", type_="foreignkey")

    op.drop_column("reports", "tool_run_id")
    op.drop_column("tool_results", "tool_run_id")
    op.drop_column("scan_results", "tool_run_id")

    op.drop_table("tool_runs")
