"""Add append-only tool_usage_events table

users.tool_usage is a same-day per-tool rate-limit counter (JSONB) whose
per-day entry is overwritten every day — it answers "how many free uses
remain today" but has no history. This migration adds an append-only event
table recording every gated tool invocation, so per-user/per-tool usage
history ("whois runs in the last 30 days") becomes queryable for analytics
and admin dashboards.

Design: one row per invocation (id, user_id FK CASCADE, tool_name, used_at),
no TimestampMixin columns — deliberately minimal and append-only. Two
indexes:
  - (user_id, tool_name, used_at): "count events for user+tool since date X"
  - (used_at): global time-range scans across all users

The existing users.tool_usage JSONB column and its read path are left
untouched; event insertion is additive alongside the JSONB increment in
cybersec/apps/api/tier.py.

Revision ID: add_tool_usage_events
Revises: add_tool_results_lifecycle
Create Date: 2026-08-03 03:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "add_tool_usage_events"
down_revision: Union[str, None] = "add_tool_results_lifecycle"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tool_usage_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("tool_name", sa.String(length=50), nullable=False),
        sa.Column("used_at", sa.TIMESTAMP(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_tool_usage_events_user_tool_used_at",
        "tool_usage_events",
        ["user_id", "tool_name", "used_at"],
    )
    op.create_index("ix_tool_usage_events_used_at", "tool_usage_events", ["used_at"])


def downgrade() -> None:
    op.drop_index("ix_tool_usage_events_used_at", table_name="tool_usage_events")
    op.drop_index("ix_tool_usage_events_user_tool_used_at", table_name="tool_usage_events")
    op.drop_table("tool_usage_events")
