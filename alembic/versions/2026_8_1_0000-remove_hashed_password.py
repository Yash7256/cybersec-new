"""Remove legacy hashed_password column from users table

Revision ID: remove_hashed_password
Revises: add_user_tier_and_usage
Create Date: 2026-08-01 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "remove_hashed_password"
down_revision: Union[str, None] = "add_user_tier_and_usage"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Password auth is fully decommissioned (Clerk migration) — drop the
    # leftover hashed_password column so it can never be reactivated.
    op.drop_column("users", "hashed_password")


def downgrade() -> None:
    # Restore the column as nullable (Clerk users have no local password).
    op.add_column(
        "users",
        sa.Column("hashed_password", sa.String(255), nullable=True),
    )
