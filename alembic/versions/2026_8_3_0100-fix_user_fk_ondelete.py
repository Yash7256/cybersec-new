"""Add ON DELETE SET NULL to nullable user_id FKs

The user_id columns on scans, tool_results, and reports are deliberately
nullable (anonymous/pre-auth usage is supported), but the FKs were created
with the default ON DELETE NO ACTION. Deleting a users row therefore raised a
foreign key violation instead of orphaning the child rows cleanly.

Align the live schema with the ORM model (cybersec/database/models.py): each
of the three FKs gets ON DELETE SET NULL. Postgres cannot ALTER an existing
constraint, so each one is dropped and recreated with the same name.

Revision ID: fix_user_fk_ondelete
Revises: fix_scan_type_enum
Create Date: 2026-08-03 01:00:00.000000
"""
from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "fix_user_fk_ondelete"
down_revision: Union[str, None] = "fix_scan_type_enum"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# table -> constraint name. The constraints keep their original Postgres
# default names (table_column_fkey) so the recreated ones are invisible to
# future autogenerate diffs.
_FKS = (
    ("scans", "scans_user_id_fkey", "user_id"),
    ("tool_results", "tool_results_user_id_fkey", "user_id"),
    ("reports", "reports_user_id_fkey", "user_id"),
)


def upgrade() -> None:
    for table, constraint, column in _FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(
            constraint,
            table,
            "users",
            [column],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    # Restore the original default behavior (ON DELETE NO ACTION).
    for table, constraint, column in _FKS:
        op.drop_constraint(constraint, table, type_="foreignkey")
        op.create_foreign_key(constraint, table, "users", [column], ["id"])
