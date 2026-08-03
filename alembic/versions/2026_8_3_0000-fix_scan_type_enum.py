"""Change scans.scan_type from scan_type_enum to VARCHAR(50)

The initial migration created scans.scan_type as an ENUM ('port','web','full'),
but the ORM model (cybersec/database/models.py) and the application treat it as
free-form tool names ('whois', 'dns', 'port_scan', ...). Align the live schema
with the model: convert the column to VARCHAR(50) and drop the now-unused enum
type.

Revision ID: fix_scan_type_enum
Revises: remove_hashed_password
Create Date: 2026-08-03 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "fix_scan_type_enum"
down_revision: Union[str, None] = "remove_hashed_password"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The values the original enum permitted. Downgrade back to the enum is only
# safe when every existing row's scan_type is one of these.
_ENUM_VALUES = ("port", "web", "full")


def upgrade() -> None:
    # Convert the column from the enum to VARCHAR(50). The explicit USING cast
    # is safe whether the column currently holds the enum or is already text
    # (e.g. environments manually altered out-of-band), and it is a no-op if the
    # type is already VARCHAR(50).
    op.execute(
        "ALTER TABLE scans "
        "ALTER COLUMN scan_type TYPE VARCHAR(50) "
        "USING scan_type::text::character varying(50)"
    )
    # Drop the enum type now that no column references it. IF EXISTS keeps the
    # migration idempotent on DBs where the type was already dropped manually.
    op.execute("DROP TYPE IF EXISTS scan_type_enum")


def downgrade() -> None:
    # Only safe to go back to the enum when every stored value is still one of
    # the three original enum labels. Free-form tool names ("whois", "dns",
    # "port_scan", ...) cannot be coerced into the enum, so refuse loudly.
    connection = op.get_bind()
    values = set(
        connection.execute(sa.text("SELECT DISTINCT scan_type FROM scans")).scalars()
    )
    invalid = values - set(_ENUM_VALUES)
    if invalid:
        raise NotImplementedError(
            "Cannot downgrade scans.scan_type to the default_scan_type_id enum: "
            f"the column contains values not present in the original enum "
            f"('port','web','full'): {sorted(invalid)}. Free-form tool names "
            "cannot be converted back; resolve these rows before downgrading."
        )

    op.execute(
        """
        DO $$ BEGIN
            CREATE TYPE scan_type_enum AS ENUM ('port', 'web', 'full');
        EXCEPTION WHEN duplicate_object THEN null;
        END $$;
        """
    )
    op.execute(
        "ALTER TABLE scans "
        "ALTER COLUMN scan_type TYPE scan_type_enum "
        "USING scan_type::text::scan_type_enum"
    )