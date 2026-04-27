"""Add ps_issued_token table for auth token audit log."""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "002_add_issued_tokens"
down_revision = "001_initial_unified"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ps_issued_token",
        sa.Column("issued_id", sa.String(64), primary_key=True),
        sa.Column("agent_id", sa.String(512), nullable=False, index=True),
        sa.Column("owner_id", sa.String(256), nullable=True, index=True),
        sa.Column("resource_iss", sa.String(1024), nullable=True),
        sa.Column("resource_scope", sa.Text, nullable=True),
        sa.Column("justification", sa.Text, nullable=True),
        sa.Column("issue_method", sa.String(32), nullable=False),
        sa.Column("token_jti", sa.String(256), nullable=True),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("ps_issued_token")
