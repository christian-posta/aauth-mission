"""Create all tables from SQLAlchemy models (unified PS + AS schema)."""

from __future__ import annotations

from alembic import op

import persistence.models  # noqa: F401
from persistence.base import Base

revision = "001_initial_unified"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    assert bind is not None
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    bind = op.get_bind()
    assert bind is not None
    Base.metadata.drop_all(bind=bind)
