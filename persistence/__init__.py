"""Single-database persistence for Person Server, Agent Server, and Portal.

Set ``AAUTH_DATABASE_URL`` or ``PSHttpSettings.database_url`` / ``AgentServerSettings.database_url``
to a SQLAlchemy URL, for example:

- ``sqlite:////var/lib/aauth/app.db`` (SQLite file; four slashes for absolute path)
- ``postgresql+psycopg://user:pass@localhost:5432/aauth`` (PostgreSQL; install ``psycopg[binary]``)

Tables are created with ``from persistence.wiring import init_db`` (called on app startup), or via ``alembic upgrade head``.
"""

from __future__ import annotations

from persistence.engine import create_session_factory, make_engine

__all__ = ["create_session_factory", "make_engine"]
