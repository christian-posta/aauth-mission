# Database and unified persistence

This project can run with **in-memory** state (default) or with a **single SQL database** shared by the Person Server (PS), Agent Server (AS), and Portal. One SQLAlchemy engine and one schema hold missions, pending flows, trust entries, agent registrations, and bindings.

## What is stored

| Area | Tables (prefix) | Notes |
|------|-----------------|--------|
| Person Server | `ps_mission`, `ps_mission_log`, `ps_pending`, `ps_trusted_agent_server` | Missions, mission logs, deferred/consent pending rows, trusted agent-server issuers |
| Agent Server | `as_pending_registration`, `as_binding`, `as_binding_jkt` | Registration flow and stable-key bindings |
| Trust registry | `ps_trusted_agent_server` | Replaces or supplements the JSON trust file when using SQL |

**Not** persisted in the database: HTTP signature **replay protection** remains an in-process cache (`ReplayCache`), as in the in-memory reference implementation.

## Enabling persistence

Set a SQLAlchemy URL using **any** of these (first non-empty value wins where the app checks multiple sources):

1. **Environment variable (recommended for ops)**  
   `AAUTH_DATABASE_URL`

2. **Person Server**  
   `AAUTH_PS_DATABASE_URL` maps to `PSHttpSettings.database_url` (Pydantic field `database_url` under prefix `AAUTH_PS_`).

3. **Agent Server (standalone)**  
   `AAUTH_AS_DATABASE_URL` maps to `AgentServerSettings.database_url`.

4. **Programmatic**  
   Pass `database_url=...` into `PSHttpSettings` / `AgentServerSettings` when constructing settings.

If **no** database URL is set, apps use the original in-memory `build_memory_ps` / `build_memory_as` wiring.

## SQLite (typical for local dev)

Use a **file** URL. For an absolute path, SQLAlchemy expects **four** slashes after `sqlite:`:

```bash
export AAUTH_DATABASE_URL='sqlite:////absolute/path/to/aauth.db'
```

Examples:

```bash
# macOS / Linux – database file in your home directory
export AAUTH_DATABASE_URL='sqlite:////Users/you/.aauth/app.db'

# Relative path (three slashes) – file is relative to the process working directory
export AAUTH_DATABASE_URL='sqlite:///./.aauth/app.db'
```

On startup, the apps call `init_db()` from `persistence.wiring`, which runs `Base.metadata.create_all(...)` so tables exist without a separate manual step (useful for development).

## PostgreSQL

1. Install the optional extra (driver):

   ```bash
   pip install 'aauth-person-server[database]'
   ```

   or add `psycopg[binary]` to your environment (see `pyproject.toml` optional dependency `database`).

2. Use a sync SQLAlchemy URL with **psycopg v3**:

   ```bash
   export AAUTH_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE'
   ```

3. Prefer **`alembic upgrade head`** in production (see below) so schema changes are tracked; `init_db()` is still convenient for quick starts.

## Portal (PS + AS on one origin)

The portal uses **one** database URL for **both** Person Server and Agent Server state. Set either:

- `AAUTH_DATABASE_URL`, or  
- `database_url` on `PSHttpSettings` **or** `AgentServerSettings` (both are read; if both are set, prefer being consistent).

The same engine backs `build_persisted_ps` and `build_persisted_as`.

## Trust list and JSON migration

If you previously used `AAUTH_PS_TRUST_FILE` (default `.aauth/ps-trusted-agents.json`), the SQL trust registry can **import** that file **once** when the `ps_trusted_agent_server` table is empty. This is done in `build_persisted_ps` via `import_trust_from_file_if_empty` in `persistence/trust_db.py`. After data lives in the database, manage trust through the API as usual.

## Alembic migrations

- Config: `alembic.ini`, `alembic/env.py`
- Initial revision: `alembic/versions/001_initial_unified.py` (creates all tables from the shared `Base.metadata`).

Run migrations (set the same URL you use at runtime):

```bash
export AAUTH_DATABASE_URL='sqlite:////path/to/aauth.db'   # or your Postgres URL
alembic upgrade head
```

`alembic/env.py` reads `AAUTH_DATABASE_URL`; if unset, it defaults to `sqlite:///./.aauth/alembic-dev.db`.

To create a new revision after model changes, use autogenerate against a real database (your driver must be installed), then review the generated script.

## Shutting down

When a database URL is used, the FastAPI apps register a lifespan handler that **`dispose()`**s the SQLAlchemy engine on shutdown so connection pools close cleanly.

## Quick reference

| Topic | Location |
|-------|----------|
| ORM models | `persistence/models.py` |
| Engine / session factory | `persistence/engine.py` |
| `init_db`, `build_persisted_ps`, `build_persisted_as` | `persistence/wiring.py` |
| PS HTTP settings | `ps/http/config.py` (`database_url`) |
| AS HTTP settings | `agent_server/http/config.py` (`database_url`) |
| App wiring (when URL set) | `ps/http/app.py`, `agent_server/http/app.py`, `portal/http/app.py` |

For code-level notes, see the docstring in `persistence/__init__.py`.
