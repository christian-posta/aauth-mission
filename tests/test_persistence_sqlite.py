"""Integration smoke tests with SQLite-backed PS + AS via unified schema."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from ps.http.app import create_app
from ps.http.config import PSHttpSettings


def test_create_app_persisted_mission_list_empty() -> None:
    app = None
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "t.db"
        url = f"sqlite:///{db_path}"
        os.environ["AAUTH_DATABASE_URL"] = url
        try:
            app = create_app(
                PSHttpSettings(
                    public_origin="http://test",
                    admin_token="adm",
                    database_url=url,
                    insecure_dev=True,
                )
            )
            c = TestClient(app)
            r = c.get("/missions", headers={"Authorization": "Bearer adm"})
            assert r.status_code == 200
            assert r.json() == []
        finally:
            os.environ.pop("AAUTH_DATABASE_URL", None)
            if app is not None:
                eng = getattr(app.state, "db_engine", None)
                if eng is not None:
                    eng.dispose()


def test_portal_persisted_starts() -> None:
    from portal.http.app import create_portal_app

    app = None
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "p.db"
        url = f"sqlite:///{db_path}"
        os.environ["AAUTH_DATABASE_URL"] = url
        try:
            app = create_portal_app(
                PSHttpSettings(
                    public_origin="http://test",
                    database_url=url,
                    insecure_dev=True,
                )
            )
            c = TestClient(app)
            r = c.get("/.well-known/aauth-person.json")
            assert r.status_code == 200
        finally:
            os.environ.pop("AAUTH_DATABASE_URL", None)
            if app is not None:
                eng = getattr(app.state, "db_engine", None)
                if eng is not None:
                    eng.dispose()
