"""Smoke tests for the MM HTTP API (in-memory)."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from mm.http.app import create_app
from mm.http.config import MMHttpSettings


@pytest.fixture
def client() -> TestClient:
    app = create_app(
        MMHttpSettings(
            insecure_dev=True,
            public_origin="http://test.example",
            auto_approve_token=False,
        )
    )
    return TestClient(app)


def test_well_known_metadata(client: TestClient) -> None:
    r = client.get("/.well-known/aauth-mission.json")
    assert r.status_code == 200
    data = r.json()
    assert data["manager"] == "http://test.example"
    assert data["token_endpoint"] == "http://test.example/token"
    assert data["mission_endpoint"] == "http://test.example/mission"


def test_mission_create(client: TestClient) -> None:
    r = client.post(
        "/mission",
        json={"mission_proposal": "# Test\n\nDo something."},
        headers={"X-AAuth-Agent-Id": "agent-1"},
    )
    assert r.status_code == 200
    m = r.json()["mission"]
    assert "s256" in m and "approved" in m


def test_token_defer_consent_flow(client: TestClient) -> None:
    r = client.post(
        "/token",
        json={"resource_token": "fake-resource-jwt"},
        headers={"X-AAuth-Agent-Id": "agent-1"},
    )
    assert r.status_code == 202
    assert r.headers.get("Cache-Control") == "no-store"
    assert "Location" in r.headers
    assert r.json()["status"] == "pending"

    req_hdr = r.headers.get("AAuth-Requirement", "")
    m = re.search(r'code="([^"]+)"', req_hdr)
    assert m is not None, req_hdr
    code = m.group(1)

    r_ctx = client.get("/interaction", params={"code": code})
    assert r_ctx.status_code == 200
    pending_id = r_ctx.json()["pending_id"]

    r_dec = client.post(
        f"/interaction/{pending_id}/decision",
        json={"approved": True},
    )
    assert r_dec.status_code == 204

    r_poll = client.get(r.headers["Location"])
    assert r_poll.status_code == 200
    body = r_poll.json()
    assert "auth_token" in body and "expires_in" in body


def test_admin_pending_lists_open_token(client: TestClient) -> None:
    r = client.post(
        "/token",
        json={"resource_token": "jwt"},
        headers={"X-AAuth-Agent-Id": "agent-1"},
    )
    assert r.status_code == 202
    pending_id = r.headers["Location"].strip("/").split("/")[-1]
    r2 = client.get("/admin/pending")
    assert r2.status_code == 200
    rows = r2.json()
    assert len(rows) == 1
    assert rows[0]["pending_id"] == pending_id
    assert rows[0]["kind"] == "token"
    assert rows[0]["agent_id"] == "agent-1"
    assert rows[0]["requirement"] == "interaction"
    assert rows[0]["code"]


def test_user_api_not_configured(client: TestClient) -> None:
    r = client.get("/user/missions", headers={"Authorization": "Bearer x"})
    assert r.status_code == 503


def test_user_missions_owner_and_consent(client: TestClient) -> None:
    app = create_app(
        MMHttpSettings(
            insecure_dev=True,
            public_origin="http://test.example",
            auto_approve_token=False,
            user_token="user-secret",
            user_id="alice",
        )
    )
    c = TestClient(app)
    r = c.post(
        "/mission",
        json={"mission_proposal": "# Owned\n\nMission text.", "owner_hint": "alice"},
        headers={"X-AAuth-Agent-Id": "agent-owned"},
    )
    assert r.status_code == 200
    s256 = r.json()["mission"]["s256"]

    r_list = c.get("/user/missions", headers={"Authorization": "Bearer user-secret"})
    assert r_list.status_code == 200
    rows = r_list.json()
    assert len(rows) == 1
    assert rows[0]["s256"] == s256
    assert rows[0]["owner_id"] == "alice"

    r_tok = c.post(
        "/token",
        json={"resource_token": "jwt"},
        headers={"X-AAuth-Agent-Id": "agent-owned"},
    )
    assert r_tok.status_code == 202
    req_hdr = r_tok.headers.get("AAuth-Requirement", "")
    m = re.search(r'code="([^"]+)"', req_hdr)
    assert m is not None
    code = m.group(1)

    r_cq = c.get("/user/consent", headers={"Authorization": "Bearer user-secret"})
    assert r_cq.status_code == 200
    queue = r_cq.json()
    assert len(queue) == 1
    assert queue[0]["code"] == code


def test_pending_gone_after_delete(client: TestClient) -> None:
    r = client.post(
        "/token",
        json={"resource_token": "x"},
        headers={"X-AAuth-Agent-Id": "agent-1"},
    )
    assert r.status_code == 202
    loc = r.headers["Location"]
    r_del = client.delete(loc, headers={"X-AAuth-Agent-Id": "agent-1"})
    assert r_del.status_code == 204
    r_gone = client.get(loc)
    assert r_gone.status_code == 410
