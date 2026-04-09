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
