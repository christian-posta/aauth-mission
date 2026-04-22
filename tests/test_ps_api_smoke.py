"""Smoke tests for the Person Server HTTP API (in-memory)."""

from __future__ import annotations

import json
import re

import aauth
import pytest
from fastapi.testclient import TestClient

from ps.http.app import create_app
from ps.http.config import PSHttpSettings


@pytest.fixture
def client() -> TestClient:
    app = create_app(
        PSHttpSettings(
            insecure_dev=True,
            public_origin="http://test.example",
            auto_approve_token=False,
        )
    )
    return TestClient(app)


def _sign_post(path: str, body: dict, private_key) -> tuple[bytes, dict[str, str]]:
    body_bytes = json.dumps(body).encode("utf-8")
    target = f"http://testserver{path}"
    h = aauth.sign_request(
        "POST",
        target,
        {"Host": "testserver", "Content-Type": "application/json"},
        body_bytes,
        private_key=private_key,
        sig_scheme="hwk",
    )
    merged = dict(h)
    merged["Content-Type"] = "application/json"
    return body_bytes, merged


def test_well_known_metadata(client: TestClient) -> None:
    r = client.get("/.well-known/aauth-person.json")
    assert r.status_code == 200
    data = r.json()
    assert data["issuer"] == "http://test.example"
    assert data["token_endpoint"] == "http://test.example/token"
    assert data["mission_endpoint"] == "http://test.example/mission"
    assert data["permission_endpoint"] == "http://test.example/permission"


def _s256_from_mission_response(r) -> str:
    m = re.search(r's256="([^"]+)"', r.headers.get("AAuth-Mission", ""))
    assert m is not None
    return m.group(1)


def test_mission_create(client: TestClient) -> None:
    r = client.post(
        "/mission",
        json={"description": "# Test\n\nDo something."},
        headers={"X-AAuth-Agent-Id": "agent-1"},
    )
    assert r.status_code == 200
    assert "AAuth-Mission" in r.headers
    blob = r.json()
    assert "approver" in blob and "description" in blob
    _s256_from_mission_response(r)


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

    r_ctx = client.get("/consent", params={"code": code})
    assert r_ctx.status_code == 200
    jctx = r_ctx.json()
    assert "mission" in jctx and jctx["mission"] is None
    assert jctx.get("pending_kind") == "token"
    pending_id = jctx["pending_id"]

    r_dec = client.post(
        f"/consent/{pending_id}/decision",
        json={"approved": True},
    )
    assert r_dec.status_code == 200
    assert r_dec.json() == {}

    loc = r.headers["Location"]
    r_poll = client.get(loc, headers={"X-AAuth-Agent-Id": "agent-1"})
    assert r_poll.status_code == 200
    body = r_poll.json()
    assert "auth_token" in body and "expires_in" in body

    r_poll2 = client.get(loc, headers={"X-AAuth-Agent-Id": "agent-1"})
    assert r_poll2.status_code == 404
    err = r_poll2.json()
    assert err.get("error") == "invalid_request"


def test_consent_includes_mission_for_deferred_token_with_mission(client: TestClient) -> None:
    r0 = client.post(
        "/mission",
        json={"description": "# Consent test\n\nM body"},
        headers={"X-AAuth-Agent-Id": "ag-mix"},
    )
    assert r0.status_code == 200
    blob = r0.json()
    assert "approver" in blob
    s256 = _s256_from_mission_response(r0)
    r = client.post(
        "/token",
        json={"resource_token": "fake-resource-jwt", "mission": {"approver": blob["approver"], "s256": s256}},
        headers={"X-AAuth-Agent-Id": "ag-mix"},
    )
    assert r.status_code == 202
    req_hdr = r.headers.get("AAuth-Requirement", "")
    m = re.search(r'code="([^"]+)"', req_hdr)
    assert m
    r_ctx = client.get("/consent", params={"code": m.group(1)})
    assert r_ctx.status_code == 200
    data = r_ctx.json()
    assert data.get("pending_kind") == "token"
    assert data.get("mission") is not None
    assert data["mission"]["s256"] == s256
    assert "description" in data["mission"] or "state" in data["mission"]


def test_post_token_hwk_signed(client: TestClient) -> None:
    app = create_app(PSHttpSettings(insecure_dev=False, public_origin="http://test.example", auto_approve_token=True))
    c = TestClient(app)
    pk, _pub = aauth.generate_ed25519_keypair()
    body_bytes, hdrs = _sign_post("/token", {"resource_token": "x"}, pk)
    r = c.request("POST", "/token", content=body_bytes, headers=hdrs)
    assert r.status_code == 200
    assert "auth_token" in r.json()


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
        PSHttpSettings(
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
        json={"description": "# Owned\n\nMission text.", "owner_hint": "alice"},
        headers={"X-AAuth-Agent-Id": "agent-owned"},
    )
    assert r.status_code == 200
    s256 = _s256_from_mission_response(r)

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
    r_gone = client.get(loc, headers={"X-AAuth-Agent-Id": "agent-1"})
    assert r_gone.status_code == 410
    assert r_gone.json().get("error") == "invalid_code"


def test_mission_invalid_state_transition(client: TestClient) -> None:
    r = client.post(
        "/mission",
        json={"description": "# X\n\nY"},
        headers={"X-AAuth-Agent-Id": "agent-1"},
    )
    assert r.status_code == 200
    s256 = _s256_from_mission_response(r)
    r2 = client.patch(f"/missions/{s256}", json={"state": "terminated"})
    assert r2.status_code == 200
    r3 = client.patch(f"/missions/{s256}", json={"state": "terminated"})
    assert r3.status_code == 400


def test_interaction_code_reusable_while_pending(client: TestClient) -> None:
    """The code stays valid for page reloads until the pending row is resolved."""
    r = client.post(
        "/token",
        json={"resource_token": "jwt"},
        headers={"X-AAuth-Agent-Id": "agent-1"},
    )
    assert r.status_code == 202
    req_hdr = r.headers.get("AAuth-Requirement", "")
    m = re.search(r'code="([^"]+)"', req_hdr)
    assert m
    code = m.group(1)
    # First load — should succeed.
    r1 = client.get("/consent", params={"code": code})
    assert r1.status_code == 200
    pid = r1.json()["pending_id"]
    # Second load (page reload) — must also succeed while the row is still open.
    r2 = client.get("/consent", params={"code": code})
    assert r2.status_code == 200
    # After the decision is posted, the code must be invalidated.
    client.post(f"/consent/{pid}/decision", json={"approved": True})
    r3 = client.get("/consent", params={"code": code})
    assert r3.status_code == 410


def test_clarification_round_limit(client: TestClient) -> None:
    r = client.post(
        "/token",
        json={"resource_token": "jwt"},
        headers={"X-AAuth-Agent-Id": "agent-1"},
    )
    assert r.status_code == 202
    loc = r.headers["Location"]
    pid = loc.strip("/").split("/")[-1]
    for _ in range(5):
        pr = client.post(
            loc,
            json={"clarification_response": "answer"},
            headers={"X-AAuth-Agent-Id": "agent-1"},
        )
        assert pr.status_code == 202
    pr6 = client.post(
        loc,
        json={"clarification_response": "too many"},
        headers={"X-AAuth-Agent-Id": "agent-1"},
    )
    assert pr6.status_code == 400
    assert pr6.json().get("error") == "invalid_request"


def test_permission_and_audit(client: TestClient) -> None:
    mr = client.post(
        "/mission",
        json={"description": "Demo"},
        headers={"X-AAuth-Agent-Id": "a1"},
    )
    m = mr.json()
    ref = {"approver": m["approver"], "s256": _s256_from_mission_response(mr)}
    r = client.post(
        "/permission",
        json={"action": "WebSearch", "mission": ref},
        headers={"X-AAuth-Agent-Id": "a1"},
    )
    assert r.status_code == 200
    assert r.json()["permission"] == "granted"
    ra = client.post(
        "/audit",
        json={"mission": ref, "action": "WebSearch", "result": {"ok": True}},
        headers={"X-AAuth-Agent-Id": "a1"},
    )
    assert ra.status_code == 201


def test_mission_terminated_on_token(client: TestClient) -> None:
    mr = client.post(
        "/mission",
        json={"description": "X"},
        headers={"X-AAuth-Agent-Id": "a2"},
    )
    m = mr.json()
    s256 = _s256_from_mission_response(mr)
    ref = {"approver": m["approver"], "s256": s256}
    client.patch(f"/missions/{s256}", json={"state": "terminated"})
    r = client.post(
        "/token",
        json={"resource_token": "jwt", "mission": ref},
        headers={"X-AAuth-Agent-Id": "a2"},
    )
    assert r.status_code == 403
    assert r.json()["error"] == "mission_terminated"
