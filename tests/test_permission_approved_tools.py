"""Layer 2: approved-tools gating on POST /permission.

When a permission request carries an active mission, the PS:
- grants immediately if the action is in the mission's ``approved_tools``;
- defers to user consent if the action is outside that list;
- emits matching mission log entries for both paths.
"""

from __future__ import annotations

import re

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
            admin_token=None,
            user_token=None,
        )
    )
    return TestClient(app)


def _s256_from(r) -> str:
    m = re.search(r's256="([^"]+)"', r.headers.get("AAuth-Mission", ""))
    assert m is not None
    return m.group(1)


def _approve_mission(client: TestClient, agent: str, tools: list[dict] | None = None) -> dict:
    body: dict = {"description": "Plan a 3-day Tokyo trip in May."}
    if tools is not None:
        body["tools"] = tools
    r = client.post("/mission", json=body, headers={"X-AAuth-Agent-Id": agent})
    assert r.status_code == 200, r.text
    return {"approver": r.json()["approver"], "s256": _s256_from(r)}


def test_permission_granted_when_action_in_approved_tools(client: TestClient) -> None:
    ref = _approve_mission(
        client,
        "agent-a",
        tools=[{"name": "WebSearch", "description": "Search the web"}],
    )
    r = client.post(
        "/permission",
        json={"action": "WebSearch", "mission": ref},
        headers={"X-AAuth-Agent-Id": "agent-a"},
    )
    assert r.status_code == 200
    assert r.json() == {"permission": "granted"}

    log = client.get(f"/missions/{ref['s256']}").json()["log"]
    perms = [e for e in log if e["kind"] == "permission"]
    assert perms[-1]["payload"]["result"] == "granted"
    assert perms[-1]["payload"]["decided_by"] == "approved_tools"


def test_permission_deferred_when_action_outside_approved_tools(client: TestClient) -> None:
    ref = _approve_mission(
        client,
        "agent-b",
        tools=[{"name": "WebSearch", "description": "Search the web"}],
    )
    r = client.post(
        "/permission",
        json={
            "action": "SendEmail",
            "description": "Email the itinerary to the user",
            "parameters": {"to": "user@example.com"},
            "mission": ref,
        },
        headers={"X-AAuth-Agent-Id": "agent-b"},
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["requirement"] == "interaction"
    assert body["code"]
    assert body["pending_url"].startswith("http://test.example/pending/")

    log = client.get(f"/missions/{ref['s256']}").json()["log"]
    deferred = [e for e in log if e["kind"] == "permission" and e["payload"].get("result") == "deferred"]
    assert deferred, log
    assert deferred[-1]["payload"]["decided_by"] == "user_pending"


def test_permission_no_mission_grants_unconditionally(client: TestClient) -> None:
    r = client.post(
        "/permission",
        json={"action": "AnyTool"},
        headers={"X-AAuth-Agent-Id": "agent-c"},
    )
    assert r.status_code == 200
    assert r.json() == {"permission": "granted"}


def test_permission_user_approves_then_polled_terminal(client: TestClient) -> None:
    """User approves at consent UI → agent polls /pending → 200 with {permission:granted}."""
    ref = _approve_mission(
        client,
        "agent-d",
        tools=[{"name": "WebSearch", "description": "Search the web"}],
    )
    r = client.post(
        "/permission",
        json={"action": "BookFlight", "description": "Book TYO flight", "mission": ref},
        headers={"X-AAuth-Agent-Id": "agent-d"},
    )
    assert r.status_code == 202
    body = r.json()
    pid = body["pending_id"]
    code = body["code"]

    # Land on consent page to get context.
    cr = client.get(f"/consent?code={code}")
    assert cr.status_code == 200
    ctx = cr.json()
    assert ctx["pending_kind"] == "permission"
    assert ctx["permission_action"] == "BookFlight"
    assert ctx["permission_description"] == "Book TYO flight"
    assert ctx["mission"]["s256"] == ref["s256"]

    # User approves.
    dr = client.post(f"/consent/{pid}/decision", json={"approved": True})
    assert dr.status_code == 200

    # Agent polls — terminal body has the decision.
    pr = client.get(f"/pending/{pid}", headers={"X-AAuth-Agent-Id": "agent-d"})
    assert pr.status_code == 200
    assert pr.json() == {"permission": "granted"}

    log = client.get(f"/missions/{ref['s256']}").json()["log"]
    decisions = [
        e for e in log if e["kind"] == "permission" and e["payload"].get("decided_by") == "user"
    ]
    assert decisions, log
    assert decisions[-1]["payload"]["result"] == "granted"


def test_permission_user_denies_then_polled_terminal(client: TestClient) -> None:
    ref = _approve_mission(client, "agent-e", tools=[])
    r = client.post(
        "/permission",
        json={"action": "DeleteAccount", "mission": ref},
        headers={"X-AAuth-Agent-Id": "agent-e"},
    )
    assert r.status_code == 202
    body = r.json()
    pid = body["pending_id"]

    dr = client.post(f"/consent/{pid}/decision", json={"approved": False})
    assert dr.status_code == 200

    pr = client.get(f"/pending/{pid}", headers={"X-AAuth-Agent-Id": "agent-e"})
    assert pr.status_code == 200
    assert pr.json() == {"permission": "denied"}

    log = client.get(f"/missions/{ref['s256']}").json()["log"]
    user_decisions = [
        e for e in log if e["kind"] == "permission" and e["payload"].get("decided_by") == "user"
    ]
    assert user_decisions[-1]["payload"]["result"] == "denied"


def test_permission_on_terminated_mission_returns_mission_terminated(client: TestClient) -> None:
    ref = _approve_mission(client, "agent-f", tools=[])
    client.patch(f"/missions/{ref['s256']}", json={"state": "terminated"})
    r = client.post(
        "/permission",
        json={"action": "WebSearch", "mission": ref},
        headers={"X-AAuth-Agent-Id": "agent-f"},
    )
    assert r.status_code == 403
    assert r.json()["error"] == "mission_terminated"
