"""Unit tests for the keyword mission evaluator (Layer 1)."""

from __future__ import annotations

from datetime import datetime, timezone

from ps.impl.keyword_evaluator import KeywordMissionEvaluator
from ps.models import Mission, MissionState
from ps.service.mission_evaluator import TokenRequestSummary


def _mission(
    description: str,
    *,
    approved_tools: tuple[dict[str, str], ...] | None = None,
) -> Mission:
    return Mission(
        s256="s",
        blob_bytes=b"{}",
        state=MissionState.ACTIVE,
        agent_id="agent",
        approved_at=datetime(2026, 5, 15, tzinfo=timezone.utc),
        owner_id="user",
        approver="http://ps.test",
        description=description,
        approved_tools=approved_tools,
        capabilities=None,
    )


def _req(scope: str | None = None, iss: str | None = None, just: str | None = None) -> TokenRequestSummary:
    return TokenRequestSummary(
        agent_id="agent",
        resource_iss=iss,
        resource_scope=scope,
        justification=just,
    )


def test_allow_when_scope_matches_approved_tool() -> None:
    m = _mission(
        "Search the web for flight options.",
        approved_tools=({"name": "search", "description": "Web search"},),
    )
    d = KeywordMissionEvaluator().evaluate(m, [], _req(scope="search"))
    assert d.decision == "allow"
    assert "approved tool" in d.reason


def test_allow_when_oauth_scope_action_matches_tool() -> None:
    m = _mission(
        "Read calendar to schedule a meeting.",
        approved_tools=({"name": "read", "description": "Read calendar"},),
    )
    d = KeywordMissionEvaluator().evaluate(m, [], _req(scope="calendar:read"))
    assert d.decision == "allow"


def test_allow_when_scope_matches_description_keyword() -> None:
    m = _mission("Plan a Tokyo trip — search flights and hotels.", approved_tools=())
    d = KeywordMissionEvaluator().evaluate(m, [], _req(scope="search"))
    assert d.decision == "allow"


def test_deny_when_mission_forbids_action() -> None:
    m = _mission("Plan a trip. Do not: delete any existing bookings.")
    d = KeywordMissionEvaluator().evaluate(m, [], _req(scope="delete"))
    assert d.decision == "deny"


def test_deny_when_mission_forbids_host() -> None:
    m = _mission("Research only. Never:bank.example.")
    d = KeywordMissionEvaluator().evaluate(m, [], _req(scope="read", iss="https://bank.example"))
    assert d.decision == "deny"


def test_clarify_when_host_known_but_scope_unclear() -> None:
    m = _mission("Plan a trip — use travel.example for itinerary lookups.")
    d = KeywordMissionEvaluator().evaluate(
        m, [], _req(scope="admin", iss="https://travel.example")
    )
    assert d.decision == "clarify"
    assert d.clarification_question is not None
    assert "travel.example" in d.clarification_question


def test_escalate_when_nothing_matches() -> None:
    m = _mission("Plan a Tokyo trip.")
    d = KeywordMissionEvaluator().evaluate(
        m, [], _req(scope="email:send", iss="https://email.example")
    )
    assert d.decision == "escalate"
