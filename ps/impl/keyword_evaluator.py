"""Deterministic keyword-based mission evaluator (Layer 1 default).

Decision policy:

1. If the mission description carries an explicit deny token (e.g. ``deny:delete``,
   ``never:write``) and the request scope or issuer matches, return ``deny``.
2. If the request scope overlaps with the mission's ``approved_tools`` names or with
   keywords extracted from the mission description, return ``allow``.
3. If the mission description contains the issuer host but no scope-level overlap, return
   ``clarify`` with a focused question.
4. Otherwise, ``escalate`` — fall through to user consent.

This is intentionally simple. It exists to demonstrate the architecture and to give the
demo crisp, predictable outcomes. Production deployments would replace this with an LLM-
backed evaluator or a policy engine.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ps.models import Mission, MissionLogEntry
from ps.service.mission_evaluator import EvaluationDecision, TokenRequestSummary

_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_-]{1,}", re.IGNORECASE)
_DENY_RE = re.compile(r"\b(?:deny|never|do\s+not|forbid)\s*[:\-]?\s*([a-z0-9_:.-]+)", re.IGNORECASE)


def _tokens(text: str | None) -> set[str]:
    if not text:
        return set()
    return {t.lower() for t in _TOKEN_RE.findall(text)}


def _scope_tokens(scope: str | None) -> set[str]:
    if not scope:
        return set()
    out: set[str] = set()
    for s in scope.split():
        out.add(s.lower())
        # OAuth-style "namespace:action" — also index the action half.
        if ":" in s:
            out.add(s.split(":", 1)[1].lower())
    return out


def _host(url: str | None) -> str | None:
    if not url:
        return None
    try:
        h = urlparse(url).hostname
    except ValueError:
        return None
    return h.lower() if h else None


class KeywordMissionEvaluator:
    """Heuristic evaluator using simple token overlap rules.

    The rules are deliberately readable — every decision carries a human-comprehensible
    reason. The demo and tests rely on that determinism.
    """

    def evaluate(
        self,
        mission: Mission,
        log: list[MissionLogEntry],  # noqa: ARG002 — log is part of the interface for future evaluators
        request: TokenRequestSummary,
    ) -> EvaluationDecision:
        desc = mission.description or ""
        desc_tokens = _tokens(desc)
        scope_tokens = _scope_tokens(request.resource_scope)
        host = _host(request.resource_iss)

        # 1. Explicit deny tokens in the mission description.
        for match in _DENY_RE.finditer(desc):
            forbidden = match.group(1).lower().rstrip(".:-_")
            if not forbidden:
                continue
            if forbidden in scope_tokens:
                return EvaluationDecision.deny(
                    f"mission explicitly forbids '{forbidden}' (matched scope)"
                )
            if host and (forbidden == host or forbidden in host.split(".")):
                return EvaluationDecision.deny(
                    f"mission explicitly forbids '{forbidden}' (matched resource host)"
                )

        approved_tool_names = {
            t.get("name", "").lower()
            for t in (mission.approved_tools or ())
            if isinstance(t, dict)
        }
        approved_tool_names.discard("")

        # 2. Allow when scope or tool name overlaps the mission's pre-approved tools
        #    or appears in the mission description.
        if scope_tokens & approved_tool_names:
            hit = next(iter(scope_tokens & approved_tool_names))
            return EvaluationDecision.allow(
                f"requested scope '{hit}' matches an approved tool"
            )
        if scope_tokens & desc_tokens:
            hit = next(iter(scope_tokens & desc_tokens))
            return EvaluationDecision.allow(
                f"requested scope '{hit}' appears in the mission description"
            )

        # 3. Issuer host (or any of its labels) known to mission but no scope overlap —
        #    ask the agent.
        host_labels = set(host.split(".")) if host else set()
        if host_labels & desc_tokens:
            return EvaluationDecision.clarify(
                f"The mission mentions {host} but the requested scope "
                f"'{request.resource_scope or '(none)'}' is not obviously in bounds. "
                "Clarify how this call advances the mission.",
                reason="host known, scope unclear",
            )

        # 4. Nothing matches — fall through to user consent with the reason shown.
        return EvaluationDecision.escalate(
            f"no overlap between mission scope and request "
            f"(resource={host or request.resource_iss or 'unknown'}, "
            f"scope={request.resource_scope or '(none)'})"
        )
