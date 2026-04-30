"""Map domain models to protocol-shaped JSON."""

from __future__ import annotations

import json

from ps.models import AuthTokenResponse, ConsentContext, DeferredResponse, Mission, MissionState


def mission_list_dict(m: Mission) -> dict[str, object]:
    base = json.loads(m.blob_bytes.decode("utf-8"))
    assert isinstance(base, dict)
    out: dict[str, object] = dict(base)
    out["s256"] = m.s256
    out["state"] = m.state.value
    out["owner_id"] = m.owner_id
    return out


def mission_detail_dict(m: Mission) -> dict[str, object]:
    return {"mission": mission_list_dict(m)}


def auth_token_http_dict(a: AuthTokenResponse) -> dict[str, object]:
    return {"auth_token": a.auth_token, "expires_in": a.expires_in}


def consent_context_http_dict(c: ConsentContext) -> dict[str, object]:
    payload: dict[str, object] = {
        "pending_id": c.pending_id,
        "scopes": c.scopes,
        "mission": mission_list_dict(c.mission) if c.mission is not None else None,
    }
    if c.pending_kind is not None:
        payload["pending_kind"] = c.pending_kind
    if c.resource_name is not None:
        payload["resource_name"] = c.resource_name
    if c.justification is not None:
        payload["justification"] = c.justification
    if c.agent_name is not None:
        payload["agent_name"] = c.agent_name
    if c.clarification_responses:
        payload["clarification_responses"] = list(c.clarification_responses)
    if c.interaction_type is not None:
        payload["interaction_type"] = c.interaction_type
    if c.summary is not None:
        payload["summary"] = c.summary
    if c.question is not None:
        payload["question"] = c.question
    if c.resource_iss is not None:
        payload["resource_iss"] = c.resource_iss
    if c.resource_scope is not None:
        payload["resource_scope"] = c.resource_scope
    if c.resource_mission_s256 is not None:
        payload["resource_mission_s256"] = c.resource_mission_s256
    return payload


def deferred_body_dict(d: DeferredResponse) -> dict[str, object]:
    """JSON body for 202 deferred responses.

    Clients such as ``aauth.agent.poller`` read ``requirement`` and ``code`` from the
    body to drive callbacks (not only from ``AAuth-Requirement``). Omitting them
    breaks interaction/consent flows even when headers are correct.
    """
    body: dict[str, object] = {"status": d.status.value}
    if d.requirement is not None:
        body["requirement"] = d.requirement.value
    if d.code is not None:
        body["code"] = d.code
    if d.interaction_url is not None:
        body["interaction_url"] = d.interaction_url
    if d.retry_after is not None:
        body["retry_after"] = d.retry_after
    if d.pending_id:
        body["pending_id"] = d.pending_id
    if d.pending_url:
        body["pending_url"] = d.pending_url
    if d.clarification is not None:
        body["clarification"] = d.clarification
    if d.timeout is not None:
        body["timeout"] = d.timeout
    if d.options is not None:
        body["options"] = d.options
    return body


def build_aauth_requirement_header(d: DeferredResponse) -> str | None:
    if d.requirement is None:
        return None
    parts = [f"requirement={d.requirement.value}"]
    if d.interaction_url and d.code:
        parts.append(f'url="{d.interaction_url}"')
        parts.append(f'code="{d.code}"')
    return "; ".join(parts)


def mission_state_from_query(raw: str | None) -> MissionState | None:
    if raw is None or raw == "":
        return None
    return MissionState(raw)
