"""Map domain models to protocol-shaped JSON."""

from __future__ import annotations

from mm.models import AuthTokenResponse, ConsentContext, DeferredResponse, Mission, MissionState


def mission_http_dict(m: Mission) -> dict[str, object]:
    return {"s256": m.s256, "approved": m.approved_text}


def auth_token_http_dict(a: AuthTokenResponse) -> dict[str, object]:
    return {"auth_token": a.auth_token, "expires_in": a.expires_in}


def consent_context_http_dict(c: ConsentContext) -> dict[str, object]:
    payload: dict[str, object] = {
        "pending_id": c.pending_id,
        "scopes": c.scopes,
    }
    if c.resource_name is not None:
        payload["resource_name"] = c.resource_name
    if c.justification is not None:
        payload["justification"] = c.justification
    if c.agent_name is not None:
        payload["agent_name"] = c.agent_name
    if c.mission is not None:
        payload["mission"] = mission_http_dict(c.mission)
    return payload


def deferred_body_dict(d: DeferredResponse) -> dict[str, object]:
    body: dict[str, object] = {"status": d.status.value}
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
