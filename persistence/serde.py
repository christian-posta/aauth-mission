"""JSON-safe serialization for domain types stored in the database."""

from __future__ import annotations

import base64
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, cast

from ps.impl.backend import PendingRecord
from ps.models import (
    AuthTokenResponse,
    InteractionTerminalResult,
    Mission,
    MissionLogEntry,
    MissionProposal,
    MissionRef,
    MissionState,
    PendingStatus,
    RequirementLevel,
    TokenRequest,
    ToolSpec,
)


def _walk_encode(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, bytes):
        return {"__b64__": base64.b64encode(obj).decode("ascii")}
    if isinstance(obj, datetime):
        return {"__dt__": obj.isoformat()}
    if isinstance(obj, Enum):
        return {"__E__": obj.__class__.__name__, "v": obj.value}
    if isinstance(obj, dict):
        return {k: _walk_encode(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_walk_encode(x) for x in obj]
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, (Mission, TokenRequest, MissionProposal, AuthTokenResponse, MissionRef, ToolSpec)):
        return _walk_encode(asdict(obj))
    return _walk_encode(asdict(obj)) if hasattr(obj, "__dataclass_fields__") else str(obj)


def _walk_decode(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        if set(obj.keys()) == {"__b64__"}:
            return base64.b64decode(obj["__b64__"])
        if set(obj.keys()) == {"__dt__"}:
            s = str(obj["__dt__"])
            dtp = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if dtp.tzinfo is None:
                dtp = dtp.replace(tzinfo=timezone.utc)
            return dtp
        if set(obj.keys()) == {"__E__", "v"}:
            name, val = str(obj["__E__"]), obj["v"]
            m = {
                "PendingStatus": PendingStatus,
                "RequirementLevel": RequirementLevel,
                "MissionState": MissionState,
            }
            if name in m:
                return m[name](val)  # type: ignore[operator,arg-type]
            from ps.models import MissionLogKind

            if name == "MissionLogKind":
                from ps.models import MissionLogKind as MLK
                return MLK(val)  # type: ignore[return-value,arg-type]
        return {k: _walk_decode(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_decode(x) for x in obj]
    return obj


def _tr_from(d: Any) -> TokenRequest:
    d = _walk_decode(d) if not isinstance(d, dict) or "__b64__" in str(d) else d
    d = cast(dict[str, Any], d)
    m = d.get("mission")
    mref: MissionRef | None = None
    if m is not None and isinstance(m, dict):
        m2 = m
        if m2.get("approver") is not None and m2.get("s256") is not None:
            mref = MissionRef(approver=str(m2["approver"]), s256=str(m2["s256"]))
    return TokenRequest(
        agent_id=str(d["agent_id"]),
        resource_token=str(d["resource_token"]),
        justification=d.get("justification"),
        upstream_token=d.get("upstream_token"),
        login_hint=d.get("login_hint"),
        tenant=d.get("tenant"),
        domain_hint=d.get("domain_hint"),
        mission=mref,
        agent_cnf_jwk=cast(Any, d.get("agent_cnf_jwk")),
        agent_jkt=d.get("agent_jkt"),
        secure_mode=bool(d.get("secure_mode", True)),
    )


def _mp_from(d: Any) -> MissionProposal:
    d = _walk_decode(d)
    d = cast(dict[str, Any], d)
    tools: list[dict[str, str]] = cast(Any, d.get("tools") or [])
    tups: tuple[ToolSpec, ...] = tuple(
        ToolSpec(name=str(t["name"]), description=str(t["description"])) for t in tools
    )
    return MissionProposal(
        agent_id=str(d["agent_id"]),
        description=str(d["description"]),
        tools=tups,
        owner_hint=d.get("owner_hint"),
    )


def _mission_from(d: Any) -> Mission:
    d = _walk_decode(d)
    d = cast(dict[str, Any], d)
    at = d.get("approved_tools")
    if at is not None:
        at_t: tuple[dict[str, str], ...] = tuple(
            {str(a): str(b) for a, b in x.items()} if isinstance(x, dict) else x for x in at  # type: ignore[misc]
        )  # type: ignore[assignment]
    else:
        at_t = None
    cap = d.get("capabilities")
    return Mission(
        s256=str(d["s256"]),
        blob_bytes=cast(Any, d["blob_bytes"]),
        state=cast(Any, d["state"]),
        agent_id=str(d["agent_id"]),
        owner_id=d.get("owner_id"),
        approver=str(d["approver"]),
        description=str(d["description"]),
        approved_at=cast(Any, d["approved_at"]),
        approved_tools=at_t,
        capabilities=tuple(cap) if cap is not None else None,
    )


def _terminal_from(d: Any) -> AuthTokenResponse | Mission | InteractionTerminalResult:
    d = _walk_decode(d)
    d = cast(dict[str, Any], d)
    if "auth_token" in d and "expires_in" in d:
        return AuthTokenResponse(auth_token=str(d["auth_token"]), expires_in=int(d["expires_in"]))
    if "s256" in d and "blob_bytes" in d:
        return _mission_from(d)
    if "body" in d and len(d) <= 2:
        return InteractionTerminalResult(body=dict(d["body"]))
    raise ValueError("unknown terminal type")


def pending_record_to_dict(rec: PendingRecord) -> dict[str, Any]:
    d: dict[str, Any] = {
        "pending_id": rec.pending_id,
        "interaction_code": rec.interaction_code,
        "kind": rec.kind,
        "created_at": rec.created_at,
        "ttl_seconds": rec.ttl_seconds,
        "token_request": asdict(rec.token_request) if rec.token_request is not None else None,
        "mission_proposal": asdict(rec.mission_proposal) if rec.mission_proposal is not None else None,
        "owner_id": rec.owner_id,
        "status": rec.status,
        "requirement": rec.requirement,
        "clarification": rec.clarification,
        "timeout": rec.timeout,
        "options": rec.options,
        "terminal": asdict(rec.terminal) if rec.terminal is not None else None,
        "interaction_type": rec.interaction_type,
        "interaction_summary": rec.interaction_summary,
        "interaction_question": rec.interaction_question,
        "relay_url": rec.relay_url,
        "relay_code": rec.relay_code,
        "mission_s256": rec.mission_s256,
        "pending_agent_id": rec.pending_agent_id,
        "interaction_description": rec.interaction_description,
        "failure": rec.failure,
        "gone": rec.gone,
        "delivered": rec.delivered,
        "clarification_responses": list(rec.clarification_responses),
        "clarification_round": rec.clarification_round,
        "callback_url": rec.callback_url,
        "last_poll_monotonic": rec.last_poll_monotonic,
        "verified_resource_claims": rec.verified_resource_claims,
        "token_agent_cnf_jwk": rec.token_agent_cnf_jwk,
    }
    return _walk_encode(d)


def pending_record_from_dict(data: Any) -> PendingRecord:
    d0 = _walk_decode(data)
    if not isinstance(d0, dict):
        raise ValueError("pending not a dict")
    d = cast(dict[str, Any], d0)
    tr = d.get("token_request")
    mp = d.get("mission_proposal")
    term = d.get("terminal")
    d.pop("token_request", None)
    d.pop("mission_proposal", None)
    d.pop("terminal", None)
    st = d["status"]
    if isinstance(st, str):
        st = PendingStatus(st)
    req = d.get("requirement")
    if isinstance(req, str) and req:
        req = RequirementLevel(req)
    return PendingRecord(
        token_request=_tr_from(tr) if tr is not None else None,
        mission_proposal=_mp_from(mp) if mp is not None else None,
        terminal=_terminal_from(term) if term is not None else None,
        pending_id=str(d["pending_id"]),
        interaction_code=str(d["interaction_code"]),
        kind=cast(Any, d["kind"]),
        created_at=cast(Any, d["created_at"]),
        ttl_seconds=int(d["ttl_seconds"]),
        owner_id=d.get("owner_id"),
        status=cast(Any, st),
        requirement=cast(Any, req),
        clarification=d.get("clarification"),
        timeout=d.get("timeout"),
        options=d.get("options"),
        interaction_type=d.get("interaction_type"),
        interaction_summary=d.get("interaction_summary"),
        interaction_question=d.get("interaction_question"),
        relay_url=d.get("relay_url"),
        relay_code=d.get("relay_code"),
        mission_s256=d.get("mission_s256"),
        pending_agent_id=d.get("pending_agent_id"),
        interaction_description=d.get("interaction_description"),
        failure=d.get("failure"),
        gone=bool(d.get("gone", False)),
        delivered=bool(d.get("delivered", False)),
        clarification_responses=list(d.get("clarification_responses") or []),
        clarification_round=int(d.get("clarification_round", 0)),
        callback_url=d.get("callback_url"),
        last_poll_monotonic=d.get("last_poll_monotonic"),
        verified_resource_claims=cast(Any, d.get("verified_resource_claims")),
        token_agent_cnf_jwk=cast(Any, d.get("token_agent_cnf_jwk")),
    )


def mission_to_mission_log_entry_dict(e: MissionLogEntry) -> dict[str, Any]:
    d = asdict(e)
    d["ts"] = e.ts
    d["kind"] = e.kind
    return _walk_encode(d)


def mission_log_entry_from_dict(data: Any) -> MissionLogEntry:
    d = _walk_decode(data)
    d = cast(dict[str, Any], d)
    from ps.models import MissionLogKind

    k = d["kind"]
    if not isinstance(k, MissionLogKind):
        k = MissionLogKind(k)
    return MissionLogEntry(ts=cast(Any, d["ts"]), kind=k, payload=dict(d.get("payload") or {}))


def compute_is_open(rec: PendingRecord) -> bool:
    return not rec.gone and rec.terminal is None and not (rec.failure or "")


def requirement_value(rec: PendingRecord) -> str | None:
    return rec.requirement.value if rec.requirement is not None else None
