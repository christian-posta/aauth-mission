"""Mission blob construction and s256 (SPEC §Mission Approval)."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import timezone
from urllib.parse import urlparse

from mm.impl.backend import utc_now
from mm.models import Mission, MissionProposal, MissionState, ToolSpec


def s256_hash_bytes(blob: bytes) -> str:
    digest = hashlib.sha256(blob).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def agent_claim_for_mission_blob(agent_id: str, ps_issuer: str) -> str:
    """Build `agent` string for mission JSON (aauth:local@host)."""
    host = urlparse(ps_issuer).hostname or "localhost"
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in agent_id)[:128]
    return f"aauth:{safe}@{host}"


def approved_tools_from_proposal(tools: tuple[ToolSpec, ...]) -> list[dict[str, str]] | None:
    if not tools:
        return None
    return [{"name": t.name, "description": t.description} for t in tools]


def build_mission_blob_bytes(
    *,
    approver: str,
    agent: str,
    approved_at_iso: str,
    description: str,
    approved_tools: list[dict[str, str]] | None,
    capabilities: list[str] | None,
) -> bytes:
    """Canonical JSON bytes for s256 (SPEC: hash of exact response body bytes)."""
    obj: dict[str, object] = {
        "approver": approver,
        "agent": agent,
        "approved_at": approved_at_iso,
        "description": description,
    }
    if approved_tools is not None:
        obj["approved_tools"] = approved_tools
    if capabilities is not None:
        obj["capabilities"] = capabilities
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def mission_from_proposal(
    proposal: MissionProposal,
    ps_issuer: str,
    *,
    refined_description: str | None = None,
    refined_tools: tuple[ToolSpec, ...] | None = None,
    capabilities: tuple[str, ...] | None = ("interaction",),
) -> Mission:
    """Build an active mission from a proposal (PS issuer URL required for approver field)."""
    desc = refined_description if refined_description is not None else proposal.description
    tools = refined_tools if refined_tools is not None else proposal.tools
    approved_tools_list = approved_tools_from_proposal(tools)
    caps_list = list(capabilities) if capabilities is not None else None
    approved_at = utc_now()
    approved_at_iso = approved_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    agent_claim = agent_claim_for_mission_blob(proposal.agent_id, ps_issuer)
    blob = build_mission_blob_bytes(
        approver=ps_issuer.rstrip("/"),
        agent=agent_claim,
        approved_at_iso=approved_at_iso,
        description=desc.rstrip(),
        approved_tools=approved_tools_list,
        capabilities=caps_list,
    )
    s256 = s256_hash_bytes(blob)
    approved_tools_tuple: tuple[dict[str, str], ...] | None
    if approved_tools_list:
        approved_tools_tuple = tuple(approved_tools_list)
    else:
        approved_tools_tuple = None
    caps_t: tuple[str, ...] | None = tuple(caps_list) if caps_list else None
    return Mission(
        s256=s256,
        blob_bytes=blob,
        state=MissionState.ACTIVE,
        agent_id=proposal.agent_id,
        approved_at=approved_at,
        owner_id=proposal.owner_hint,
        approver=ps_issuer.rstrip("/"),
        description=desc.rstrip(),
        approved_tools=approved_tools_tuple,
        capabilities=caps_t,
    )


def mission_blob_dict(m: Mission) -> dict[str, object]:
    """Deserialize mission fields for API responses (same logical content as blob_bytes)."""
    d = json.loads(m.blob_bytes.decode("utf-8"))
    assert isinstance(d, dict)
    return d
