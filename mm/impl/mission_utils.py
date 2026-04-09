"""Mission hashing (protocol §Mission Approval)."""

from __future__ import annotations

import base64
import hashlib
from mm.impl.backend import utc_now
from mm.models import Mission, MissionProposal, MissionState


def s256_hash(approved_text: str) -> str:
    digest = hashlib.sha256(approved_text.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def mission_from_proposal(proposal: MissionProposal, refined_text: str | None = None) -> Mission:
    """Build an active mission with approval text and integrity hash."""
    base = refined_text if refined_text is not None else proposal.proposal_text
    footer = f"\n\n## Approval\n- Approved at: {utc_now().isoformat()}"
    approved = base.rstrip() + footer
    return Mission(
        s256=s256_hash(approved),
        approved_text=approved,
        state=MissionState.ACTIVE,
        agent_id=proposal.agent_id,
        created_at=utc_now(),
    )
