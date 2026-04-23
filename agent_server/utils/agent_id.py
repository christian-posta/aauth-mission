"""Agent identifier generation and validation per AAuth spec."""

from __future__ import annotations

import re
import uuid

# Spec character rules (draft-hardt-aauth-protocol §Agent Identifiers):
# local part MUST use lowercase ASCII a-z, digits 0-9, hyphen, underscore, plus, period
# MUST NOT be empty, MUST NOT exceed 255 characters
_LOCAL_PART_RE = re.compile(r"^[a-z0-9\-_.+]{1,255}$")


def generate_agent_id(server_domain: str) -> str:
    """Mint a new stable agent ID: aauth:<uuid>@<domain>."""
    local = str(uuid.uuid4())  # lowercase hex + hyphens — valid per spec
    return f"aauth:{local}@{server_domain}"


def is_valid_agent_id(agent_id: str) -> bool:
    """Validate aauth:<local>@<domain> format per spec character rules."""
    if not agent_id.startswith("aauth:"):
        return False
    rest = agent_id[6:]
    if "@" not in rest:
        return False
    local, domain = rest.rsplit("@", 1)
    if not local or not domain:
        return False
    return bool(_LOCAL_PART_RE.match(local))
