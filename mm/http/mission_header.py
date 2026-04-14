"""Parse and build AAuth-Mission header (SPEC §AAuth-Mission Request Header)."""

from __future__ import annotations

import re

from mm.models import MissionRef


def parse_aauth_mission_header(header_val: str | None) -> MissionRef | None:
    if not header_val:
        return None
    app = re.search(r'approver="([^"]+)"', header_val)
    s256 = re.search(r's256="([^"]+)"', header_val)
    if not app or not s256:
        return None
    return MissionRef(approver=app.group(1), s256=s256.group(1))


def build_aauth_mission_response_header(approver: str, s256: str) -> str:
    return f'approver="{approver}"; s256="{s256}"'
