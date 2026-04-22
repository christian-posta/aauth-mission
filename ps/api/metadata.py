"""Well-known PS metadata (SPEC §Person Server Metadata)."""

from __future__ import annotations

from ps.models import PSMetadata


def get_ps_metadata(configured: PSMetadata) -> PSMetadata:
    """Return configured metadata for `/.well-known/aauth-person.json` (and legacy alias)."""
    return configured
