"""Well-known PS metadata (SPEC §Person Server Metadata)."""

from __future__ import annotations

from mm.models import MMMetadata


def get_mm_metadata(configured: MMMetadata) -> MMMetadata:
    """Return configured metadata for `/.well-known/aauth-person.json` (and legacy alias)."""
    return configured
