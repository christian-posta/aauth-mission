"""Well-known MM metadata (protocol §MM Metadata)."""

from __future__ import annotations

from mm.models import MMMetadata


def get_mm_metadata(configured: MMMetadata) -> MMMetadata:
    """GET `/.well-known/aauth-mission.json` — return configured/static metadata."""
    return configured
