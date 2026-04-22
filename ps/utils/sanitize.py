"""Sanitize Markdown-oriented user/agent text before display (protocol §Markdown String)."""

from __future__ import annotations

import bleach


def sanitize_markdown_input(text: str) -> str:
    """Strip dangerous HTML/script; keep plain text and most Markdown intact."""
    return bleach.clean(
        text,
        tags=bleach.sanitizer.ALLOWED_TAGS | {"p", "pre", "code"},
        attributes={**bleach.sanitizer.ALLOWED_ATTRIBUTES, "a": ["href", "title", "rel"]},
        strip=True,
    )
