"""Synchronous JSON HTTP fetch for JWKS / metadata discovery (stdlib only)."""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urljoin


def fetch_json(url: str, *, timeout: float = 15.0) -> dict[str, Any]:
    """GET JSON from ``url``. Allows http for localhost-style dev URLs."""
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        raise ValueError(f"HTTP {e.code} fetching {url}") from e
    except urllib.error.URLError as e:
        raise ValueError(f"Failed to fetch {url}: {e}") from e
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object from {url}")
    return data


def discover_jwks_via_metadata(identifier: str, metadata_filename: str) -> dict[str, Any]:
    """Fetch ``{identifier}/.well-known/{metadata_filename}`` and then the ``jwks_uri`` document."""
    base = identifier.rstrip("/") + "/"
    meta_url = urljoin(base, f".well-known/{metadata_filename}")
    meta = fetch_json(meta_url)
    jwks_uri = meta.get("jwks_uri")
    if not jwks_uri or not isinstance(jwks_uri, str):
        raise ValueError(f"No jwks_uri in metadata from {meta_url}")
    jwks = fetch_json(jwks_uri)
    if not isinstance(jwks.get("keys"), list):
        raise ValueError(f"Invalid JWKS from {jwks_uri}")
    return jwks
