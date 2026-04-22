"""AS metadata discovery (protocol §Auth Server Metadata)."""

from __future__ import annotations

from abc import ABC, abstractmethod

from ps.models import ASMetadata


class ASDiscovery(ABC):
    """Fetch `{as_url}/.well-known/aauth-issuer.json`."""

    @abstractmethod
    def discover(self, as_url: str) -> ASMetadata:
        """Return issuer metadata for the given authorization server base URL."""
