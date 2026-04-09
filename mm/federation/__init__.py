"""Federation layer: MM calls to external authorization servers."""

from mm.federation.as_discovery import ASDiscovery
from mm.federation.as_federator import ASFederator
from mm.federation.identity_provider import IdentityProvider

__all__ = ["ASDiscovery", "ASFederator", "IdentityProvider"]
