"""Domain exceptions for the AAuth Agent Server."""

from __future__ import annotations


class AgentServerError(Exception):
    pass


class BindingNotFoundError(AgentServerError):
    pass


class BindingRevokedError(AgentServerError):
    pass


class PendingNotFoundError(AgentServerError):
    pass


class PendingExpiredError(AgentServerError):
    pass


class PendingDeniedError(AgentServerError):
    pass


class InvalidSignatureError(AgentServerError):
    pass


class DuplicateStableKeyError(AgentServerError):
    """Raised when a stable JKT is already registered on a binding (link dedup)."""
    pass


class ReplayError(AgentServerError):
    """Raised when a replayed HTTP signature is detected."""
    pass
