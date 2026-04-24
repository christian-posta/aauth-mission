"""Domain errors surfaced by the HTTP layer."""


class PendingGoneError(Exception):
    """Pending resource was cancelled; HTTP 410."""

    pass


class PendingDeniedError(Exception):
    """User or policy denied the request; HTTP 403."""

    def __init__(self, reason: str = "denied") -> None:
        self.reason = reason


class NotFoundError(Exception):
    """Unknown mission or pending id; HTTP 404."""

    pass


class ForbiddenOwnerError(Exception):
    """Mission not owned by the authenticated legal user; HTTP 403."""

    pass


class PendingExpiredError(Exception):
    """Pending request timed out; HTTP 408."""

    pass


class SlowDownError(Exception):
    """Polling too frequently; HTTP 429."""

    pass


class ClarificationLimitError(Exception):
    """Too many clarification rounds; HTTP 400."""

    pass


class InvalidInteractionCodeError(Exception):
    """Unknown or already-used interaction code; HTTP 410."""

    pass


class MissionTerminatedError(Exception):
    """Referenced mission is not active; HTTP 403 mission_terminated."""

    pass


class ResourceTokenRejectError(Exception):
    """Invalid or expired resource token on ``POST /token`` (secure mode)."""

    def __init__(self, message: str, *, error: str) -> None:
        super().__init__(message)
        self.error = error
        self.message = message


class AgentTokenRejectError(Exception):
    """Invalid agent HTTP signature or ``aa-agent+jwt`` on secure ``POST /token``."""

    def __init__(self, message: str, *, error: str) -> None:
        super().__init__(message)
        self.error = error
        self.message = message
