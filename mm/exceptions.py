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
