"""Directed subject and claims for MM–AS federation (protocol §MM-to-AS)."""

from __future__ import annotations

from abc import ABC, abstractmethod


class IdentityProvider(ABC):
    """User identity for federation: pairwise `sub` and claim release."""

    @abstractmethod
    def get_directed_sub(self, user_id: str, as_url: str) -> str:
        """Return the pairwise pseudonymous subject for this user at the given AS."""

    @abstractmethod
    def get_claims(self, user_id: str, requested_claims: list[str]) -> dict[str, object]:
        """Return identity claims for an AS `requirement=claims` request."""
