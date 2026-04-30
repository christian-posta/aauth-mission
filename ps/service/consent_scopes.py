"""Consent scope configuration management (admin-configurable scopes requiring user consent)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Sequence

logger = logging.getLogger(__name__)

_DEFAULT_SCOPES = ["require:user"]


class ConsentScopeStore:
    """Manages the list of scopes that require user consent."""

    def __init__(self, file_path: str | None) -> None:
        self._file_path = Path(file_path) if file_path else None
        self._scopes: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self._file_path:
            self._scopes = set(_DEFAULT_SCOPES)
            logger.info("No consent scopes file configured; using defaults: %s", _DEFAULT_SCOPES)
            return

        if not self._file_path.exists():
            self._scopes = set(_DEFAULT_SCOPES)
            self._save()
            logger.info("Created consent scopes file at %s with defaults", self._file_path)
            return

        try:
            with open(self._file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if not isinstance(data, dict) or "scopes" not in data:
                    raise ValueError("Invalid format: expected {\"scopes\": [...]}")
                scopes = data["scopes"]
                if not isinstance(scopes, list):
                    raise ValueError("Invalid format: scopes must be an array")
                self._scopes = set(s for s in scopes if isinstance(s, str))
                logger.info("Loaded %d consent scopes from %s", len(self._scopes), self._file_path)
        except Exception as e:
            logger.warning("Failed to load consent scopes from %s: %s; using defaults", self._file_path, e)
            self._scopes = set(_DEFAULT_SCOPES)

    def _save(self) -> None:
        if not self._file_path:
            return

        try:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._file_path, "w", encoding="utf-8") as f:
                json.dump({"scopes": sorted(self._scopes)}, f, indent=2)
            logger.debug("Saved %d consent scopes to %s", len(self._scopes), self._file_path)
        except Exception as e:
            logger.error("Failed to save consent scopes to %s: %s", self._file_path, e)

    def get_scopes(self) -> list[str]:
        """Return the current list of consent-required scopes."""
        return sorted(self._scopes)

    def add_scope(self, scope: str) -> bool:
        """Add a scope to the consent-required list. Returns True if added, False if already present."""
        scope = scope.strip()
        if not scope:
            raise ValueError("Scope cannot be empty")
        if scope in self._scopes:
            return False
        self._scopes.add(scope)
        self._save()
        logger.info("Added consent scope: %s", scope)
        return True

    def remove_scope(self, scope: str) -> bool:
        """Remove a scope from the consent-required list. Returns True if removed, False if not present."""
        if scope not in self._scopes:
            return False
        self._scopes.remove(scope)
        self._save()
        logger.info("Removed consent scope: %s", scope)
        return True

    def requires_consent(self, resource_scope: str | None) -> bool:
        """Check if any of the requested scopes require user consent."""
        if not resource_scope or not isinstance(resource_scope, str):
            return False
        requested = set(resource_scope.split())
        return bool(requested & self._scopes)
