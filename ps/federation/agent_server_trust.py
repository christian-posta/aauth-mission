"""Runtime registry of agent server issuers the PS trusts (SPEC §Agent Token Verification)."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def normalize_issuer(url: str) -> str:
    return url.rstrip("/")


@dataclass(frozen=True, slots=True)
class TrustedAgentServer:
    issuer: str
    display_name: str
    jwks_uri: str
    jwks_fingerprint: str
    added_at: str


class AgentServerTrustRegistry(ABC):
    @abstractmethod
    def list_trusted(self) -> list[TrustedAgentServer]:
        ...

    @abstractmethod
    def add(self, entry: TrustedAgentServer) -> None:
        ...

    @abstractmethod
    def remove(self, issuer: str) -> bool:
        ...

    @abstractmethod
    def is_trusted(self, issuer: str) -> bool:
        ...


class MemoryAgentServerTrustRegistry(AgentServerTrustRegistry):
    """In-memory trust list with optional JSON persistence."""

    def __init__(self, persistence_path: str | None = None) -> None:
        self._by_issuer: dict[str, TrustedAgentServer] = {}
        self._path = Path(persistence_path) if persistence_path else None
        if self._path and self._path.exists():
            self._load()

    def _load(self) -> None:
        assert self._path is not None
        raw = json.loads(self._path.read_text(encoding="utf-8"))
        items = raw.get("trusted", [])
        for it in items:
            e = TrustedAgentServer(
                issuer=normalize_issuer(str(it["issuer"])),
                display_name=str(it.get("display_name", "")),
                jwks_uri=str(it["jwks_uri"]),
                jwks_fingerprint=str(it["jwks_fingerprint"]),
                added_at=str(it.get("added_at", "")),
            )
            self._by_issuer[e.issuer] = e

    def _persist(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        rows = [
            {
                "issuer": x.issuer,
                "display_name": x.display_name,
                "jwks_uri": x.jwks_uri,
                "jwks_fingerprint": x.jwks_fingerprint,
                "added_at": x.added_at,
            }
            for x in sorted(self._by_issuer.values(), key=lambda z: z.issuer)
        ]
        payload = {"trusted": rows}
        self._path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def list_trusted(self) -> list[TrustedAgentServer]:
        return sorted(self._by_issuer.values(), key=lambda x: x.issuer)

    def add(self, entry: TrustedAgentServer) -> None:
        self._by_issuer[normalize_issuer(entry.issuer)] = entry
        self._persist()

    def remove(self, issuer: str) -> bool:
        key = normalize_issuer(issuer)
        if key not in self._by_issuer:
            return False
        del self._by_issuer[key]
        self._persist()
        return True

    def is_trusted(self, issuer: str) -> bool:
        return normalize_issuer(issuer) in self._by_issuer
