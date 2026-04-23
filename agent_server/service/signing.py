"""SigningService — Ed25519 key management and agent token signing."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aauth
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = logging.getLogger(__name__)

_KID_COMMENT_PREFIX = "# kid:"


class SigningService:
    """Manages the agent server's own Ed25519 signing key and issues agent tokens."""

    def __init__(
        self,
        issuer: str,
        server_domain: str,
        signing_key_path: str | None,
        previous_key_path: str | None,
        agent_token_lifetime: int,
    ) -> None:
        self._issuer = issuer
        self._server_domain = server_domain
        self._lifetime = agent_token_lifetime

        self._private_key, self._kid = self._load_or_generate(signing_key_path)
        self._previous_key: Ed25519PrivateKey | None = None
        self._previous_kid: str | None = None
        if previous_key_path:
            p = Path(previous_key_path)
            if p.exists():
                self._previous_key, self._previous_kid = self._load_key(p)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._private_key

    def get_jwks(self) -> dict[str, Any]:
        """Return JWKS with current + previous signing public keys."""
        keys = []
        keys.append(self._to_jwk(self._private_key, self._kid))
        if self._previous_key is not None:
            keys.append(self._to_jwk(self._previous_key, self._previous_kid or "prev"))
        return {"keys": keys}

    def create_agent_token(
        self,
        agent_id: str,
        ephemeral_pub: dict[str, Any],
        lifetime_seconds: int | None = None,
    ) -> str:
        """Create and sign an aa-agent+jwt token."""
        lt = lifetime_seconds if lifetime_seconds is not None else self._lifetime
        exp = int(time.time()) + lt
        return aauth.create_agent_token(
            iss=self._issuer,
            sub=agent_id,
            cnf_jwk=ephemeral_pub,
            private_key=self._private_key,
            kid=self._kid,
            exp=exp,
        )

    # ------------------------------------------------------------------
    # Key management helpers
    # ------------------------------------------------------------------

    def _load_or_generate(self, path: str | None) -> tuple[Ed25519PrivateKey, str]:
        if path:
            p = Path(path)
            if p.exists():
                return self._load_key(p)
            # Generate and persist
            key, kid = self._generate_key()
            self._save_key(key, kid, p)
            return key, kid
        # No path — ephemeral in-memory key (useful for tests / insecure_dev)
        key, kid = self._generate_key()
        logger.warning(
            "No signing_key_path configured — using ephemeral in-memory key. "
            "Tokens will not survive restarts."
        )
        return key, kid

    @staticmethod
    def _generate_key() -> tuple[Ed25519PrivateKey, str]:
        key = Ed25519PrivateKey.generate()
        kid = f"as-{datetime.now(timezone.utc).strftime('%Y%m')}-{uuid.uuid4().hex[:8]}"
        return key, kid

    @staticmethod
    def _load_key(path: Path) -> tuple[Ed25519PrivateKey, str]:
        raw = path.read_bytes()
        lines = raw.decode().splitlines()
        kid: str | None = None
        pem_lines: list[str] = []
        for line in lines:
            if line.startswith(_KID_COMMENT_PREFIX):
                kid = line[len(_KID_COMMENT_PREFIX):].strip()
            else:
                pem_lines.append(line)
        pem = "\n".join(pem_lines).encode()
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"Expected Ed25519 key at {path}")
        if kid is None:
            kid = f"as-loaded-{path.stem}"
        logger.info("Loaded signing key %s from %s", kid, path)
        return key, kid

    @staticmethod
    def _save_key(key: Ed25519PrivateKey, kid: str, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        content = f"{_KID_COMMENT_PREFIX}{kid}\n".encode() + pem
        path.write_bytes(content)
        logger.info("Generated and saved new signing key %s to %s", kid, path)

    @staticmethod
    def _to_jwk(key: Ed25519PrivateKey, kid: str) -> dict[str, Any]:
        jwk = aauth.public_key_to_jwk(key.public_key(), kid=kid)
        jwk["use"] = "sig"
        jwk["alg"] = "EdDSA"
        return jwk
