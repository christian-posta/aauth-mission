"""PSSigningService — Ed25519 key for PS-issued aa-auth+jwt (SPEC §Auth Token)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aauth
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

logger = logging.getLogger(__name__)

_KID_COMMENT_PREFIX = "# kid:"


class PSSigningService:
    """Manages the Person Server's Ed25519 signing key and exposes JWKS for aauth-person.json discovery."""

    def __init__(self, signing_key_path: str | None) -> None:
        """Load or create a key on disk.

        ``signing_key_path``:
        - A non-empty string: load PEM if it exists, else generate, persist, and reuse.
        - ``None``: ephemeral in-memory key (tests / explicit ephemeral mode).
        """
        self._path: Path | None = Path(signing_key_path) if signing_key_path else None
        self._private_key: Ed25519PrivateKey
        self._kid: str
        if self._path is None:
            self._private_key, self._kid = self._generate_key()
            logger.warning(
                "No AAUTH_PS_SIGNING_KEY_PATH — using ephemeral in-memory PS signing key; "
                "auth tokens will not survive restarts."
            )
        else:
            self._private_key, self._kid = self._load_or_generate(self._path)

    @property
    def kid(self) -> str:
        return self._kid

    @property
    def private_key(self) -> Ed25519PrivateKey:
        return self._private_key

    def get_jwks(self) -> dict[str, Any]:
        keys = [self._to_jwk(self._private_key, self._kid)]
        return {"keys": keys}

    def _load_or_generate(self, path: Path) -> tuple[Ed25519PrivateKey, str]:
        if path.exists():
            return self._load_key(path)
        key, kid = self._generate_key()
        self._save_key(key, kid, path)
        return key, kid

    @staticmethod
    def _generate_key() -> tuple[Ed25519PrivateKey, str]:
        key = Ed25519PrivateKey.generate()
        kid = f"ps-{datetime.now(timezone.utc).strftime('%Y%m')}-{uuid.uuid4().hex[:8]}"
        return key, kid

    @staticmethod
    def _load_key(path: Path) -> tuple[Ed25519PrivateKey, str]:
        raw = path.read_bytes()
        lines = raw.decode().splitlines()
        kid: str | None = None
        pem_lines: list[str] = []
        for line in lines:
            if line.startswith(_KID_COMMENT_PREFIX):
                kid = line[len(_KID_COMMENT_PREFIX) :].strip()
            else:
                pem_lines.append(line)
        pem = "\n".join(pem_lines).encode()
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"Expected Ed25519 key at {path}")
        if kid is None:
            kid = f"ps-loaded-{path.stem}"
        logger.info("Loaded PS signing key %s from %s", kid, path)
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
        logger.info("Generated and saved new PS signing key %s to %s", kid, path)

    @staticmethod
    def _to_jwk(key: Ed25519PrivateKey, kid: str) -> dict[str, Any]:
        jwk = aauth.public_key_to_jwk(key.public_key(), kid=kid)
        jwk["use"] = "sig"
        jwk["alg"] = "EdDSA"
        return jwk
