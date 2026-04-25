"""FastAPI server exports for the AAuth Person Server.

Keep imports lazy so importing ``ps.http`` does not eagerly construct an app.
"""

from __future__ import annotations

from typing import Any

from ps.http.config import PSHttpSettings

__all__ = ["app", "create_app", "PSHttpSettings"]


def create_app(*args: Any, **kwargs: Any):
    from ps.http.app import create_app as _create_app

    return _create_app(*args, **kwargs)


def __getattr__(name: str) -> Any:
    if name == "app":
        from ps.http.app import app as _app

        return _app
    if name == "create_app":
        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
