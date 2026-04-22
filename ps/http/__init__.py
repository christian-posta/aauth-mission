"""FastAPI server for the AAuth Person Server."""

from ps.http.app import app, create_app
from ps.http.config import PSHttpSettings

__all__ = ["app", "create_app", "PSHttpSettings"]
