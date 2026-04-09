"""Thin HTTP-oriented stubs mapping routes to service calls (framework-agnostic)."""

from mm.api.admin_routes import patch_mission, list_missions_route, get_mission_route
from mm.api.agent_routes import (
    cancel_pending_route,
    create_mission_route,
    get_pending_route,
    post_pending_route,
    request_token_route,
)
from mm.api.metadata import get_mm_metadata
from mm.api.user_routes import get_interaction_route, post_decision_route

__all__ = [
    "cancel_pending_route",
    "create_mission_route",
    "get_interaction_route",
    "get_mission_route",
    "get_mm_metadata",
    "get_pending_route",
    "list_missions_route",
    "patch_mission",
    "post_decision_route",
    "post_pending_route",
    "request_token_route",
]
