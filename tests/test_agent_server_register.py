"""Agent Server registration: ``agent_name`` on ``POST /register`` and person APIs."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_server.http.bodies import RegisterBody
from agent_server.impl.memory_bindings import MemoryBindingStore


def test_register_body_valid_and_strips() -> None:
    b = RegisterBody(
        stable_pub={"kty": "OKP", "crv": "Ed25519", "x": "abc"},
        agent_name="  my-agent  ",
    )
    assert b.agent_name == "my-agent"


def test_register_body_rejects_empty_agent_name() -> None:
    with pytest.raises(ValidationError):
        RegisterBody(
            stable_pub={"kty": "OKP", "crv": "Ed25519", "x": "abc"},
            agent_name="",
        )
    with pytest.raises(ValidationError):
        RegisterBody(
            stable_pub={"kty": "OKP", "crv": "Ed25519", "x": "abc"},
            agent_name="   \t  ",
        )


def test_register_body_rejects_too_long_after_trim() -> None:
    with pytest.raises(ValidationError):
        RegisterBody(
            stable_pub={"kty": "OKP", "crv": "Ed25519", "x": "abc"},
            agent_name="a" * 257,
        )


def test_register_body_rejects_unknown_label_field() -> None:
    with pytest.raises(ValidationError):
        RegisterBody.model_validate(
            {
                "stable_pub": {"kty": "OKP", "crv": "Ed25519", "x": "abc"},
                "label": "no longer valid",
            }
        )


def test_binding_store_update_agent_name() -> None:
    store = MemoryBindingStore()
    b = store.create("aauth:x@example", "first", "urn:jkt:sha-256:aaa")
    assert b.agent_name == "first"
    store.update_agent_name("aauth:x@example", "  second  ")
    assert store.get_by_agent_id("aauth:x@example") is not None
    assert store.get_by_agent_id("aauth:x@example").agent_name == "second"
