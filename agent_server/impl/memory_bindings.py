"""In-memory BindingStore."""

from __future__ import annotations

from datetime import datetime, timezone

from agent_server.models import Binding


class MemoryBindingStore:
    def __init__(self) -> None:
        self._by_agent_id: dict[str, Binding] = {}
        self._jkt_index: dict[str, str] = {}  # stable_jkt -> agent_id

    def create(self, agent_id: str, agent_name: str, stable_jkt: str) -> Binding:
        binding = Binding(
            agent_id=agent_id,
            agent_name=agent_name,
            created_at=datetime.now(timezone.utc),
            stable_key_thumbprints=[stable_jkt],
            revoked=False,
        )
        self._by_agent_id[agent_id] = binding
        self._jkt_index[stable_jkt] = agent_id
        return binding

    def lookup_by_stable_jkt(self, jkt: str) -> Binding | None:
        agent_id = self._jkt_index.get(jkt)
        if agent_id is None:
            return None
        return self._by_agent_id.get(agent_id)

    def get_by_agent_id(self, agent_id: str) -> Binding | None:
        return self._by_agent_id.get(agent_id)

    def update_agent_name(self, agent_id: str, agent_name: str) -> None:
        binding = self._by_agent_id.get(agent_id)
        if binding is None:
            raise KeyError(agent_id)
        binding.agent_name = agent_name.strip()

    def list_all(self) -> list[Binding]:
        return sorted(self._by_agent_id.values(), key=lambda b: b.created_at)

    def add_stable_key(self, agent_id: str, stable_jkt: str) -> None:
        binding = self._by_agent_id.get(agent_id)
        if binding is None:
            raise KeyError(agent_id)
        if stable_jkt in binding.stable_key_thumbprints:
            from agent_server.exceptions import DuplicateStableKeyError
            raise DuplicateStableKeyError(f"{stable_jkt} already on binding {agent_id}")
        binding.stable_key_thumbprints.append(stable_jkt)
        self._jkt_index[stable_jkt] = agent_id

    def revoke(self, agent_id: str) -> None:
        binding = self._by_agent_id.get(agent_id)
        if binding is None:
            raise KeyError(agent_id)
        binding.revoked = True
