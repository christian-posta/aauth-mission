"""Port for mission + mission log storage (in-memory or SQL)."""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable

from ps.models import Mission, MissionLogEntry


@runtime_checkable
class MissionStatePort(Protocol):
    def get_mission(self, s256: str) -> Mission | None: ...

    def set_mission(self, m: Mission) -> None: ...

    def has_mission(self, s256: str) -> bool: ...

    def iter_missions(self) -> Iterator[Mission]: ...

    def append_mission_log(self, s256: str, entry: MissionLogEntry) -> None: ...

    def get_mission_log(self, s256: str) -> list[MissionLogEntry]: ...
