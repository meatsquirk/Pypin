"""DHT interface protocols."""

from __future__ import annotations

from typing import Protocol, runtime_checkable, TYPE_CHECKING

if TYPE_CHECKING:
    from .base import ProviderRecord


@runtime_checkable
class DHTBackendProtocol(Protocol):
    """Structural interface for DHT backends."""

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def provide(self, key: bytes, multiaddrs: list[str]) -> bool: ...

    async def find_providers(self, key: bytes) -> list["ProviderRecord"]: ...

    async def put_value(self, key: bytes, value: bytes) -> bool: ...

    async def get_value(self, key: bytes) -> bytes | None: ...
