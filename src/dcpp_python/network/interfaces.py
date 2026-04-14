"""Network interface protocols."""

from __future__ import annotations

from typing import Awaitable, Callable, Protocol, runtime_checkable

from dcpp_python.core.messages import MessageType


@runtime_checkable
class StreamProtocol(Protocol):
    @property
    def info(self) -> object: ...

    @property
    def state(self) -> object: ...

    async def read(self, n: int) -> bytes: ...

    async def write(self, data: bytes) -> None: ...

    async def close(self) -> None: ...


StreamHandler = Callable[[StreamProtocol], Awaitable[None]]


@runtime_checkable
class HostProtocol(Protocol):
    @property
    def peer_id(self) -> bytes: ...

    @property
    def addrs(self) -> list[str]: ...

    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def connect(self, peer_id: bytes, addrs: list[str]) -> bool: ...

    async def disconnect(self, peer_id: bytes) -> None: ...

    async def new_stream(self, peer_id: bytes, protocol_id: str) -> StreamProtocol: ...

    def set_stream_handler(self, protocol_id: str, handler: StreamHandler) -> None: ...

    def connected_peers(self) -> list[bytes]: ...


@runtime_checkable
class MessageHandlerProtocol(Protocol):
    """Callable interface for handling decoded DCPP messages."""

    def __call__(self, peer_id: bytes, msg_type: MessageType, payload: bytes) -> bytes | None: ...
