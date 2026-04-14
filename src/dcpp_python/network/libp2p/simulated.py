"""
DCPP libp2p Host Integration

Implements the libp2p-based control plane for DCPP (RFC Section 4, 9).
Provides peer-to-peer networking with:
- Ed25519 identity
- TCP/QUIC transports
- Noise encryption
- Stream multiplexing (yamux/mplex)
- Kademlia DHT
- GossipSub pub/sub
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, cast

import cbor2
from nacl.signing import SigningKey, VerifyKey

from dcpp_python.core.constants import PROTOCOL_ID, MAX_MESSAGE_SIZE
from dcpp_python.crypto.signing import generate_keypair
from dcpp_python.core.framing import DCPPFramer, ChecksumError, MagicBytesError, FramingError
from dcpp_python.core.messages import MessageType
from dcpp_python.network.dht.interfaces import DHTBackendProtocol
from dcpp_python.network.interfaces import (
    HostProtocol,
    StreamProtocol,
    MessageHandlerProtocol,
    StreamHandler,
)
from dcpp_python.storage.interfaces import StorageBackendProtocol


logger = logging.getLogger("dcpp.libp2p")


# =============================================================================
# Peer Identity
# =============================================================================


@dataclass
class PeerIdentity:
    """libp2p peer identity based on Ed25519 keypair."""

    signing_key: SigningKey
    verify_key: VerifyKey
    peer_id: bytes

    @classmethod
    def generate(cls) -> "PeerIdentity":
        """Generate a new peer identity."""
        signing_key, verify_key = generate_keypair()
        peer_id = cls._derive_peer_id(verify_key)
        return cls(signing_key=signing_key, verify_key=verify_key, peer_id=peer_id)

    @classmethod
    def from_key(cls, signing_key: SigningKey) -> "PeerIdentity":
        """Create identity from existing signing key."""
        verify_key = signing_key.verify_key
        peer_id = cls._derive_peer_id(verify_key)
        return cls(signing_key=signing_key, verify_key=verify_key, peer_id=peer_id)

    @staticmethod
    def _derive_peer_id(verify_key: VerifyKey) -> bytes:
        """
        Derive libp2p PeerId from Ed25519 public key.

        libp2p PeerId for Ed25519 (38 bytes):
        - [0]: 0x00 (identity hash function)
        - [1]: 0x24 (length = 36)
        - [2:4]: 0x08 0x01 (protobuf field 1: key type = Ed25519)
        - [4:6]: 0x12 0x20 (protobuf field 2: data, 32 bytes)
        - [6:38]: 32-byte Ed25519 public key
        """
        pubkey_bytes = bytes(verify_key)
        return bytes([0x00, 0x24, 0x08, 0x01, 0x12, 0x20]) + pubkey_bytes


# =============================================================================
# Stream Abstraction
# =============================================================================


class StreamState(Enum):
    """State of a stream."""

    OPEN = auto()
    CLOSING = auto()
    CLOSED = auto()
    ERROR = auto()


@dataclass
class StreamInfo:
    """Information about a stream."""

    stream_id: str
    protocol_id: str
    remote_peer: bytes
    remote_addrs: list[str]
    direction: str  # "inbound" or "outbound"
    opened_at: int


class Stream(ABC):
    """Abstract base class for libp2p streams."""

    @property
    @abstractmethod
    def info(self) -> StreamInfo:
        """Get stream information."""
        pass

    @property
    @abstractmethod
    def state(self) -> StreamState:
        """Get stream state."""
        pass

    @abstractmethod
    async def read(self, max_bytes: int = 65536) -> bytes:
        """Read data from stream."""
        pass

    @abstractmethod
    async def write(self, data: bytes) -> int:
        """Write data to stream."""
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close the stream."""
        pass


# =============================================================================
# Host Configuration
# =============================================================================


@dataclass
class HostConfig:
    """libp2p host configuration."""

    # Listen addresses (multiaddr format)
    listen_addrs: list[str] = field(default_factory=lambda: ["/ip4/0.0.0.0/tcp/4001"])
    # Bootstrap peers
    bootstrap_peers: list[str] = field(default_factory=list)
    # Enable relay (for NAT traversal)
    enable_relay: bool = True
    # Enable DHT server mode
    dht_server_mode: bool = False
    # Connection limits
    max_connections: int = 100
    max_streams_per_conn: int = 256
    # Timeouts
    dial_timeout: float = 30.0
    stream_timeout: float = 60.0
    # Protocol handlers
    protocol_handlers: dict[str, StreamHandler] = field(default_factory=dict)


# =============================================================================
# Host Interface
# =============================================================================


class Host(ABC):
    """Abstract base class for libp2p hosts."""

    @property
    @abstractmethod
    def peer_id(self) -> bytes:
        """Get this host's peer ID."""
        pass

    @property
    @abstractmethod
    def addrs(self) -> list[str]:
        """Get this host's listen addresses."""
        pass

    @abstractmethod
    async def start(self) -> None:
        """Start the host."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the host."""
        pass

    @abstractmethod
    async def connect(self, peer_id: bytes, addrs: list[str]) -> bool:
        """Connect to a peer."""
        pass

    @abstractmethod
    async def disconnect(self, peer_id: bytes) -> None:
        """Disconnect from a peer."""
        pass

    @abstractmethod
    async def new_stream(self, peer_id: bytes, protocol_id: str) -> Stream:
        """Open a new stream to a peer."""
        pass

    @abstractmethod
    def set_stream_handler(self, protocol_id: str, handler: StreamHandler) -> None:
        """Register a handler for incoming streams."""
        pass

    @abstractmethod
    def connected_peers(self) -> list[bytes]:
        """Get list of connected peer IDs."""
        pass


# =============================================================================
# DCPP Protocol Handler
# =============================================================================


class DCPPProtocolHandler:
    """
    Handler for DCPP protocol streams.

    Handles message framing, serialization, and routing.
    """

    def __init__(
        self,
        host: HostProtocol,
        message_handler: MessageHandlerProtocol,
    ):
        """
        Initialize protocol handler.

        Args:
            host: libp2p host
            message_handler: Callback for handling messages
                (peer_id, msg_type, payload) -> optional response payload
        """
        self.host = host
        self.message_handler = message_handler
        self._streams: dict[bytes, StreamProtocol] = {}  # peer_id -> stream

    def register(self) -> None:
        """Register this handler with the host."""
        self.host.set_stream_handler(PROTOCOL_ID, self._handle_stream)
        logger.info(f"Registered protocol handler for {PROTOCOL_ID}")

    async def _handle_stream(self, stream: StreamProtocol) -> None:
        """Handle an incoming DCPP stream with full envelope framing."""
        info = cast(StreamInfo, stream.info)
        logger.debug(f"New stream from {info.remote_peer.hex()[:16]}")

        try:
            while stream.state == StreamState.OPEN:
                # Read framed message with full envelope (header + payload)
                data = await stream.read(MAX_MESSAGE_SIZE + DCPPFramer.HEADER_SIZE)
                if not data:
                    break

                # Decode frame with MANDATORY CRC verification
                try:
                    result = DCPPFramer.decode(data)
                    msg_type = result.message_type
                    payload = result.payload
                    request_id = result.request_id
                except ChecksumError as e:
                    logger.warning(f"CRC mismatch - dropping frame: {e}")
                    continue
                except MagicBytesError as e:
                    logger.warning(f"Invalid magic bytes - dropping frame: {e}")
                    continue
                except FramingError as e:
                    logger.warning(f"Framing error - dropping frame: {e}")
                    continue

                # Handle message
                response = self.message_handler(info.remote_peer, msg_type, payload)

                # Send response if any, echoing the request_id
                if response:
                    frame = DCPPFramer.encode_response(
                        MessageType(response[0]), response[1:], request_id
                    )
                    await stream.write(frame)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Stream handler error: {e}")
        finally:
            await stream.close()

    async def send_message(
        self,
        peer_id: bytes,
        msg_type: MessageType,
        payload: bytes,
    ) -> bytes | None:
        """
        Send a message to a peer with full envelope framing.

        Args:
            peer_id: Target peer ID
            msg_type: Message type
            payload: CBOR payload

        Returns:
            Response payload or None
        """
        # Get or create stream
        if peer_id not in self._streams or self._streams[peer_id].state != StreamState.OPEN:
            try:
                stream = await self.host.new_stream(peer_id, PROTOCOL_ID)
                self._streams[peer_id] = stream
            except Exception as e:
                logger.error(f"Failed to open stream to {peer_id.hex()[:16]}: {e}")
                return None

        stream = self._streams[peer_id]

        # Send framed message with full envelope (includes request ID)
        frame, request_id = DCPPFramer.encode_request(msg_type, payload)
        await stream.write(frame)

        # Read response with full envelope
        try:
            response_data = await stream.read(MAX_MESSAGE_SIZE + DCPPFramer.HEADER_SIZE)
            if response_data:
                try:
                    result = DCPPFramer.decode(response_data)
                    # Verify request ID matches (response MUST echo it)
                    if result.request_id != request_id:
                        logger.error(
                            f"Request ID mismatch: sent {request_id}, got {result.request_id} - "
                            "treating as invalid response"
                        )
                        return None
                    return result.payload
                except (ChecksumError, MagicBytesError, FramingError) as e:
                    logger.warning(f"Invalid response frame: {e}")
                    return None
        except Exception as e:
            logger.warning(f"Failed to read response: {e}")

        return None


# =============================================================================
# Simulated Host (for testing)
# =============================================================================


class SimulatedStream(Stream):
    """Simulated stream for testing."""

    def __init__(self, info: StreamInfo):
        self._info = info
        self._state = StreamState.OPEN
        self._read_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._write_queue: asyncio.Queue[bytes] = asyncio.Queue()

    @property
    def info(self) -> StreamInfo:
        return self._info

    @property
    def state(self) -> StreamState:
        return self._state

    async def read(self, max_bytes: int = 65536) -> bytes:
        if self._state != StreamState.OPEN:
            return b""
        try:
            data = await asyncio.wait_for(self._read_queue.get(), timeout=30.0)
            return data[:max_bytes]
        except asyncio.TimeoutError:
            return b""

    async def write(self, data: bytes) -> int:
        if self._state != StreamState.OPEN:
            return 0
        await self._write_queue.put(data)
        return len(data)

    async def close(self) -> None:
        self._state = StreamState.CLOSED


class SimulatedHost(Host):
    """
    Simulated libp2p host for testing.

    Multiple instances can be connected to simulate a network.
    """

    # Class-level network simulation
    _network: dict[bytes, "SimulatedHost"] = {}

    def __init__(self, config: HostConfig | None = None):
        self.config = config or HostConfig()
        self.identity = PeerIdentity.generate()
        self._started = False
        self._handlers: dict[str, StreamHandler] = {}
        self._connected: set[bytes] = set()
        self._streams: dict[str, SimulatedStream] = {}

    @property
    def peer_id(self) -> bytes:
        return self.identity.peer_id

    @property
    def addrs(self) -> list[str]:
        return self.config.listen_addrs

    async def start(self) -> None:
        self._started = True
        SimulatedHost._network[self.peer_id] = self
        logger.info(f"Simulated host {self.peer_id.hex()[:16]} started")

    async def stop(self) -> None:
        self._started = False
        if self.peer_id in SimulatedHost._network:
            del SimulatedHost._network[self.peer_id]
        self._connected.clear()
        logger.info(f"Simulated host {self.peer_id.hex()[:16]} stopped")

    async def connect(self, peer_id: bytes, addrs: list[str]) -> bool:
        if not self._started:
            return False
        if peer_id not in SimulatedHost._network:
            return False
        self._connected.add(peer_id)
        SimulatedHost._network[peer_id]._connected.add(self.peer_id)
        return True

    async def disconnect(self, peer_id: bytes) -> None:
        self._connected.discard(peer_id)
        if peer_id in SimulatedHost._network:
            SimulatedHost._network[peer_id]._connected.discard(self.peer_id)

    async def new_stream(self, peer_id: bytes, protocol_id: str) -> Stream:
        if peer_id not in self._connected:
            raise ConnectionError(f"Not connected to {peer_id.hex()[:16]}")

        stream_id = f"{self.peer_id.hex()[:8]}-{peer_id.hex()[:8]}-{int(time.time() * 1000)}"
        info = StreamInfo(
            stream_id=stream_id,
            protocol_id=protocol_id,
            remote_peer=peer_id,
            remote_addrs=[],
            direction="outbound",
            opened_at=int(time.time()),
        )
        stream = SimulatedStream(info)
        self._streams[stream_id] = stream
        return stream

    def set_stream_handler(self, protocol_id: str, handler: StreamHandler) -> None:
        self._handlers[protocol_id] = handler

    def connected_peers(self) -> list[bytes]:
        return list(self._connected)

    @classmethod
    def reset_network(cls) -> None:
        """Reset the simulated network (for testing)."""
        cls._network.clear()


# =============================================================================
# Full DCPP Node (combining all components)
# =============================================================================


class DCPPNode:
    """
    Complete DCPP node implementation.

    Combines:
    - libp2p host for networking
    - DHT for peer discovery
    - Protocol handler for message exchange
    - Storage for content
    """

    def __init__(
        self,
        host: HostProtocol,
        storage: StorageBackendProtocol,
        dht: DHTBackendProtocol,
        collections: list[str] | None = None,
    ):
        self.host = host
        self.storage = storage
        self.dht = dht
        self.collections = collections or []
        self._started = False

    async def start(self) -> None:
        """Start the DCPP node."""
        await self.host.start()

        # Import here to avoid circular import
        from dcpp_python.network.dht.base import CollectionDiscovery

        self.discovery = CollectionDiscovery(self.dht, self.host.peer_id)
        await self.discovery.start()

        # Announce collections
        for collection_id in self.collections:
            await self.discovery.announce_collection(collection_id, self.host.addrs)

        self._started = True
        logger.info(f"DCPP node started with peer ID {self.host.peer_id.hex()[:16]}")

    async def stop(self) -> None:
        """Stop the DCPP node."""
        if hasattr(self, "discovery"):
            await self.discovery.stop()
        await self.host.stop()
        self._started = False
        logger.info("DCPP node stopped")
