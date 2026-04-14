"""
DCPP Daemon - Network Node Implementation

This module provides the daemon entry point for running a DCPP node.
It identifies gaps in the current Python PoC that need to be filled
for full integration and system testing.

IMPLEMENTATION GAPS (for RFC compliance):
==========================================

1. NETWORK LAYER (Critical - Missing)
   - libp2p integration for control plane
   - TCP/QUIC transport support
   - Noise encryption (required by libp2p)
   - Stream multiplexing (yamux/mplex)

2. PEER DISCOVERY (Critical - Partial)
   - Kademlia DHT integration
   - DHT key computation: sha256("dcpp/1.0:" + collection_id)
   - Provider record announcement
   - Pub/sub topic subscription: /dcpp/1.0/collection/{id}
   - Bootstrap node connection (IMPLEMENTED - outbound TCP)

3. STATE MACHINE (Critical - Missing)
   - Node states: OFFLINE, CONNECTING, READY, SYNCING, GUARDING, SEEDING, DEGRADED
   - Collection states: UNKNOWN, INTERESTED, SYNCING, COMPLETE, PARTIAL, STALE
   - State transitions and timeouts

4. STORAGE BACKEND (Critical - Missing)
   - Content storage (local filesystem or other backends)
   - CID verification before storage
   - Merkle root verification
   - Shard management

5. BITTORRENT INTEGRATION (Required for data plane)
   - Torrent generation from manifest
   - BitTorrent v2 (BEP 52) support
   - Seeding coordination
   - Piece verification

6. HEALTH PROBING (Partial - Needs extension)
   - Probe scheduling (24h default interval)
   - Response time tracking
   - Peer demotion on failure
   - Rate limiting enforcement

7. RATE LIMITING (Missing)
   - Per-peer request limits (100/min)
   - ANNOUNCE rate limiting (5 min per collection)
   - Response data limits (10 MB/min)

8. SIGNATURE VERIFICATION (Partial)
   - ANNOUNCE replay protection (sequence, expiry, clock skew)
   - REVOKE signature verification

9. CONFIGURATION (Partial)
   - Configuration file support (NOT IMPLEMENTED)
   - CLI argument parsing (IMPLEMENTED - --bootstrap, --listen, --collection, etc.)
   - Environment variable support (NOT IMPLEMENTED)

10. OBSERVABILITY (Missing)
    - Metrics (Prometheus format)
    - Structured logging
    - Health check endpoint
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import json
import os
import re
import signal
import socket
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Callable, Mapping, Optional, Protocol, Tuple, TypedDict, cast
from typing_extensions import NotRequired

import cbor2


from dcpp_python.core.constants import (
    PROTOCOL_ID,
    MAX_MESSAGE_SIZE,
    MAX_PEERS_PER_COLLECTION,
    MAX_TOTAL_CONNECTIONS,
    DHT_REANNOUNCE_INTERVAL,
    ANNOUNCE_INTERVAL_SECONDS,
    DEFAULT_PROBE_INTERVAL,
    CLOCK_SKEW_TOLERANCE_SECONDS,
    MAX_CHALLENGES_PER_PROBE,
    MAGIC_BYTES,
    CONFORMANCE_DEFAULTS,
    MessageType,
    Capability,
    ErrorCode,
    validate_timestamp,
)
from dcpp_python.core.framing import (
    DCPPFramer,
    Profile1Framer,
    ChecksumError,
    MagicBytesError,
    FramingError,
    MessageTooLargeError,
)
from dcpp_python.crypto.signing import (
    generate_keypair,
    derive_peer_id,
    sign_message,
    canonical_cbor_dumps,
    sign_announce,
)
from dcpp_python.crypto.cid import compute_cid
from dcpp_python.crypto.peer_id import base58_decode, format_peer_id
from dcpp_python.core.messages import (
    Announce,
    Hello,
    GetPeers,
    PeersResponse,
    PeerInfo,
    Goodbye,
    decode_message,
    GetManifest,
    ManifestResponse,
    HealthProbe,
    HealthResponse,
    ChallengeResponse,
    CollectionAnnouncement,
    ErrorResponse,
)
from dcpp_python.storage.base import StorageBackend
from dcpp_python.storage.interfaces import CollectionMetadataStorageProtocol
from dcpp_python.storage.filesystem import FileSystemStorage
from dcpp_python.storage.memory import MemoryStorage
from dcpp_python.storage.genesis import FileSystemGenesisStore
from dcpp_python.manifest.verify import ManifestVerificationPipeline, VerificationResult
from dcpp_python.core.uci import parse_uci, UCIScheme
from dcpp_python.network.bittorrent.base import (
    DCPPTorrentManager,
    MockBitTorrentBackend,
    TorrentStatus,
    BitTorrentBackend,
)
from dcpp_python.manifest.manifest import Manifest, ItemsIndex, ManifestPayload

# Import real BitTorrent backend if available
try:
    from dcpp_python.network.bittorrent.real import (
        RealBitTorrentBackend,
        TORF_AVAILABLE,
        get_backend as get_real_backend,
        is_local_only_allowed,
    )

    BITTORRENT_REAL_AVAILABLE = True
except ImportError:
    BITTORRENT_REAL_AVAILABLE = False
    TORF_AVAILABLE = False

    def is_local_only_allowed() -> bool:
        return False


class BitTorrentBackendType(Enum):
    """BitTorrent backend selection."""

    MOCK = "mock"  # In-memory mock (test only)
    LOCAL = "local"  # Local-only real backend (no peer networking)
    REAL = "real"  # Full backend (requires torf + libtorrent)


class ExternalAddrSource(Enum):
    """Source for external/advertised address computation."""

    NONE = "none"  # Use listen address as-is (default, local/dev mode)
    STATIC = "static"  # Use configured external_addr
    HTTP = "http"  # Fetch public IP from HTTP service
    ENV = "env"  # Read from DCPP_EXTERNAL_ADDR environment variable


def _get_bt_backend_from_env() -> BitTorrentBackendType:
    """
    Get BitTorrent backend type from DCPP_BT_BACKEND environment variable.

    Valid values: mock, local, real
    Default: real (production default, requires torf for BEP 52 compliance)

    Note: mock backend requires explicit opt-in via DCPP_BT_BACKEND=mock.
    Invalid values will raise an error rather than silently defaulting.
    """
    env_value = os.environ.get("DCPP_BT_BACKEND", "real").lower()
    try:
        return BitTorrentBackendType(env_value)
    except ValueError:
        valid_values = ", ".join(t.value for t in BitTorrentBackendType)
        raise ValueError(
            f"Invalid DCPP_BT_BACKEND value '{env_value}'. "
            f"Valid values: {valid_values}. "
            f"Set DCPP_BT_BACKEND=mock explicitly if mock backend is intended."
        )


def _get_storage_path_from_env() -> Path:
    """
    Get storage path from DCPP_DATA_DIR environment variable.

    This allows Docker deployments to configure storage via environment
    variable (set in Dockerfile.python) rather than requiring --storage CLI arg.

    Default: ~/.dcpp/storage (if DCPP_DATA_DIR not set)
    """
    env_value = os.environ.get("DCPP_DATA_DIR")
    if env_value:
        return Path(env_value).expanduser().resolve()
    return Path("~/.dcpp/storage").expanduser()


def _get_probe_interval_from_env() -> int:
    """
    Get health probe interval (seconds) from environment.

    Uses DCPP_PROBE_INTERVAL_SECONDS or DCPP_PROBE_INTERVAL when set.
    Defaults to DEFAULT_PROBE_INTERVAL on missing/invalid values.
    """
    raw_value = os.environ.get("DCPP_PROBE_INTERVAL_SECONDS") or os.environ.get(
        "DCPP_PROBE_INTERVAL"
    )
    if raw_value is None:
        return DEFAULT_PROBE_INTERVAL
    try:
        value = int(raw_value)
        return value if value > 0 else DEFAULT_PROBE_INTERVAL
    except ValueError:
        return DEFAULT_PROBE_INTERVAL


# Import real libp2p if available
try:
    from dcpp_python.network.libp2p.real import (
        RealHost,
        RealHostConfig,
        DCPPRealNode,
        HostEvent,
        HostEventData,
        is_available as libp2p_available,
    )

    LIBP2P_AVAILABLE = libp2p_available()
except ImportError:
    LIBP2P_AVAILABLE = False

# Import bootstrap discovery
from dcpp_python.network.dht.bootstrap_discovery import discover_bootstrap_peers

# Import state machine
from dcpp_python.state.machine import (
    NodeStateMachine,
    NodeState as SMNodeState,
    CollectionState as SMCollectionState,
    NodeStartedEvent,
    BootstrapCompleteEvent,
    CollectionAnnounceReceivedEvent,
    ManifestReceivedEvent,
    DownloadStartedEvent,
    DownloadProgressEvent,
    DownloadCompleteEvent,
    PeerDisconnectedEvent,
    NetworkPartitionEvent,
    NetworkRecoveredEvent,
    SendAnnounceAction,
    UpdateCoverageAction,
    FetchManifestAction,
    StartDownloadAction,
    StateAction,
    LogAction,
    EmitMetricAction,
    LogLevel,
    # Host event conversion for libp2p integration
    convert_host_event_to_state_event,
    HostEventInfo,
    StateEvent,
    PeerConnectedInfo,
    PeerDisconnectedInfo,
    MessageReceivedInfo,
)
from dcpp_python.network.bittorrent.base import bt_status_from_torrent_status


# =============================================================================
# Multiaddr Parsing
# =============================================================================


def parse_multiaddr(multiaddr: str) -> Optional[Tuple[str, int]]:
    """
    Parse a multiaddr string to extract host and port for TCP connections.

    Supports formats:
        /ip4/127.0.0.1/tcp/4001
        /ip4/192.168.1.1/tcp/4001/p2p/QmPeerID
        /dns4/example.com/tcp/4001
        /ip6/::1/tcp/4001

    Returns:
        Tuple of (host, port) or None if parsing fails.
    """
    # Match IPv4 multiaddr: /ip4/<addr>/tcp/<port>
    ipv4_match = re.match(r"^/ip4/([^/]+)/tcp/(\d+)", multiaddr)
    if ipv4_match:
        return (ipv4_match.group(1), int(ipv4_match.group(2)))

    # Match IPv6 multiaddr: /ip6/<addr>/tcp/<port>
    ipv6_match = re.match(r"^/ip6/([^/]+)/tcp/(\d+)", multiaddr)
    if ipv6_match:
        return (ipv6_match.group(1), int(ipv6_match.group(2)))

    # Match DNS multiaddr: /dns4/<hostname>/tcp/<port> or /dns/<hostname>/tcp/<port>
    dns_match = re.match(r"^/dns[46]?/([^/]+)/tcp/(\d+)", multiaddr)
    if dns_match:
        return (dns_match.group(1), int(dns_match.group(2)))

    return None


# =============================================================================
# Outbound TCP Connection
# =============================================================================


@dataclass
class ConnectionHealth:
    """Health metrics for a managed connection."""

    last_activity: float = 0.0  # Unix timestamp of last activity
    consecutive_failures: int = 0
    rtt_estimate_ms: float = 0.0
    total_successes: int = 0
    total_failures: int = 0


class ConnectionManager:
    """
    Manages outbound TCP connections with health tracking and connection reuse.

    Provides:
    - Connection pooling and reuse
    - Health tracking (RTT, failure counts)
    - Automatic cleanup of failed connections
    """

    def __init__(
        self,
        max_connections: int = MAX_TOTAL_CONNECTIONS,
        max_consecutive_failures: int = 3,
        connection_timeout: float = 30.0,
        logger: Optional[logging.Logger] = None,
    ):
        self.max_connections = max_connections
        self.max_consecutive_failures = max_consecutive_failures
        self.connection_timeout = connection_timeout
        self.logger = logger or logging.getLogger("dcpp.connection_manager")

        # Connection pool: multiaddr -> (connection, health)
        self._connections: dict[str, tuple[OutboundTCPConnection, ConnectionHealth]] = {}
        self._lock = asyncio.Lock()

    async def get_or_create(self, multiaddr: str) -> Optional["OutboundTCPConnection"]:
        """
        Get an existing connection or create a new one.

        Args:
            multiaddr: Multiaddr of the peer to connect to

        Returns:
            Connected OutboundTCPConnection or None if connection failed
        """
        async with self._lock:
            # Check for existing connection
            if multiaddr in self._connections:
                conn, health = self._connections[multiaddr]
                if conn.is_connected:
                    health.last_activity = time.time()
                    return conn
                # Connection is stale, remove it
                del self._connections[multiaddr]

            # Check connection limit
            if len(self._connections) >= self.max_connections:
                # Try to evict a stale connection
                await self._evict_one()
                if len(self._connections) >= self.max_connections:
                    self.logger.warning(
                        f"Connection limit reached ({self.max_connections}), cannot connect to {multiaddr}"
                    )
                    return None

            # Create new connection
            conn_opt = OutboundTCPConnection.from_multiaddr(
                multiaddr,
                timeout=self.connection_timeout,
                logger=self.logger,
            )
            if conn_opt is None:
                self.logger.warning(f"Failed to parse multiaddr: {multiaddr}")
                return None
            conn = conn_opt

            if not await conn.connect():
                return None

            health = ConnectionHealth(last_activity=time.time())
            self._connections[multiaddr] = (conn, health)
            self.logger.debug(f"Created new connection to {multiaddr}")
            return conn

    def record_success(self, multiaddr: str, rtt_ms: float = 0.0) -> None:
        """
        Record a successful operation on a connection.

        Args:
            multiaddr: Multiaddr of the peer
            rtt_ms: Round-trip time in milliseconds (if measured)
        """
        if multiaddr not in self._connections:
            return

        _, health = self._connections[multiaddr]
        health.last_activity = time.time()
        health.consecutive_failures = 0
        health.total_successes += 1

        # Update RTT estimate with exponential moving average
        if rtt_ms > 0:
            if health.rtt_estimate_ms == 0:
                health.rtt_estimate_ms = rtt_ms
            else:
                # EMA with alpha = 0.2
                health.rtt_estimate_ms = 0.8 * health.rtt_estimate_ms + 0.2 * rtt_ms

    def record_failure(self, multiaddr: str) -> None:
        """
        Record a failed operation on a connection.

        Args:
            multiaddr: Multiaddr of the peer
        """
        if multiaddr not in self._connections:
            return

        _, health = self._connections[multiaddr]
        health.consecutive_failures += 1
        health.total_failures += 1

        # Mark for cleanup if too many failures
        if health.consecutive_failures >= self.max_consecutive_failures:
            self.logger.info(
                f"Connection to {multiaddr} marked unhealthy "
                f"({health.consecutive_failures} consecutive failures)"
            )

    async def cleanup(self) -> int:
        """
        Clean up failed and stale connections.

        Returns:
            Number of connections cleaned up
        """
        async with self._lock:
            return await self._cleanup_internal()

    async def _cleanup_internal(self) -> int:
        """Internal cleanup without lock."""
        to_remove = []

        for multiaddr, (conn, health) in self._connections.items():
            should_remove = False

            # Remove if too many consecutive failures
            if health.consecutive_failures >= self.max_consecutive_failures:
                should_remove = True
                self.logger.debug(f"Removing {multiaddr}: too many failures")

            # Remove if connection is no longer connected
            elif not conn.is_connected:
                should_remove = True
                self.logger.debug(f"Removing {multiaddr}: disconnected")

            # Remove if stale (no activity for 1 hour)
            elif time.time() - health.last_activity > 3600:
                should_remove = True
                self.logger.debug(f"Removing {multiaddr}: stale")

            if should_remove:
                to_remove.append(multiaddr)

        for multiaddr in to_remove:
            conn, _ = self._connections.pop(multiaddr)
            await conn.disconnect()

        if to_remove:
            self.logger.info(f"Cleaned up {len(to_remove)} connection(s)")

        return len(to_remove)

    async def _evict_one(self) -> bool:
        """
        Evict one connection to make room for a new one.

        Prefers connections with:
        1. Highest consecutive failures
        2. Oldest last_activity

        Returns:
            True if a connection was evicted
        """
        if not self._connections:
            return False

        # Find worst connection
        worst_addr = None
        worst_score = -1.0

        for multiaddr, (_, health) in self._connections.items():
            # Score: higher is worse
            # Prioritize failure count, then age
            score = health.consecutive_failures * 10000 + (time.time() - health.last_activity)
            if score > worst_score:
                worst_score = score
                worst_addr = multiaddr

        if worst_addr:
            conn, _ = self._connections.pop(worst_addr)
            await conn.disconnect()
            self.logger.debug(f"Evicted connection to {worst_addr}")
            return True

        return False

    def get_health(self, multiaddr: str) -> Optional[ConnectionHealth]:
        """Get health metrics for a connection."""
        if multiaddr in self._connections:
            _, health = self._connections[multiaddr]
            return health
        return None

    @property
    def active_connections(self) -> int:
        """Number of active connections."""
        return len(self._connections)

    async def close_all(self) -> None:
        """Close all connections."""
        async with self._lock:
            for multiaddr, (conn, _) in list(self._connections.items()):
                await conn.disconnect()
            self._connections.clear()
            self.logger.info("Closed all connections")


class OutboundTCPConnection:
    """
    Async TCP client for outbound connections to DCPP peers.

    WARNING: RAW TCP IS FOR TESTING ONLY.
    Production DCPP traffic MUST use libp2p with Noise encryption.
    See DCPPDaemon with use_libp2p=True (default) for production use.

    Uses full envelope framing (DCPPFramer) with:
    - Magic bytes (REQUIRED)
    - Request ID for correlation
    - CRC-32C checksum (MANDATORY)
    - Strict version checking (v1.x only)
    """

    def __init__(
        self,
        host: str,
        port: int,
        timeout: float = 30.0,
        logger: Optional[logging.Logger] = None,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.logger = logger or logging.getLogger("dcpp.tcp")
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected = False
        self._pending_request_id: int = 0  # For request/response correlation

    @classmethod
    def from_multiaddr(
        cls,
        multiaddr: str,
        timeout: float = 30.0,
        logger: Optional[logging.Logger] = None,
    ) -> Optional["OutboundTCPConnection"]:
        """Create connection from a multiaddr string."""
        parsed = parse_multiaddr(multiaddr)
        if parsed is None:
            return None
        host, port = parsed
        return cls(host=host, port=port, timeout=timeout, logger=logger)

    async def connect(self) -> bool:
        """
        Establish TCP connection to the peer.

        Returns:
            True if connection successful, False otherwise.
        """
        if self._connected:
            return True

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            self._connected = True
            self.logger.info(f"Connected to {self.host}:{self.port}")
            return True
        except asyncio.TimeoutError:
            self.logger.error(f"Connection to {self.host}:{self.port} timed out")
            return False
        except OSError as e:
            self.logger.error(f"Connection to {self.host}:{self.port} failed: {e}")
            return False

    async def disconnect(self) -> None:
        """Close the TCP connection."""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception as e:
                self.logger.debug(f"Error closing connection: {e}")
            finally:
                self._writer = None
                self._reader = None
                self._connected = False
                self.logger.info(f"Disconnected from {self.host}:{self.port}")

    @property
    def is_connected(self) -> bool:
        """Check if connection is active."""
        return self._connected and self._writer is not None

    async def send_message(
        self,
        message_type: MessageType,
        payload: bytes,
        request_id: Optional[int] = None,
    ) -> Tuple[bool, int]:
        """
        Send a DCPP message with full envelope framing (DCPPFramer).

        Args:
            message_type: DCPP message type
            payload: CBOR-encoded payload bytes
            request_id: Optional request ID (auto-generated if not provided)

        Returns:
            Tuple of (success, request_id) for correlation.
        """
        if not self.is_connected:
            self.logger.error("Cannot send: not connected")
            return (False, 0)

        try:
            if request_id is None:
                # Generate request ID for correlation
                frame, request_id = DCPPFramer.encode_request(message_type, payload)
            else:
                # Use provided request ID (for responses)
                frame = DCPPFramer.encode_response(message_type, payload, request_id)

            self._pending_request_id = request_id
            writer = self._writer
            if writer is None:
                self.logger.error("Cannot send: connection writer not initialized")
                return (False, 0)
            writer.write(frame)
            await writer.drain()
            self.logger.debug(
                f"Sent {message_type.name} (request_id={request_id}, {len(frame)} bytes)"
            )
            return (True, request_id)
        except Exception as e:
            self.logger.error(f"Send failed: {e}")
            return (False, 0)

    async def receive_message(self) -> Optional[Tuple[MessageType, bytes, int]]:
        """
        Receive a DCPP message with full envelope framing (DCPPFramer).

        Performs MANDATORY validation:
        - Magic bytes check (BEFORE reading payload)
        - Version check (BEFORE reading payload)
        - Length guard (MUST reject oversized messages)
        - CRC-32C verification (drops frame on mismatch)

        Returns:
            Tuple of (message_type, payload_bytes, request_id) or None on error.
        """
        if not self.is_connected:
            self.logger.error("Cannot receive: not connected")
            return None

        try:
            # Read full header (20 bytes for DCPPFramer)
            reader = self._reader
            if reader is None:
                self.logger.error("Cannot receive: connection reader not initialized")
                return None

            header = await asyncio.wait_for(
                reader.readexactly(DCPPFramer.HEADER_SIZE),
                timeout=self.timeout,
            )

            # Validate magic bytes BEFORE extracting length
            if header[0:4] != MAGIC_BYTES:
                self.logger.warning(f"Invalid magic bytes - dropping frame: {header[0:4]!r}")
                return None

            # Validate version BEFORE extracting length (only accept v1.0 exactly)
            version = int.from_bytes(header[4:6], "big")
            if version != 0x0100:
                self.logger.warning(
                    f"Unsupported protocol version 0x{version:04X} - "
                    "only DCPP v1.0 (0x0100) is supported"
                )
                return None

            # Parse header to get length
            # Header format: Magic(4) + Version(2) + Type(2) + RequestID(4) + Length(4) + CRC(4)
            length = int.from_bytes(header[12:16], "big")

            # Guard against oversized messages BEFORE reading payload
            if length > MAX_MESSAGE_SIZE:
                self.logger.warning(
                    f"Message too large: {length} bytes exceeds maximum {MAX_MESSAGE_SIZE}"
                )
                return None

            # Read payload
            payload = await asyncio.wait_for(
                reader.readexactly(length),
                timeout=self.timeout,
            )

            # Decode full frame with MANDATORY CRC verification
            try:
                frame = DCPPFramer.decode(header + payload)
            except MagicBytesError as e:
                self.logger.warning(f"Invalid magic bytes - dropping frame: {e}")
                return None
            except ChecksumError as e:
                self.logger.warning(f"CRC mismatch - dropping frame: {e}")
                return None
            except FramingError as e:
                self.logger.warning(f"Framing error - dropping frame: {e}")
                return None

            # Verify request ID matches - MUST reject on mismatch per spec
            if self._pending_request_id and frame.request_id != self._pending_request_id:
                self.logger.error(
                    f"Request ID mismatch: expected {self._pending_request_id}, "
                    f"got {frame.request_id} - treating as invalid response"
                )
                return None

            self.logger.debug(
                f"Received {frame.message_type.name} "
                f"(request_id={frame.request_id}, {len(frame.payload)} bytes)"
            )
            return (frame.message_type, frame.payload, frame.request_id)

        except asyncio.TimeoutError:
            self.logger.error("Receive timed out")
            return None
        except asyncio.IncompleteReadError:
            self.logger.error("Connection closed by peer")
            self._connected = False
            return None
        except Exception as e:
            self.logger.error(f"Receive failed: {e}")
            return None


# =============================================================================
# Node States (RFC Section 7)
# =============================================================================


class NodeState(Enum):
    """Node state machine states (RFC Section 7.1)."""

    OFFLINE = auto()
    CONNECTING = auto()
    READY = auto()
    SYNCING = auto()
    GUARDING = auto()
    SEEDING = auto()
    DEGRADED = auto()


class CollectionState(Enum):
    """Per-collection state (RFC Section 7.3)."""

    UNKNOWN = auto()
    INTERESTED = auto()
    SYNCING = auto()
    COMPLETE = auto()
    PARTIAL = auto()
    STALE = auto()


# =============================================================================
# Configuration
# =============================================================================


@dataclass
class DaemonConfig:
    """Daemon configuration."""

    # Network
    listen_addrs: list[str] = field(default_factory=lambda: ["/ip4/0.0.0.0/tcp/4001"])
    bootstrap_peers: list[str] = field(default_factory=list)

    # Identity
    identity_key_path: Path | None = None

    # Storage
    # Controlled by DCPP_DATA_DIR env var, defaults to ~/.dcpp/storage
    storage_path: Path = field(default_factory=_get_storage_path_from_env)

    # Collections to guard
    collections: list[str] = field(default_factory=list)

    # Capabilities
    enable_guardian: bool = True
    enable_seeder: bool = True
    enable_private: bool = True

    # Limits
    max_peers_per_collection: int = MAX_PEERS_PER_COLLECTION
    max_total_connections: int = MAX_TOTAL_CONNECTIONS

    # Probing
    probe_interval: int = field(default_factory=_get_probe_interval_from_env)
    dht_reannounce_interval: int = DHT_REANNOUNCE_INTERVAL
    announce_interval: int = ANNOUNCE_INTERVAL_SECONDS

    # Transport mode (RFC Section 3.1 compliance)
    # When True, uses libp2p with Noise encryption (spec-compliant)
    # When False, falls back to raw TCP (non-compliant interim mode)
    use_libp2p: bool = True

    # Bootstrap discovery (RFC Section 9.3)
    enable_dns_discovery: bool = True
    enable_ipns_discovery: bool = True
    bootstrap_dns_domain: str = "_dcpp-bootstrap.dcpp.network"
    bootstrap_ipns_name: str = "/ipns/bootstrap.dcpp.network"

    # External address configuration (for NAT traversal / WAN deployment)
    # advertise_addrs: explicit list of multiaddrs to announce to peers
    advertise_addrs: list[str] = field(default_factory=list)
    # external_addr_source: how to compute external address (none, static, http, env)
    external_addr_source: ExternalAddrSource = ExternalAddrSource.NONE
    # external_addr: multiaddr or host:port when external_addr_source=static
    external_addr: str | None = None
    # enable_relay: enable libp2p relay client behavior for NAT traversal
    enable_relay: bool = False
    # enable_hole_punch: enable libp2p hole punching for direct connections
    enable_hole_punch: bool = False
    # dial_timeout_secs: timeout for bootstrap dial attempts
    dial_timeout_secs: float = 30.0

    # BitTorrent backend (RFC Section 3.2)
    # Controlled by DCPP_BT_BACKEND env var: mock, local, real
    bt_backend: BitTorrentBackendType = field(default_factory=_get_bt_backend_from_env)

    # Logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    log_format_type: str = "text"  # text, json, or pretty

    # HTTP API (for health checks and status queries)
    # Enabled by default; use --no-http-api to disable
    http_api_addr: str | None = "0.0.0.0:8080"

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> "DaemonConfig":
        """Create config from command-line arguments."""
        config = cls()

        if args.listen:
            config.listen_addrs = args.listen
        if args.bootstrap:
            config.bootstrap_peers = args.bootstrap
        if args.storage:
            config.storage_path = Path(args.storage)
        if args.collections:
            config.collections = args.collections
        if args.log_level:
            config.log_level = args.log_level
        if hasattr(args, "log_format") and args.log_format:
            config.log_format_type = args.log_format
        if hasattr(args, "no_libp2p") and args.no_libp2p:
            config.use_libp2p = False

        # Bootstrap discovery flags
        if hasattr(args, "no_bootstrap_discovery") and args.no_bootstrap_discovery:
            config.enable_dns_discovery = False
            config.enable_ipns_discovery = False
        if hasattr(args, "bootstrap_dns") and args.bootstrap_dns:
            config.enable_dns_discovery = True
            config.bootstrap_dns_domain = args.bootstrap_dns
        if hasattr(args, "bootstrap_ipns") and args.bootstrap_ipns:
            config.enable_ipns_discovery = True
            config.bootstrap_ipns_name = args.bootstrap_ipns

        # External address configuration
        if hasattr(args, "advertise_addrs") and args.advertise_addrs:
            config.advertise_addrs = args.advertise_addrs
        if hasattr(args, "external_addr_source") and args.external_addr_source:
            config.external_addr_source = ExternalAddrSource(args.external_addr_source)
        if hasattr(args, "external_addr") and args.external_addr:
            config.external_addr = args.external_addr
        if hasattr(args, "enable_relay") and args.enable_relay:
            config.enable_relay = True
        if hasattr(args, "enable_hole_punch") and args.enable_hole_punch:
            config.enable_hole_punch = True
        if hasattr(args, "dial_timeout") and args.dial_timeout:
            config.dial_timeout_secs = float(args.dial_timeout)

        # HTTP API configuration
        if hasattr(args, "no_http_api") and args.no_http_api:
            config.http_api_addr = None
        elif hasattr(args, "http_api") and args.http_api:
            config.http_api_addr = args.http_api

        return config


async def compute_advertise_addrs(
    config: DaemonConfig,
    local_peer_id: bytes,
    logger: logging.Logger,
) -> list[str]:
    """
    Compute advertised addresses based on configuration.

    This determines what multiaddrs are announced to peers and included
    in DHT provider records. For nodes behind NAT, this should include
    externally routable addresses.

    Args:
        config: Daemon configuration
        local_peer_id: Local peer ID bytes
        logger: Logger instance

    Returns:
        List of multiaddr strings to advertise
    """
    advertise_addrs: list[str] = []
    peer_id_str = format_peer_id(local_peer_id) if local_peer_id else ""

    # Start with explicitly configured advertise_addrs
    if config.advertise_addrs:
        advertise_addrs.extend(config.advertise_addrs)
        logger.info(
            f"Using {len(config.advertise_addrs)} explicitly configured advertise address(es)"
        )

    # Compute external address based on source
    if config.external_addr_source == ExternalAddrSource.STATIC:
        if config.external_addr:
            external = config.external_addr
            # Ensure /p2p/<peer_id> suffix if we have a peer ID
            if peer_id_str and "/p2p/" not in external:
                external = f"{external}/p2p/{peer_id_str}"
            advertise_addrs.append(external)
            logger.info(f"External address (static): {external}")
        else:
            logger.warning("external_addr_source=static but no external_addr configured")

    elif config.external_addr_source == ExternalAddrSource.HTTP:
        # Fetch public IP from HTTP service
        public_ip = await _fetch_public_ip(logger)
        if public_ip:
            # Extract port from first listen address
            port = _extract_port_from_multiaddr(
                config.listen_addrs[0] if config.listen_addrs else "/tcp/4001"
            )
            external = f"/ip4/{public_ip}/tcp/{port}"
            if peer_id_str:
                external = f"{external}/p2p/{peer_id_str}"
            advertise_addrs.append(external)
            logger.info(f"External address (http): {external}")
        else:
            logger.warning("Failed to fetch public IP via HTTP")

    elif config.external_addr_source == ExternalAddrSource.ENV:
        env_addr = os.environ.get("DCPP_EXTERNAL_ADDR")
        if env_addr:
            if peer_id_str and "/p2p/" not in env_addr:
                env_addr = f"{env_addr}/p2p/{peer_id_str}"
            advertise_addrs.append(env_addr)
            logger.info(f"External address (env): {env_addr}")
        else:
            logger.warning("external_addr_source=env but DCPP_EXTERNAL_ADDR not set")

    # If no external addresses computed, use listen addresses
    if not advertise_addrs:
        # Convert listen addresses to full multiaddrs with peer ID
        for listen_addr in config.listen_addrs:
            addr = listen_addr
            if peer_id_str and "/p2p/" not in addr:
                addr = f"{addr}/p2p/{peer_id_str}"
            advertise_addrs.append(addr)
        logger.debug(f"Using listen addresses as advertise addresses: {advertise_addrs}")

    return advertise_addrs


async def _fetch_public_ip(logger: logging.Logger) -> str | None:
    """Fetch public IP from HTTP service (for external_addr_source=http)."""
    import aiohttp  # type: ignore[import-not-found]

    services = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]

    for service_url in services:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    service_url, timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        ip = cast(str, await response.text()).strip()
                        # Validate it looks like an IP
                        if ip and (ip.count(".") == 3 or ":" in ip):
                            logger.debug(f"Fetched public IP from {service_url}: {ip}")
                            return ip
        except Exception as e:
            logger.debug(f"Failed to fetch IP from {service_url}: {e}")
            continue

    return None


def _extract_port_from_multiaddr(multiaddr: str) -> int:
    """Extract TCP port from a multiaddr string."""
    import re

    match = re.search(r"/tcp/(\d+)", multiaddr)
    if match:
        return int(match.group(1))
    return 4001  # Default DCPP port


# =============================================================================
# HTTP API Server (Health Checks and Status)
# =============================================================================


class AppRunnerProtocol(Protocol):
    async def setup(self) -> None: ...

    async def cleanup(self) -> None: ...


class TCPSiteProtocol(Protocol):
    async def start(self) -> None: ...


class RequestProtocol(Protocol):
    match_info: Mapping[str, str]


class HealthResponsePayload(TypedDict):
    status: str
    timestamp: int


class CollectionHealthPayload(TypedDict):
    collection_id: str
    state: str
    total_items: NotRequired[int]
    total_size_bytes: NotRequired[int]
    version: NotRequired[int]
    is_stub: NotRequired[bool]
    peer_count: NotRequired[int]


class HealthDetailedPayload(TypedDict):
    status: str
    timestamp: int
    node_state: str
    peer_id: str | None
    collections: list[CollectionHealthPayload]


class CollectionStatusPayload(TypedDict):
    collection_id: str
    state: str
    coverage: float
    total_items: int
    total_size_bytes: int
    version: int
    peer_count: int
    is_stub_manifest: bool


class HttpApiServer:
    """
    Optional HTTP API server for health checks and status queries.

    Provides endpoints compatible with the Rust implementation:
    - GET /health - Basic health check (for Docker healthcheck)
    - GET /health/detailed - Detailed health with collection info
    - GET /api/v1/collections/:id/status - Collection status

    This enables:
    - Docker health checks for container orchestration
    - Test verification of node state
    - Monitoring and debugging
    """

    def __init__(
        self,
        listen_addr: str,
        daemon: "DCPPDaemon",
        logger: logging.Logger,
    ):
        """
        Initialize the HTTP API server.

        Args:
            listen_addr: Address to listen on (e.g., "0.0.0.0:8080")
            daemon: Reference to the DCPPDaemon for status queries
            logger: Logger instance
        """
        self.listen_addr = listen_addr
        self.daemon = daemon
        self.logger = logger
        self._runner: Optional[AppRunnerProtocol] = None
        self._site: Optional[TCPSiteProtocol] = None

    async def start(self) -> None:
        """Start the HTTP server."""
        try:
            from aiohttp import web
        except ImportError:
            self.logger.warning(
                "aiohttp not installed - HTTP API disabled. Install with: pip install aiohttp"
            )
            return

        # Parse listen address
        if ":" in self.listen_addr:
            host, port_str = self.listen_addr.rsplit(":", 1)
            port = int(port_str)
        else:
            host = self.listen_addr
            port = 8080

        # Create aiohttp app with routes
        app = web.Application()
        app.router.add_get("/health", self._handle_health)
        app.router.add_get("/health/detailed", self._handle_health_detailed)
        app.router.add_get(
            "/api/v1/collections/{collection_id}/status",
            self._handle_collection_status,
        )

        # Start server
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, host, port)
        await self._site.start()

        self.logger.info(f"HTTP API listening on {host}:{port}")

    async def stop(self) -> None:
        """Stop the HTTP server."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            self.logger.info("HTTP API stopped")

    async def _handle_health(self, request: object) -> object:
        """
        Handle GET /health - basic health check for Docker healthcheck.

        Returns:
            JSON response with status and timestamp
        """
        from aiohttp import web
        import time as time_module

        response_data: HealthResponsePayload = {
            "status": "ok",
            "timestamp": int(time_module.time()),
        }
        return web.json_response(response_data)

    async def _handle_health_detailed(self, request: object) -> object:
        """
        Handle GET /health/detailed - detailed health with collection info.

        Returns:
            JSON response with status, timestamp, and collection details
        """
        from aiohttp import web
        import time as time_module

        collections: list[CollectionHealthPayload] = []
        for collection_id in self.daemon.config.collections:
            collection_info: CollectionHealthPayload = {
                "collection_id": collection_id,
                "state": self.daemon.collection_states.get(
                    collection_id, CollectionState.UNKNOWN
                ).name.lower(),
            }

            # Add manifest info if available
            manifest = self.daemon._manifests.get(collection_id)
            if manifest:
                collection_info["total_items"] = manifest.total_items
                collection_info["total_size_bytes"] = manifest.total_size_bytes
                collection_info["version"] = manifest.version
                collection_info["is_stub"] = self.daemon.is_stub_manifest(collection_id)

            # Add peer count
            peer_table = self.daemon.peer_tables.get(collection_id)
            if peer_table:
                collection_info["peer_count"] = len(peer_table.peers)

            collections.append(collection_info)

        response_data: HealthDetailedPayload = {
            "status": "ok",
            "timestamp": int(time_module.time()),
            "node_state": self.daemon.state.name.lower(),
            "peer_id": format_peer_id(self.daemon._local_peer_id)
            if self.daemon._local_peer_id
            else None,
            "collections": collections,
        }
        return web.json_response(response_data)

    async def _handle_collection_status(self, request: RequestProtocol) -> object:
        """
        Handle GET /api/v1/collections/:id/status - collection status.

        Returns:
            JSON response with collection state, coverage, and item counts
        """
        from aiohttp import web
        import time as time_module

        collection_id = request.match_info["collection_id"]

        # Check if we're tracking this collection
        if collection_id not in self.daemon.config.collections:
            return web.json_response(
                {"error": "not_found", "message": f"Collection not found: {collection_id}"},
                status=404,
            )

        # Get collection state
        state = self.daemon.collection_states.get(collection_id, CollectionState.UNKNOWN)

        # Get manifest info
        manifest = self.daemon._manifests.get(collection_id)
        total_items = manifest.total_items if manifest else 0
        total_size_bytes = manifest.total_size_bytes if manifest else 0
        version = manifest.version if manifest else 0

        # Calculate coverage from storage
        # For now, use a simplified approach based on state
        coverage = 0.0
        if state == CollectionState.COMPLETE:
            coverage = 100.0
        elif state == CollectionState.SYNCING:
            coverage = 50.0  # Approximate
        elif state == CollectionState.PARTIAL:
            coverage = 25.0  # Approximate

        # Get peer count
        peer_table = self.daemon.peer_tables.get(collection_id)
        peer_count = len(peer_table.peers) if peer_table else 0

        # Determine state string (compatible with Rust)
        state_str = "waiting"
        if coverage >= 100.0:
            state_str = "seeding"
        elif coverage > 0.0:
            state_str = "downloading"

        response_data: CollectionStatusPayload = {
            "collection_id": collection_id,
            "state": state_str,
            "coverage": coverage,
            "total_items": total_items,
            "total_size_bytes": total_size_bytes,
            "version": version,
            "peer_count": peer_count,
            "is_stub_manifest": self.daemon.is_stub_manifest(collection_id),
        }
        return web.json_response(response_data)


# =============================================================================
# Peer Table (RFC Section 15.5)
# =============================================================================


@dataclass
class PeerEntry:
    """Entry in the peer table for a collection."""

    node_id: bytes
    multiaddrs: list[str]
    coverage: float
    last_seen: int
    response_quality: float = 0.5
    probe_successes: int = 0
    probe_failures: int = 0
    avg_response_time_ms: float = 0.0


class PeerTable:
    """
    Peer table for tracking collection guardians.

    Implements peer ranking algorithm from RFC Section 15.5.
    """

    def __init__(self, collection_id: str):
        self.collection_id = collection_id
        self.peers: dict[bytes, PeerEntry] = {}

    def upsert(self, node_id: bytes, multiaddrs: list[str], coverage: float) -> None:
        """Insert or update a peer entry."""
        if node_id in self.peers:
            entry = self.peers[node_id]
            entry.multiaddrs = multiaddrs
            entry.coverage = coverage
            entry.last_seen = int(time.time())
        else:
            self.peers[node_id] = PeerEntry(
                node_id=node_id,
                multiaddrs=multiaddrs,
                coverage=coverage,
                last_seen=int(time.time()),
            )

    def record_probe_result(
        self, node_id: bytes, success: bool, response_time_ms: float = 0
    ) -> None:
        """Record the result of a health probe."""
        if node_id not in self.peers:
            return

        entry = self.peers[node_id]
        if success:
            entry.probe_successes += 1
            # Rolling average of response time
            total_probes = entry.probe_successes + entry.probe_failures
            entry.avg_response_time_ms = (
                entry.avg_response_time_ms * (total_probes - 1) + response_time_ms
            ) / total_probes
        else:
            entry.probe_failures += 1

        # Update response quality
        entry.response_quality = self._calculate_quality(entry)

    def _calculate_quality(self, entry: PeerEntry) -> float:
        """
        Calculate peer quality score (RFC Section 15.5).

        score = (
            0.4 * (1.0 - avg_response_time / 5.0).clamp(0, 1) +  // Speed
            0.3 * successful_probes / total_probes +              // Reliability
            0.2 * coverage +                                       // Coverage
            0.1 * (1.0 if last_seen < 1hr else 0.5)               // Freshness
        )
        """
        total_probes = entry.probe_successes + entry.probe_failures
        if total_probes == 0:
            return 0.5  # Unknown

        # Speed (0-1, higher is better)
        speed_score = max(0.0, min(1.0, 1.0 - entry.avg_response_time_ms / 5000.0))

        # Reliability (0-1)
        reliability_score = entry.probe_successes / total_probes

        # Coverage (0-1)
        coverage_score = entry.coverage

        # Freshness (1.0 if seen in last hour, 0.5 otherwise)
        age = time.time() - entry.last_seen
        freshness_score = 1.0 if age < 3600 else 0.5

        return (
            0.4 * speed_score
            + 0.3 * reliability_score
            + 0.2 * coverage_score
            + 0.1 * freshness_score
        )

    def get_top_peers(self, n: int) -> list[PeerEntry]:
        """Get top N peers by quality score."""
        sorted_peers = sorted(
            self.peers.values(),
            key=lambda p: self._calculate_quality(p),
            reverse=True,
        )
        return sorted_peers[:n]

    def cleanup_stale(self, max_age_seconds: int = 86400) -> int:
        """
        Remove stale peers from the table.

        A peer is considered stale if:
        - last_seen is older than max_age_seconds (default 24 hours)
        - response_quality is below 0.1 (very poor)

        Args:
            max_age_seconds: Maximum age in seconds before considering stale

        Returns:
            Number of peers removed
        """
        now = int(time.time())
        to_remove = []

        for node_id, entry in self.peers.items():
            age = now - entry.last_seen
            if age > max_age_seconds or entry.response_quality < 0.1:
                to_remove.append(node_id)

        for node_id in to_remove:
            del self.peers[node_id]

        return len(to_remove)

    def peer_count(self) -> int:
        """Get the number of peers in the table."""
        return len(self.peers)


# =============================================================================
# Daemon Core
# =============================================================================


class DCPPDaemon:
    """
    DCPP Network Daemon

    Implements the DCPP network node with support for:
    - libp2p networking with Noise encryption (spec-compliant, when py-libp2p is installed)
    - Fallback to raw TCP (non-compliant interim mode)
    - DHT-based peer discovery
    - GossipSub announcements
    - Health probing
    - Storage backend for content storage (RFC Section 4)
    - BitTorrent integration for data plane (RFC Section 3.2)
    """

    def __init__(self, config: DaemonConfig):
        self.config = config
        self.state = NodeState.OFFLINE
        self.collection_states: dict[str, CollectionState] = {}
        self.peer_tables: dict[str, PeerTable] = {}
        self.logger = logging.getLogger("dcpp.daemon")
        self._shutdown_event = asyncio.Event()
        self._tasks: list[asyncio.Task[None]] = []

        # Determine transport mode
        self._use_libp2p = config.use_libp2p and LIBP2P_AVAILABLE
        if config.use_libp2p and not LIBP2P_AVAILABLE:
            # This should not happen if main() is used, as it checks and exits first.
            # But if DCPPDaemon is instantiated directly, raise an error.
            raise RuntimeError(
                "libp2p requested but not available. Install with: pip install libp2p. "
                "Or set use_libp2p=False to use raw TCP (non-compliant with RFC Section 3.1)."
            )

        # libp2p networking (when available)
        self._libp2p_node: Optional[DCPPRealNode] = None

        # Fallback raw TCP networking
        self._connections: dict[str, OutboundTCPConnection] = {}  # multiaddr -> connection
        self._connection_manager = ConnectionManager(
            max_connections=config.max_total_connections,
            logger=self.logger,
        )
        self._signing_key, self._verify_key = generate_keypair()
        self._local_peer_id = derive_peer_id(self._verify_key)
        self._announce_seq = int(time.time())
        self._announce_coverage: dict[str, float] = {}

        # Storage backend (RFC Section 4 - Data Plane)
        self._storage: StorageBackend = FileSystemStorage(config.storage_path)
        self.logger.info(f"Storage backend: FileSystemStorage at {config.storage_path}")

        # Manifest verification (RFC Sections 7.4, 7.5)
        self._genesis_store = FileSystemGenesisStore(config.storage_path)
        self._manifest_verifier = ManifestVerificationPipeline(self._genesis_store)

        # BitTorrent manager (RFC Section 3.2 - BitTorrent Integration)
        bt_download_dir = config.storage_path / "torrents"
        bt_download_dir.mkdir(parents=True, exist_ok=True)
        bt_backend = self._create_bt_backend(config.bt_backend, bt_download_dir)
        self._torrent_manager = DCPPTorrentManager(bt_backend, bt_download_dir)
        self.logger.info(
            f"BitTorrent manager initialized ({config.bt_backend.value} backend, download dir: {bt_download_dir})"
        )

        # Collection manifests cache
        self._manifests: dict[str, Manifest] = {}
        # Track which manifests are stubs (created locally, not from peers)
        # These should be replaced on first real MANIFEST message from peers

        # State machine (RFC Section 7)
        self._state_machine = NodeStateMachine()
        self._stub_manifests: set[str] = set()

        # Computed advertise addresses (for DHT provider records, peer announcements)
        # Populated during start() based on config.external_addr_source
        self._advertise_addrs: list[str] = []

        # HTTP API server (optional - for health checks and status queries)
        self._http_server: Optional[HttpApiServer] = None

    def _sign_manifest_if_possible(self, collection_id: str, manifest: Manifest) -> bytes | None:
        """
        Sign a manifest if this node holds the corresponding key: scheme private key.
        """
        try:
            uci = parse_uci(collection_id)
        except Exception as e:
            self.logger.debug(f"Cannot parse collection ID for signing: {e}")
            return None

        if uci.scheme != UCIScheme.KEY:
            return None
        if uci.algorithm not in (None, "ed25519"):
            self.logger.warning(f"Unsupported key algorithm for signing: {uci.algorithm}")
            return None
        if uci.pubkey_bytes != bytes(self._verify_key):
            self.logger.debug("Manifest signing skipped: node key does not match collection key")
            return None

        try:
            payload = cast(dict[str, object], manifest.to_dict())
            return sign_message(payload, self._signing_key)
        except Exception as e:
            self.logger.error(f"Manifest signing failed: {e}")
            return None

    def _create_bt_backend(
        self, backend_type: BitTorrentBackendType, download_dir: Path
    ) -> BitTorrentBackend:
        """
        Create the BitTorrent backend based on configuration.

        Args:
            backend_type: Type of backend to create (from DCPP_BT_BACKEND env var)
            download_dir: Download directory for torrents

        Returns:
            BitTorrentBackend instance

        Raises:
            RuntimeError: If required dependencies are missing for the requested backend

        Selection logic (production-safe):
            - mock: Explicit opt-in only (DCPP_BT_BACKEND=mock), test-only, in-memory
            - local: Use TorfBackend for BEP 52 compliance (requires torf)
            - real: Use TorfBackend for BEP 52 compliance (requires torf + libtorrent)

        RFC 3.2 requires BEP 52 compliant info hashes. Mock backend does not provide
        this and is only for testing. Production deployments MUST use local or real
        with torf installed.

        Fallback behavior (when DCPP_BT_ALLOW_LOCAL=1, default):
            If torf is not available but DCPP_BT_ALLOW_LOCAL is set, falls back to
            native RealBitTorrentBackend. This allows local-only torrent operations
            without BEP 52 compliance. Useful for development/testing without torf.
        """
        if backend_type == BitTorrentBackendType.MOCK:
            # Mock backend explicitly requested - this is intentional for testing
            self.logger.warning(
                "Using MockBitTorrentBackend (test-only, in-memory). "
                "This backend is NOT compliant with RFC 3.2 (BEP 52). "
                "For production, use DCPP_BT_BACKEND=local or DCPP_BT_BACKEND=real with torf installed."
            )
            return MockBitTorrentBackend()

        # For local/real backends, we require torf for BEP 52 compliance
        if backend_type in (BitTorrentBackendType.LOCAL, BitTorrentBackendType.REAL):
            if not BITTORRENT_REAL_AVAILABLE:
                raise RuntimeError(
                    f"DCPP_BT_BACKEND={backend_type.value} requested but bittorrent_real module "
                    "is not available. This is required for production. "
                    "Ensure the dcpp_python package is properly installed."
                )

            if not TORF_AVAILABLE:
                # Check if local-only fallback is allowed (DCPP_BT_ALLOW_LOCAL)
                if is_local_only_allowed():
                    self.logger.warning(
                        f"DCPP_BT_BACKEND={backend_type.value} requested but torf is not available. "
                        "Falling back to native RealBitTorrentBackend (DCPP_BT_ALLOW_LOCAL=1). "
                        "WARNING: Torrents created will NOT be BEP 52 compliant. "
                        "For spec compliance, install torf>=4.0.0."
                    )
                    return RealBitTorrentBackend(download_dir)
                else:
                    raise RuntimeError(
                        f"DCPP_BT_BACKEND={backend_type.value} requested but torf library is not installed. "
                        "RFC 3.2 requires BEP 52 compliant info hashes which need torf>=4.0.0. "
                        "Install with: pip install torf>=4.0.0\n"
                        "For testing only, set DCPP_BT_BACKEND=mock explicitly.\n"
                        "For local-only (non-compliant) torrents, set DCPP_BT_ALLOW_LOCAL=1."
                    )

            # Use get_real_backend which returns TorfBackend (BEP 52 compliant)
            backend = get_real_backend(download_dir)
            self.logger.info(
                f"Using TorfBackend ({backend_type.value} mode, BEP 52 compliant, "
                f"download_dir={download_dir})"
            )
            return backend

        # Should not reach here due to enum validation
        raise ValueError(f"Unknown backend type: {backend_type}")

    def _create_stub_manifest(self, collection_id: str) -> Manifest:
        """
        Create a stub manifest for a collection (RFC Section 8).

        BOOTSTRAP BEHAVIOR: This creates a minimal placeholder manifest when
        no manifest exists for a collection. This is expected during node
        bootstrap before syncing with peers.

        The stub manifest:
        - Has version=1, total_items=0, total_size_bytes=0
        - Has a placeholder merkle_root ("0" * 64)
        - Should be replaced when receiving a real MANIFEST from peers

        Use `is_stub_manifest()` to check if a manifest is a stub.
        Use `update_manifest()` to replace a stub with a real manifest.
        """
        import time
        import hashlib
        from dcpp_python.manifest.manifest import TorrentInfo, SourceInfo

        now = int(time.time())

        # Generate stub torrent info
        infohash = hashlib.sha256(collection_id.encode()).hexdigest()
        magnet_uri = f"magnet:?xt=urn:btmh:1220{infohash}&dn={collection_id}"

        torrent_info = TorrentInfo(
            infohash=infohash,
            magnet=magnet_uri,
            piece_length=262144,  # 256 KiB
        )

        # Determine source info from collection_id
        source_info = None
        if collection_id.startswith("eth:"):
            contract = collection_id[4:]
            source_info = SourceInfo(type="blockchain", chain="eth", contract=contract)

        manifest = Manifest(
            protocol="dcpp/1.0",
            type="nft-collection" if collection_id.startswith("eth:") else "custom",
            access_mode="public",
            collection_id=collection_id,
            name=f"Collection {collection_id}",
            version=1,
            created_at=now,
            updated_at=now,
            total_items=0,  # Stub: no items yet
            total_size_bytes=0,
            merkle_root="0" * 64,  # Stub merkle root
            torrent=torrent_info,
            source=source_info,
            probe_interval=3600,  # 1 hour
        )

        # Track this as a stub manifest
        self._stub_manifests.add(collection_id)
        self.logger.info(
            f"Created STUB manifest for {collection_id} (bootstrap placeholder). "
            f"Will be replaced when real MANIFEST received from peers."
        )
        return manifest

    def _load_manifests_from_storage(self) -> None:
        """Load existing manifests from storage into memory."""
        storage = cast(CollectionMetadataStorageProtocol, self._storage)
        for collection_id in self.config.collections:
            try:
                metadata = storage.get_collection_metadata(collection_id)
            except Exception as e:
                self.logger.warning(f"Failed to read stored manifest for {collection_id}: {e}")
                continue

            if not metadata:
                continue

            try:
                manifest = Manifest.from_dict(metadata)
            except Exception as e:
                self.logger.warning(f"Stored manifest for {collection_id} is invalid: {e}")
                continue

            if manifest.collection_id != collection_id:
                self.logger.warning(
                    f"Stored manifest collection_id mismatch: expected {collection_id}, "
                    f"got {manifest.collection_id}"
                )
                continue

            self._manifests[collection_id] = manifest
            self._stub_manifests.discard(collection_id)
            self.logger.info(
                f"Loaded manifest for {collection_id} from storage "
                f"(version={manifest.version}, items={manifest.total_items})"
            )

    def is_stub_manifest(self, collection_id: str) -> bool:
        """
        Check if a collection's manifest is a stub (placeholder).

        Stub manifests are created during bootstrap and should be replaced
        when a real MANIFEST message is received from peers.
        """
        return collection_id in self._stub_manifests

    def update_manifest(self, collection_id: str, manifest: Manifest) -> bool:
        """
        Update the manifest for a collection.

        If the collection had a stub manifest, it will be replaced and
        a log message will indicate the transition.

        Args:
            collection_id: Collection ID
            manifest: New manifest to store

        Returns:
            True if this replaced a stub manifest, False otherwise
        """
        was_stub = collection_id in self._stub_manifests
        self._manifests[collection_id] = manifest

        # Persist manifest to disk for durability and cross-node verification
        storage = cast(CollectionMetadataStorageProtocol, self._storage)
        if not storage.collection_exists(collection_id):
            storage.create_collection(collection_id, manifest.to_dict())
        else:
            storage.set_collection_metadata(collection_id, manifest.to_dict())

        if was_stub:
            self._stub_manifests.discard(collection_id)
            self.logger.info(
                f"Replaced STUB manifest for {collection_id} with real manifest "
                f"(version={manifest.version}, items={manifest.total_items})"
            )
        else:
            self.logger.debug(
                f"Updated manifest for {collection_id} "
                f"(version={manifest.version}, items={manifest.total_items})"
            )

        return was_stub

    def get_manifest(self, collection_id: str, warn_if_stub: bool = True) -> Manifest | None:
        """
        Get manifest for a collection.

        Returns cached manifest or creates a stub manifest if none exists.

        BOOTSTRAP BEHAVIOR: If no manifest exists, a stub is created.
        This is expected during bootstrap before syncing with peers.

        Args:
            collection_id: Collection ID
            warn_if_stub: If True, log warning when serving stub manifest to peers

        Returns:
            Manifest or None if collection unknown
        """
        if collection_id not in self._manifests:
            # Create stub manifest for this collection
            self._manifests[collection_id] = self._create_stub_manifest(collection_id)

        manifest = self._manifests.get(collection_id)

        # Warn when serving stub manifest (likely to peers requesting it)
        if warn_if_stub and manifest and self.is_stub_manifest(collection_id):
            self.logger.warning(
                f"Serving STUB manifest for {collection_id}. "
                f"This is a placeholder - real manifest should be fetched from peers."
            )

        return manifest

    async def handle_received_manifest(
        self,
        collection_id: str,
        manifest_dict: ManifestPayload,
        source_peer: str = "unknown",
        signature: bytes | None = None,
    ) -> bool:
        """
        Handle a manifest received from a peer (e.g., via MANIFEST response).

        This method validates the manifest and stores it, clearing any stub
        tracking for the collection. Per RFC Section 7.4, the first valid
        manifest establishes genesis.

        Args:
            collection_id: Collection ID
            manifest_dict: Manifest data as dictionary (from CBOR decode)
            source_peer: Identifier of the peer that sent the manifest (for logging)

        Returns:
            True if manifest was accepted and stored, False if rejected
        """
        try:
            # Parse the manifest
            manifest = Manifest.from_dict(manifest_dict)

            # Validate collection_id matches
            if manifest.collection_id != collection_id:
                self.logger.warning(
                    f"Rejecting manifest from {source_peer}: collection_id mismatch "
                    f"(expected {collection_id}, got {manifest.collection_id})"
                )
                return False

            manifest_payload = cast(dict[str, object], manifest.to_dict())
            manifest_bytes = canonical_cbor_dumps(manifest_payload)
            manifest_cid = compute_cid(manifest_bytes)

            verification = await self._manifest_verifier.verify(
                collection_id,
                manifest,
                manifest_cid,
                signature=signature,
            )
            allow_skipped = os.environ.get("DCPP_ACCEPT_SKIPPED_MANIFESTS", "0") == "1"
            if verification.is_skipped and allow_skipped:
                self.logger.warning(
                    f"Accepting skipped verification for {collection_id} from {source_peer}: "
                    f"{verification.scheme.value} ({verification.message})"
                )
                verification = VerificationResult.tofu_accepted(
                    verification.scheme,
                    manifest_cid,
                    "Skipped verification accepted by configuration",
                )

            if not verification.is_success:
                self.logger.warning(
                    f"Rejecting manifest from {source_peer} for {collection_id}: "
                    f"{verification.scheme.value} verification {verification.status.value} "
                    f"({verification.message})"
                )
                return False

            self.logger.info(
                f"Received manifest for {collection_id} from {source_peer} "
                f"(version={manifest.version}, items={manifest.total_items}, "
                f"verification={verification.status.value})"
            )

            # Store the manifest, clearing stub tracking if applicable
            was_stub = self.update_manifest(collection_id, manifest)
            if was_stub:
                self.logger.info(
                    f"Stub manifest for {collection_id} replaced with real manifest from {source_peer}"
                )

            return True

        except Exception as e:
            self.logger.error(
                f"Failed to process manifest from {source_peer} for {collection_id}: {e}"
            )
            return False

    def store_content(self, collection_id: str, cid: str, data: bytes) -> bool:
        """
        Store content in the storage backend with CID verification.

        Args:
            collection_id: Collection ID
            cid: Content identifier (IPFS CID)
            data: Content bytes

        Returns:
            True if stored successfully
        """
        return self._storage.store(collection_id, cid, data)

    def retrieve_content(self, collection_id: str, cid: str) -> bytes | None:
        """
        Retrieve content from the storage backend.

        Args:
            collection_id: Collection ID
            cid: Content identifier

        Returns:
            Content bytes or None if not found
        """
        return self._storage.retrieve_verified(collection_id, cid)

    def get_storage_stats(self) -> dict[str, object]:
        """Get storage statistics."""
        stats = self._storage.get_stats()
        return {
            "total_items": stats.total_items,
            "total_size_bytes": stats.total_size_bytes,
            "collections": stats.collections,
        }

    async def start(self) -> None:
        """Start the daemon."""
        self.logger.info("Starting DCPP daemon...")
        self.logger.info(f"Protocol: {PROTOCOL_ID}")

        # Log transport mode explicitly for cross-impl debugging
        if self._use_libp2p:
            self.logger.info("Transport: libp2p with Noise encryption (RFC 3.1 compliant)")
            self.logger.info(
                "NOTE: Python libp2p mode uses py-libp2p. "
                "For cross-impl testing with Rust, ensure bootstrap multiaddrs include /p2p/<peer_id>."
            )
        else:
            self.logger.warning(
                "Transport: raw TCP (NON-COMPLIANT with RFC Section 3.1). "
                "This mode is for testing only and will NOT interoperate with libp2p nodes."
            )

        self.logger.info(f"Listen addresses: {self.config.listen_addrs}")
        self.logger.info(f"Bootstrap peers: {self.config.bootstrap_peers}")
        self.logger.info(f"Collections: {self.config.collections}")

        # Fire NodeStarted event (RFC Section 7)
        self._process_state_event(NodeStartedEvent())

        # Initialize peer tables for each collection BEFORE bootstrap
        # so that _connect_to_bootstrap_peer() can populate them
        for collection_id in self.config.collections:
            self.peer_tables[collection_id] = PeerTable(collection_id)
            self.collection_states[collection_id] = CollectionState.INTERESTED
            self._announce_coverage.setdefault(collection_id, 0.0)
            # Register interest with state machine
            self._state_machine.register_interest(collection_id)

        if self._use_libp2p:
            # Initialize libp2p host with Noise encryption (RFC Section 3.1 compliant)
            await self._start_libp2p()
        else:
            # Fallback to raw TCP (non-compliant interim mode)
            self.logger.info(f"Local peer ID: {format_peer_id(self._local_peer_id)}")
            # Always attempt bootstrap - _bootstrap() handles DNS/IPNS discovery
            # when no CLI peers are provided (RFC Section 9.3)
            await self._bootstrap()

        # Compute advertise addresses (for DHT provider records, peer announcements)
        self._advertise_addrs = await compute_advertise_addrs(
            self.config, self._local_peer_id, self.logger
        )
        self.logger.info(f"Advertise addresses for DHT provider records: {self._advertise_addrs}")

        # Update libp2p host with computed advertise addresses so they're used
        # as default for all DHT provider records (RFC Section 9.1)
        if self._libp2p_node and self._advertise_addrs:
            self._libp2p_node.set_advertise_addrs(self._advertise_addrs)

        # Load any pre-existing manifests from storage before announcing.
        self._load_manifests_from_storage()

        # Fallback: Try to fetch manifests via HTTP from bootstrap sources.
        # This helps data-plane tests when GossipSub ANNOUNCE is delayed or missed.
        for collection_id in self.config.collections:
            if self.is_stub_manifest(collection_id) or collection_id not in self._manifests:
                fetched = await self._fetch_manifest_via_http(
                    collection_id,
                    attempts=3,
                    log_fail=True,
                )
                if not fetched:
                    asyncio.create_task(self._fetch_manifest_via_http(collection_id))

        # Initial DHT announcements (includes advertise_addrs in provider records)
        # RFC Section 6.3 line 298: "the announcing node MUST be able to provide
        # the manifest immediately or upon the receiver's first GET_MANIFEST request"
        # Therefore, we MUST NOT announce collections where we only have stub manifests.
        if self._libp2p_node:
            for collection_id in self.config.collections:
                # RFC compliance: only announce if we have a real manifest
                if self.is_stub_manifest(collection_id) or collection_id not in self._manifests:
                    self.logger.info(
                        f"Skipping initial DHT announce for {collection_id}: no real manifest available. "
                        f"Will announce after receiving manifest from peers."
                    )
                    continue
                try:
                    await self._libp2p_node.announce_collection(
                        collection_id, self._advertise_addrs
                    )
                except Exception as e:
                    self.logger.warning(f"Initial DHT announce failed for {collection_id}: {e}")

        # Start HTTP API server if configured
        if self.config.http_api_addr:
            self._http_server = HttpApiServer(
                self.config.http_api_addr,
                self,
                self.logger,
            )
            await self._http_server.start()

        # Start background tasks
        self._tasks.append(asyncio.create_task(self._dht_announce_loop()))
        self._tasks.append(asyncio.create_task(self._announce_loop()))
        self._tasks.append(asyncio.create_task(self._health_probe_loop()))
        self._tasks.append(asyncio.create_task(self._peer_maintenance_loop()))

        if self._use_libp2p:
            # Start libp2p event loop
            self._tasks.append(asyncio.create_task(self._libp2p_event_loop()))

        # Fire BootstrapComplete event with actual peer count (RFC Section 7)
        # DO NOT use max(1, peer_count) - that would bypass spec's degraded-path behavior
        # Zero peers correctly transitions to Degraded state per the state machine
        peer_count = (
            len(self._libp2p_node.connected_peers())
            if self._libp2p_node
            else len(self._connections)
        )
        self._process_state_event(BootstrapCompleteEvent(peer_count=peer_count))

        if peer_count == 0:
            self.logger.warning(
                "Bootstrap complete with 0 connected peers - node is in DEGRADED state. "
                "This is expected for bootstrap nodes or if DNS/IPNS discovery found no peers."
            )
        else:
            self.logger.info(f"Daemon started successfully (connected peers: {peer_count})")

        # Wait for shutdown
        await self._shutdown_event.wait()

    async def _start_libp2p(self) -> None:
        """Initialize and start the libp2p host with Noise encryption."""
        # Collect bootstrap peers from CLI and DNS/IPNS discovery (RFC Section 9.3)
        all_bootstrap_addrs: list[str] = list(self.config.bootstrap_peers)

        # DNS/IPNS discovery (RFC Section 9.3 - MUST be used in libp2p mode)
        if self.config.enable_dns_discovery or self.config.enable_ipns_discovery:
            self.logger.info("Discovering bootstrap peers via DNS/IPNS (RFC 9.3)...")
            discovered_peers = await discover_bootstrap_peers(
                enable_dns=self.config.enable_dns_discovery,
                enable_ipns=self.config.enable_ipns_discovery,
                dns_domain=self.config.bootstrap_dns_domain,
                ipns_name=self.config.bootstrap_ipns_name,
            )
            if discovered_peers:
                self.logger.info(
                    f"Discovered {len(discovered_peers)} bootstrap peer(s) via DNS/IPNS"
                )
                all_bootstrap_addrs.extend(discovered_peers)
            else:
                self.logger.debug("No peers discovered via DNS/IPNS")

        # Parse and validate bootstrap peers into (peer_id, multiaddr) tuples
        # Multiaddrs with /p2p/<peer_id> suffix are preferred for Kademlia routing
        bootstrap_tuples: list[tuple[bytes, str]] = []
        for addr in all_bootstrap_addrs:
            peer_id, normalized_addr = self._parse_bootstrap_multiaddr(addr)
            bootstrap_tuples.append((peer_id, normalized_addr))

        libp2p_config = RealHostConfig(
            listen_addrs=self.config.listen_addrs,
            bootstrap_peers=bootstrap_tuples,
            enable_dht=True,
            enable_gossipsub=True,
            dht_reannounce_interval=self.config.dht_reannounce_interval,
            advertise_addrs=self.config.advertise_addrs,
            enable_relay=self.config.enable_relay,
            enable_hole_punch=self.config.enable_hole_punch,
        )

        self._libp2p_node = DCPPRealNode(libp2p_config, self.config.collections)
        await self._libp2p_node.start()

        self._local_peer_id = self._libp2p_node.peer_id
        self.logger.info(f"Local peer ID: {format_peer_id(self._local_peer_id)}")

        # Bootstrap with all discovered peers
        if bootstrap_tuples:
            self.logger.info(f"Bootstrapping with {len(bootstrap_tuples)} peer(s)...")
            await self._libp2p_node.bootstrap(bootstrap_tuples)
        else:
            self.logger.info(
                "No bootstrap peers configured - running as bootstrap node. "
                "Other nodes should bootstrap to this node's address."
            )

        # Note: Initial DHT announcements are done in start() after compute_advertise_addrs()
        # to ensure external addresses are included in provider records

    def _parse_bootstrap_multiaddr(self, addr: str) -> tuple[bytes, str]:
        """
        Parse a bootstrap multiaddr and extract peer ID if present.

        For Kademlia routing to work, bootstrap addresses should include /p2p/<peer_id>.
        Without the peer ID, we can still connect but won't seed the routing table.

        Args:
            addr: Multiaddr string (e.g., "/ip4/1.2.3.4/tcp/4001/p2p/QmPeer...")

        Returns:
            Tuple of (peer_id_bytes, multiaddr_string)
            peer_id_bytes is empty if no /p2p/ component found
        """
        peer_id = b""

        # Check for /p2p/<peer_id> suffix
        if "/p2p/" in addr:
            parts = addr.split("/p2p/")
            if len(parts) == 2:
                peer_id_str = parts[1].split("/")[0]  # Handle any trailing components
                try:
                    # Decode base58 peer ID to raw multihash bytes for libp2p
                    peer_id = base58_decode(peer_id_str)
                    self.logger.debug(f"Bootstrap peer has peer ID: {peer_id_str[:16]}...")
                except Exception as e:
                    self.logger.warning(f"Failed to parse peer ID from {addr}: {e}")
        else:
            # Check for DCPP_BOOTSTRAP_PEER_ID environment variable as fallback
            import os

            env_peer_id = os.environ.get("DCPP_BOOTSTRAP_PEER_ID", "")
            if env_peer_id:
                try:
                    peer_id = base58_decode(env_peer_id)
                    self.logger.info(
                        f"Using DCPP_BOOTSTRAP_PEER_ID for address {addr}: {env_peer_id[:16]}..."
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Failed to parse DCPP_BOOTSTRAP_PEER_ID '{env_peer_id[:16]}...': {e}"
                    )
            else:
                self.logger.debug(
                    f"Bootstrap address lacks /p2p/<peer_id>: {addr}. "
                    "Set DCPP_BOOTSTRAP_PEER_ID env var or use full multiaddr. "
                    "Connection may fail without peer ID."
                )

        return (peer_id, addr)

    async def _libp2p_event_loop(self) -> None:
        """Process events from the libp2p host."""
        while not self._shutdown_event.is_set():
            try:
                if self._libp2p_node:
                    event = await self._libp2p_node.next_event()
                    if event:
                        await self._handle_libp2p_event(event)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"libp2p event loop error: {e}")

    async def _handle_libp2p_event(self, event: HostEventData) -> None:
        """Handle a libp2p host event with state machine integration."""
        # Convert to HostEventInfo and potentially to StateEvent
        host_event_info: Optional[HostEventInfo] = None
        state_event: Optional[StateEvent] = None

        if event.event_type == HostEvent.PEER_CONNECTED:
            self.logger.info(f"Peer connected: {format_peer_id(event.peer_id)}")
            if event.peer_id:
                for collection_id in self.config.collections:
                    if collection_id in self.peer_tables:
                        self.peer_tables[collection_id].upsert(
                            event.peer_id,
                            [],
                            0.0,  # Coverage unknown until ANNOUNCE/HELLO
                        )
                    if self._use_libp2p and self._libp2p_node:
                        asyncio.create_task(self._probe_peer_libp2p(event.peer_id, collection_id))
                host_event_info = PeerConnectedInfo(peer_id=event.peer_id)

        elif event.event_type == HostEvent.PEER_DISCONNECTED:
            self.logger.info(f"Peer disconnected: {format_peer_id(event.peer_id)}")
            if event.peer_id:
                host_event_info = PeerDisconnectedInfo(peer_id=event.peer_id)

        elif event.event_type == HostEvent.DCPP_REQUEST:
            # Handle incoming DCPP protocol message
            await self._handle_dcpp_request(event)
            # Create MessageReceivedInfo for state machine if it's an ANNOUNCE
            if event.message_type == MessageType.ANNOUNCE and event.peer_id:
                # Try to extract collection info from payload
                try:
                    if event.payload is None:
                        return
                    announce = cast(Announce, decode_message(MessageType.ANNOUNCE, event.payload))
                    # ANNOUNCE contains a list of CollectionAnnouncement objects
                    # Process each collection separately for the state machine
                    for collection_ann in announce.collections:
                        self.logger.info(
                            f"Received ANNOUNCE from {format_peer_id(announce.node_id)} "
                            f"for collection {collection_ann.id} (coverage: {collection_ann.coverage:.0%})"
                        )
                        host_event_info = MessageReceivedInfo(
                            peer_id=event.peer_id,
                            message_type=event.message_type,
                            collection_id=collection_ann.id,
                            manifest_cid=collection_ann.manifest_cid,
                            coverage=collection_ann.coverage,
                        )
                        # Process each collection announcement
                        state_event = convert_host_event_to_state_event(host_event_info)
                        if state_event:
                            self._process_state_event(state_event)
                    # Clear host_event_info since we processed inline
                    host_event_info = None
                except Exception as e:
                    self.logger.debug(f"Failed to parse ANNOUNCE for state machine: {e}")

        elif event.event_type == HostEvent.GOSSIP_MESSAGE:
            # Handle GossipSub announcement
            self.logger.debug(f"Gossip message on {event.topic}")
            # GossipSub messages contain raw CBOR (not framed) in event.data
            if event.data:
                try:
                    announce = cast(Announce, decode_message(MessageType.ANNOUNCE, event.data))
                    self.logger.info(
                        f"Received ANNOUNCE via GossipSub from {format_peer_id(announce.node_id)} "
                        f"(relayed by {format_peer_id(event.peer_id)})"
                    )
                    # Process each collection in the ANNOUNCE
                    for collection_ann in announce.collections:
                        self.logger.info(
                            f"  Collection: {collection_ann.id} "
                            f"(manifest_cid: {collection_ann.manifest_cid[:16]}..., "
                            f"coverage: {collection_ann.coverage:.0%})"
                        )
                        # Create state machine event for interested collections
                        # Use the relay peer (event.peer_id) for manifest fetch since that's
                        # the peer we're connected to. The announce.node_id is the original
                        # author but may not be directly reachable.
                        if collection_ann.id in self.config.collections:
                            # Prefer the GossipSub relay peer for fetching
                            fetch_peer = event.peer_id if event.peer_id else announce.node_id
                            state_event = CollectionAnnounceReceivedEvent(
                                collection_id=collection_ann.id,
                                manifest_cid=collection_ann.manifest_cid,
                                source_peer=fetch_peer,
                                coverage=collection_ann.coverage,
                            )
                            self._process_state_event(state_event)
                except Exception as e:
                    self.logger.debug(f"Failed to parse GossipSub message as ANNOUNCE: {e}")

        elif event.event_type == HostEvent.PROVIDER_FOUND:
            # Handle DHT provider discovery
            self.logger.debug(
                f"DHT provider found for key {event.key.hex()[:16] if event.key else 'unknown'}..."
            )
            # No collection_id mapping available for ProviderFoundInfo in this context.

        # Convert host event to state event if applicable
        if host_event_info:
            state_event = convert_host_event_to_state_event(host_event_info)
            if state_event:
                self._process_state_event(state_event)

    async def _handle_dcpp_request(self, event: HostEventData) -> None:
        """Handle an incoming DCPP protocol request over libp2p."""
        if event.message_type is None or event.payload is None:
            return
        payload = event.payload

        try:
            if event.message_type == MessageType.HELLO:
                # Decode and validate HELLO
                remote_hello = cast(Hello, decode_message(MessageType.HELLO, payload))

                # Validate timestamp per RFC Section 13.2
                if not validate_timestamp(remote_hello.timestamp):
                    self.logger.warning(
                        f"Rejecting HELLO: timestamp {remote_hello.timestamp} "
                        f"exceeds {CLOCK_SKEW_TOLERANCE_SECONDS}s skew tolerance"
                    )
                    return

                self.logger.info(
                    f"HELLO from {format_peer_id(remote_hello.node_id)} "
                    f"(version: {remote_hello.version})"
                )

                # Track peer in tables for declared collections
                for collection_id in remote_hello.collections:
                    if collection_id in self.peer_tables:
                        self.peer_tables[collection_id].upsert(
                            remote_hello.node_id,
                            [],
                            0.0,  # Coverage unknown from HELLO
                        )

                # Send HELLO response
                response_hello = Hello(
                    version=Hello.DEFAULT_VERSION,
                    node_id=self._local_peer_id,
                    capabilities=self.get_capabilities(),
                    collections=self.config.collections,
                    timestamp=int(time.time()),
                    user_agent=f"dcpp-py-daemon/0.1.0 ({PROTOCOL_ID})",
                )

                if self._libp2p_node and event.stream:
                    # Echo the request_id in the response for correlation
                    await self._libp2p_node.host.send_dcpp_response(
                        event.stream,
                        MessageType.HELLO,
                        response_hello.to_cbor(),
                        request_id=event.request_id,  # Echo request ID
                    )

            elif event.message_type == MessageType.GET_MANIFEST:
                # Handle GET_MANIFEST (RFC Section 3.2, 6.4)
                get_manifest = cast(GetManifest, decode_message(MessageType.GET_MANIFEST, payload))
                self.logger.info(
                    f"GET_MANIFEST for collection {get_manifest.collection_id} "
                    f"(version: {get_manifest.version}, since: {get_manifest.since_version})"
                )

                # Check if we have a REAL manifest for this collection
                # (RFC 7.4: first valid manifest establishes genesis - never serve stubs)
                collection_id = get_manifest.collection_id
                manifest = self._manifests.get(collection_id)
                is_stub = self.is_stub_manifest(collection_id)

                if manifest is None or is_stub or collection_id not in self.config.collections:
                    # Send MANIFEST_NOT_FOUND error (RFC 6.11)
                    # Never serve stub manifests - they could be accepted as invalid genesis
                    if is_stub:
                        self.logger.warning(
                            f"GET_MANIFEST for {collection_id}: refusing to serve stub manifest. "
                            f"Peer must wait for real manifest from authoritative source."
                        )
                    error_response = ErrorResponse(
                        code=ErrorCode.MANIFEST_NOT_FOUND,
                        message=f"Collection {collection_id} not found",
                        request_type=MessageType.GET_MANIFEST,
                    )
                    if self._libp2p_node and event.stream:
                        await self._libp2p_node.host.send_dcpp_response(
                            event.stream,
                            MessageType.ERROR,
                            error_response.to_cbor(),
                            request_id=event.request_id,
                        )
                else:
                    # Send MANIFEST response (only for real, non-stub manifests)
                    signature = self._sign_manifest_if_possible(collection_id, manifest)
                    manifest_payload = cast(dict[str, object], manifest.to_dict())
                    manifest_response = ManifestResponse(
                        collection_id=collection_id,
                        manifest=manifest_payload,
                        signature=signature,
                    )
                    if self._libp2p_node and event.stream:
                        await self._libp2p_node.host.send_dcpp_response(
                            event.stream,
                            MessageType.MANIFEST,
                            manifest_response.to_cbor(),
                            request_id=event.request_id,
                        )

            elif event.message_type == MessageType.GET_PEERS:
                # Handle GET_PEERS (RFC Section 6.6)
                get_peers = cast(GetPeers, decode_message(MessageType.GET_PEERS, payload))
                self.logger.info(
                    f"GET_PEERS for collection {get_peers.collection_id} "
                    f"(max: {get_peers.max_peers}, shard: {get_peers.shard_id})"
                )

                # Get peers from our peer table for this collection
                peers_list: list[PeerInfo] = []
                if get_peers.collection_id in self.peer_tables:
                    table = self.peer_tables[get_peers.collection_id]
                    top_peers = table.get_top_peers(get_peers.max_peers)
                    # Convert PeerEntry to PeerInfo
                    peers_list = [
                        PeerInfo(
                            node_id=entry.node_id,
                            multiaddrs=entry.multiaddrs,
                            coverage=entry.coverage,
                            last_seen=entry.last_seen,
                            response_quality=entry.response_quality,
                        )
                        for entry in top_peers
                    ]

                peers_response = PeersResponse(
                    collection_id=get_peers.collection_id,
                    peers=peers_list,
                )
                if self._libp2p_node and event.stream:
                    await self._libp2p_node.host.send_dcpp_response(
                        event.stream,
                        MessageType.PEERS,
                        peers_response.to_cbor(),
                        request_id=event.request_id,
                    )

            elif event.message_type == MessageType.HEALTH_PROBE:
                # Handle HEALTH_PROBE (RFC Section 6.8, 10.3)
                probe = cast(HealthProbe, decode_message(MessageType.HEALTH_PROBE, payload))
                self.logger.info(
                    f"HEALTH_PROBE for collection {probe.collection_id} "
                    f"({len(probe.challenges)} challenges)"
                )

                # RFC 10.3: Maximum challenges per probe is 10
                if len(probe.challenges) > MAX_CHALLENGES_PER_PROBE:
                    self.logger.warning(
                        f"HEALTH_PROBE exceeds max challenges: {len(probe.challenges)} > {MAX_CHALLENGES_PER_PROBE}"
                    )
                    error_response = ErrorResponse(
                        code=ErrorCode.INVALID_REQUEST,
                        message=f"Too many challenges: {len(probe.challenges)} exceeds max {MAX_CHALLENGES_PER_PROBE}",
                        request_type=MessageType.HEALTH_PROBE,
                    )
                    if self._libp2p_node and event.stream:
                        await self._libp2p_node.host.send_dcpp_response(
                            event.stream,
                            MessageType.ERROR,
                            error_response.to_cbor(),
                            request_id=event.request_id,
                        )
                    return

                # Process challenges and build responses
                challenge_responses: list[ChallengeResponse] = []
                for challenge in probe.challenges:
                    # RFC Section 6.8: offset is uint64, length is uint32
                    # Reject negative values that could bypass bounds checks via Python slicing
                    if getattr(challenge, "_invalid_offset", False) or challenge.offset < 0:
                        challenge_responses.append(
                            ChallengeResponse(
                                cid=challenge.cid,
                                data=None,
                                error="invalid_offset",
                            )
                        )
                        continue
                    if getattr(challenge, "_invalid_length", False) or challenge.length <= 0:
                        challenge_responses.append(
                            ChallengeResponse(
                                cid=challenge.cid,
                                data=None,
                                error="invalid_length",
                            )
                        )
                        continue

                    # Try to retrieve the requested content
                    content = self.retrieve_content(probe.collection_id, challenge.cid)
                    if content is not None:
                        # RFC 10.3: Check offset bounds - error if offset exceeds content length
                        if challenge.offset >= len(content):
                            challenge_responses.append(
                                ChallengeResponse(
                                    cid=challenge.cid,
                                    data=None,
                                    error="offset_out_of_bounds",
                                )
                            )
                        else:
                            # Extract the requested byte range
                            start = challenge.offset
                            end = min(challenge.offset + challenge.length, len(content))
                            data = content[start:end]
                            challenge_responses.append(
                                ChallengeResponse(
                                    cid=challenge.cid,
                                    data=data,
                                    error=None,
                                )
                            )
                    else:
                        challenge_responses.append(
                            ChallengeResponse(
                                cid=challenge.cid,
                                data=None,
                                error="content_not_found",
                            )
                        )

                # Send HEALTH_RESPONSE
                health_response = HealthResponse(
                    nonce=probe.nonce,
                    responses=challenge_responses,
                )
                if self._libp2p_node and event.stream:
                    await self._libp2p_node.host.send_dcpp_response(
                        event.stream,
                        MessageType.HEALTH_RESPONSE,
                        health_response.to_cbor(),
                        request_id=event.request_id,
                    )

        except Exception as e:
            self.logger.error(f"Error handling DCPP request: {e}")

    def _process_state_event(self, event: StateEvent) -> None:
        """
        Process a state machine event and execute resulting actions.

        This method:
        1. Passes the event to the state machine
        2. Executes any actions returned by the state machine
        3. Syncs the state machine's state to the daemon's state

        Per RFC Section 7, the state machine manages state transitions
        and determines when ANNOUNCE messages should be sent.
        """
        actions = self._state_machine.process_event(event)
        self._execute_state_actions(actions)

        # Sync state machine state to daemon state
        sm_state = self._state_machine.node_state
        if sm_state == SMNodeState.OFFLINE:
            self.state = NodeState.OFFLINE
        elif sm_state == SMNodeState.CONNECTING:
            self.state = NodeState.CONNECTING
        elif sm_state == SMNodeState.READY:
            self.state = NodeState.READY
        elif sm_state == SMNodeState.SYNCING:
            self.state = NodeState.SYNCING
        elif sm_state == SMNodeState.GUARDING:
            self.state = NodeState.GUARDING
        elif sm_state == SMNodeState.SEEDING:
            self.state = NodeState.SEEDING
        elif sm_state == SMNodeState.DEGRADED:
            self.state = NodeState.DEGRADED

    def _execute_state_actions(self, actions: list[StateAction]) -> None:
        """
        Execute state machine actions.

        Handles:
        - SendAnnounceAction: Queue collection announcements (gated by Ready state)
        - FetchManifestAction: Queue manifest fetch from peer
        - LogAction: Log message at appropriate level
        - EmitMetricAction: Emit metrics (placeholder for observability)
        """
        for action in actions:
            if isinstance(action, SendAnnounceAction):
                # Only send ANNOUNCE if state machine says we're ready
                if self._state_machine.is_ready_for_announce():
                    for collection_id in action.collections:
                        self.logger.debug(f"State machine triggered ANNOUNCE for {collection_id}")
                        asyncio.create_task(self._publish_announce([collection_id]))
                else:
                    self.logger.debug("ANNOUNCE actions deferred - not in Ready state")

            elif isinstance(action, FetchManifestAction):
                self.logger.info(
                    f"State machine triggered manifest fetch for {action.collection_id} "
                    f"from peer {format_peer_id(action.peer_id)}"
                )
                # Schedule async manifest fetch
                asyncio.create_task(
                    self._fetch_manifest_from_peer(
                        action.collection_id,
                        action.peer_id,
                    )
                )

            elif isinstance(action, StartDownloadAction):
                self.logger.info(
                    f"State machine triggered download for {action.manifest.collection_id}"
                )
                # Schedule async download start
                asyncio.create_task(self._start_collection_download(action.manifest))

            elif isinstance(action, UpdateCoverageAction):
                self._announce_coverage[action.collection_id] = action.coverage

            elif isinstance(action, LogAction):
                msg = action.message
                if action.level == LogLevel.DEBUG:
                    self.logger.debug(msg)
                elif action.level == LogLevel.INFO:
                    self.logger.info(msg)
                elif action.level == LogLevel.WARN:
                    self.logger.warning(msg)
                elif action.level == LogLevel.ERROR:
                    self.logger.error(msg)

            elif isinstance(action, EmitMetricAction):
                # Placeholder for metrics emission
                self.logger.debug(f"Metric: {action.name}={action.value} labels={action.labels}")

    async def _fetch_manifest_from_peer(
        self,
        collection_id: str,
        peer_id: bytes,
    ) -> None:
        """
        Fetch manifest from a peer using GET_MANIFEST request.

        This is triggered by the state machine when an ANNOUNCE is received
        for a collection we're interested in.

        Args:
            collection_id: Collection to fetch manifest for
            peer_id: Peer to fetch from (from ANNOUNCE)
        """
        # First check if we already have the manifest (e.g., from bootstrap)
        existing_manifest = self._manifests.get(collection_id)
        if existing_manifest and not self.is_stub_manifest(collection_id):
            self.logger.info(
                f"Manifest already available for {collection_id} "
                f"(version={existing_manifest.version}, items={existing_manifest.total_items})"
            )
            self.logger.info(
                f"Manifest validated for {collection_id}, items: {existing_manifest.total_items}"
            )
            self._process_state_event(
                ManifestReceivedEvent(
                    collection_id=collection_id,
                    manifest=existing_manifest,
                )
            )
            asyncio.create_task(self._announce_collection_now(collection_id))
            return

        self.logger.info(
            f"Fetching manifest for {collection_id} from peer {format_peer_id(peer_id)}"
        )

        try:
            if self._libp2p_node:
                # Use libp2p to send GET_MANIFEST request
                get_manifest_msg = GetManifest(
                    collection_id=collection_id,
                    version=None,
                    since_version=None,
                )
                response = await self._libp2p_node.host.send_dcpp_request(
                    peer_id,
                    MessageType.GET_MANIFEST,
                    get_manifest_msg.to_cbor(),
                )

                if response and response.message_type == MessageType.MANIFEST:
                    manifest_response = cast(
                        ManifestResponse, decode_message(MessageType.MANIFEST, response.payload)
                    )
                    self.logger.info(
                        f"Received MANIFEST for {collection_id} from {format_peer_id(peer_id)}"
                    )

                    # Store the manifest
                    received_payload = cast(ManifestPayload, manifest_response.manifest)
                    if await self.handle_received_manifest(
                        collection_id,
                        received_payload,
                        source_peer=format_peer_id(peer_id),
                        signature=manifest_response.signature,
                    ):
                        # Manifest validated - notify state machine
                        manifest = Manifest.from_dict(received_payload)
                        self.logger.info(
                            f"Manifest validated for {collection_id}, items: {manifest.total_items}"
                        )
                        self._process_state_event(
                            ManifestReceivedEvent(
                                collection_id=collection_id,
                                manifest=manifest,
                            )
                        )
                        asyncio.create_task(self._announce_collection_now(collection_id))
                    else:
                        self.logger.warning(f"Manifest validation failed for {collection_id}")
                elif response and response.message_type == MessageType.ERROR:
                    error = cast(ErrorResponse, decode_message(MessageType.ERROR, response.payload))
                    try:
                        error_code_name = ErrorCode(error.code).name
                    except Exception:
                        error_code_name = str(error.code)
                    self.logger.warning(
                        f"Peer {format_peer_id(peer_id)} returned error for GET_MANIFEST: "
                        f"{error_code_name}: {error.message}"
                    )
                else:
                    self.logger.warning(
                        f"No valid MANIFEST response from {format_peer_id(peer_id)} "
                        f"for {collection_id}"
                    )
            else:
                # Fallback: try to find peer in connections and use raw TCP
                self.logger.debug(
                    f"libp2p not available, cannot fetch manifest from {format_peer_id(peer_id)}"
                )

        except Exception as e:
            self.logger.error(f"Error fetching manifest for {collection_id}: {e}")

    async def _fetch_manifest_via_http(
        self,
        collection_id: str,
        attempts: int = 5,
        log_fail: bool = True,
    ) -> bool:
        """
        Fetch manifest over HTTP from bootstrap sources.

        Uses the Rust node HTTP API as a fallback when ANNOUNCE-driven
        manifest fetches have not occurred.
        """
        sources = self._derive_http_sources()
        if not sources:
            return False

        encoded_id = urllib.parse.quote(collection_id, safe="")
        for attempt in range(1, attempts + 1):
            for base_url in sources:
                url = f"{base_url}/api/v1/collections/{encoded_id}/manifest"
                try:
                    req = urllib.request.Request(url)
                    with urllib.request.urlopen(req, timeout=10) as response:
                        if response.status != 200:
                            continue
                        body = response.read()
                    manifest_dict = json.loads(body.decode("utf-8"))
                except Exception as e:
                    if log_fail:
                        self.logger.debug(
                            f"HTTP manifest fetch error for {collection_id} from {url}: {e}"
                        )
                    continue

                if not isinstance(manifest_dict, dict):
                    continue

                # Accept both direct manifest dicts and wrapper responses.
                manifest_payload = manifest_dict
                if "manifest" in manifest_dict and isinstance(manifest_dict["manifest"], dict):
                    manifest_payload = cast(dict[str, object], manifest_dict["manifest"])
                manifest_payload = cast(ManifestPayload, manifest_payload)
                if await self.handle_received_manifest(
                    collection_id,
                    manifest_payload,
                    source_peer="http-bootstrap",
                ):
                    manifest = Manifest.from_dict(manifest_payload)
                    self.logger.info(
                        f"Manifest fetched via HTTP for {collection_id}, items: {manifest.total_items}"
                    )
                    self._process_state_event(
                        ManifestReceivedEvent(
                            collection_id=collection_id,
                            manifest=manifest,
                        )
                    )
                    asyncio.create_task(self._announce_collection_now(collection_id))
                    return True

            await asyncio.sleep(2.0 * attempt)

        if log_fail:
            self.logger.warning(
                f"HTTP manifest fetch failed for {collection_id} after {attempts} attempts"
            )
        return False

    async def _announce_collection_now(self, collection_id: str) -> None:
        """Announce a collection immediately after manifest receipt."""
        if not self._libp2p_node:
            return
        if self.is_stub_manifest(collection_id) or collection_id not in self._manifests:
            return

        advertise_addrs = self._advertise_addrs if self._advertise_addrs else None
        try:
            await self._libp2p_node.announce_collection(collection_id, advertise_addrs)
        except Exception as e:
            self.logger.warning(f"Immediate DHT announce failed for {collection_id}: {e}")

        await self._publish_announce([collection_id])

    def _next_announce_seq(self) -> int:
        """Get next monotonic announce sequence number."""
        self._announce_seq += 1
        return self._announce_seq

    def _get_collection_coverage(self, collection_id: str) -> float:
        """Get best-known coverage for a collection (0.0-1.0)."""
        if collection_id in self._announce_coverage:
            return max(0.0, min(1.0, self._announce_coverage[collection_id]))

        torrent_coverage = self._torrent_manager.get_collection_coverage(collection_id)
        if torrent_coverage > 0.0:
            return max(0.0, min(1.0, torrent_coverage))

        state = self._state_machine.collection_state(collection_id)
        if state == SMCollectionState.COMPLETE:
            return 1.0
        if state in (SMCollectionState.SYNCING, SMCollectionState.PARTIAL):
            return 0.5
        return 0.0

    def _get_collection_bt_status(self, collection_id: str) -> str:
        """Get BitTorrent status string for ANNOUNCE."""
        status = self._torrent_manager.get_collection_status(collection_id)
        bt_status = bt_status_from_torrent_status(status)

        state = self._state_machine.collection_state(collection_id)
        if state != SMCollectionState.COMPLETE and bt_status == "seeding":
            bt_status = (
                "leeching"
                if state
                in (
                    SMCollectionState.SYNCING,
                    SMCollectionState.PARTIAL,
                )
                else "none"
            )

        return bt_status

    def _build_announce(self, collection_ids: list[str]) -> Announce | None:
        """Build a signed ANNOUNCE message for the given collections."""
        collections: list[CollectionAnnouncement] = []
        for collection_id in collection_ids:
            manifest = self._manifests.get(collection_id)
            if manifest is None or self.is_stub_manifest(collection_id):
                continue

            try:
                manifest_cid = compute_cid(manifest.to_cbor())
            except Exception as e:
                self.logger.warning(f"Failed to compute manifest CID for {collection_id}: {e}")
                continue

            coverage = self._get_collection_coverage(collection_id)
            bt_status = self._get_collection_bt_status(collection_id)

            collections.append(
                CollectionAnnouncement(
                    id=collection_id,
                    manifest_cid=manifest_cid,
                    coverage=coverage,
                    bt_status=bt_status,
                    shard_ids=None,
                )
            )

        if not collections:
            return None

        timestamp = int(time.time())
        expires_at = timestamp + int(CONFORMANCE_DEFAULTS["announce_expiry_seconds"])
        announce = Announce(
            node_id=self._local_peer_id,
            announce_seq=self._next_announce_seq(),
            collections=collections,
            timestamp=timestamp,
            expires_at=expires_at,
            signature=b"",
        )
        announce.signature = sign_announce(announce, self._signing_key)
        return announce

    async def _publish_announce(self, collection_ids: list[str]) -> None:
        """Publish ANNOUNCE to GossipSub for given collections."""
        if not self._libp2p_node:
            return
        if not self._state_machine.is_ready_for_announce():
            self.logger.debug(
                f"GossipSub ANNOUNCE skipped (state={self._state_machine.node_state.name}, "
                "not ready for announce)"
            )
            return

        announce = self._build_announce(collection_ids)
        if not announce:
            return

        payload = announce.to_cbor()
        for collection in announce.collections:
            try:
                await self._libp2p_node.publish_announcement(collection.id, payload)
            except Exception as e:
                self.logger.warning(f"GossipSub ANNOUNCE failed for {collection.id}: {e}")

    async def _start_collection_download(self, manifest: Manifest) -> None:
        """
        Start downloading content for a collection using BitTorrent.

        This is triggered by the state machine after a manifest is received
        and validated.

        Args:
            manifest: The validated manifest to download
        """
        collection_id = manifest.collection_id
        self.logger.info(f"Starting download for collection {collection_id}")

        try:
            infohash_hex = manifest.torrent.infohash if manifest.torrent else ""
            piece_length = manifest.torrent.piece_length if manifest.torrent else 0

            if infohash_hex:
                self.logger.info(
                    f"BitTorrent metadata: infohash={infohash_hex[:16]}..., "
                    f"piece_length={piece_length}"
                )

            # Notify state machine that download started
            self._process_state_event(
                DownloadStartedEvent(
                    collection_id=collection_id,
                    info_hash=bytes.fromhex(infohash_hex) if infohash_hex else b"",
                )
            )

            # Fast-path HTTP fetch for cross-impl testing when manifest has inline items.
            # This is a pragmatic fallback until BitTorrent networking is fully wired.
            fetched_count = await self._fetch_manifest_items_via_http(manifest)
            if fetched_count > 0:
                total_items = max(1, manifest.total_items)
                coverage = min(1.0, fetched_count / float(total_items))
                self._process_state_event(
                    DownloadProgressEvent(
                        collection_id=collection_id,
                        coverage=coverage,
                        have_pieces=fetched_count,
                        total_pieces=total_items,
                    )
                )

                if fetched_count >= manifest.total_items:
                    self.logger.info(f"Download complete for collection {collection_id}")
                    self._process_state_event(
                        DownloadCompleteEvent(
                            collection_id=collection_id,
                        )
                    )
                    self.logger.info(f"Node transitioning to Guarding state for {collection_id}")
                return

            # If no HTTP items were fetched, fall back to BitTorrent placeholder behavior.
            if manifest.torrent:
                self.logger.info(f"Download complete for collection {collection_id} (simulated)")
                self._process_state_event(
                    DownloadCompleteEvent(
                        collection_id=collection_id,
                    )
                )
                self.logger.info(f"Node transitioning to Guarding state for {collection_id}")
            else:
                self.logger.warning(
                    f"No torrent info in manifest for {collection_id}, cannot download"
                )

        except Exception as e:
            self.logger.error(f"Error starting download for {collection_id}: {e}")

    async def _fetch_manifest_items_via_http(self, manifest: Manifest) -> int:
        """
        Fetch a subset of manifest items via HTTP from bootstrap peers.

        This is used as a lightweight data-plane fallback for cross-impl tests.
        """
        sources = self._derive_http_sources()
        if not sources:
            self.logger.warning("No HTTP sources available for item fetch")
            return 0

        try:
            max_items = int(os.environ.get("DCPP_HTTP_FETCH_LIMIT", "10"))
        except ValueError:
            max_items = 10

        encoded_id = urllib.parse.quote(manifest.collection_id, safe="")
        fetched = 0

        items = manifest.items
        if not items and manifest.items_index_cid:
            index_data = await asyncio.to_thread(
                self._fetch_item_from_sources,
                sources,
                encoded_id,
                manifest.items_index_cid,
            )
            if index_data:
                try:
                    items = ItemsIndex.from_cbor(index_data).items
                except Exception as e:
                    self.logger.warning(f"Failed to decode items index: {e}")
                    return 0

        if not items:
            return 0

        for item in items[:max_items]:
            cid = item.cid
            if not cid:
                continue
            if self._storage.exists(manifest.collection_id, cid):
                continue

            data = await asyncio.to_thread(self._fetch_item_from_sources, sources, encoded_id, cid)
            if data is None:
                continue

            if self._storage.store(manifest.collection_id, cid, data):
                fetched += 1
            else:
                self.logger.warning(f"CID verification failed for fetched item {cid[:16]}...")

        if fetched > 0:
            self.logger.info(f"Fetched {fetched} item(s) via HTTP for {manifest.collection_id}")

        return fetched

    def _fetch_item_from_sources(
        self, sources: list[str], encoded_id: str, cid: str
    ) -> bytes | None:
        """Try to fetch an item from available HTTP sources."""
        for base_url in sources:
            url = f"{base_url}/api/v1/collections/{encoded_id}/items/{cid}"
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=10) as response:
                    if response.status == 200:
                        return cast(bytes, response.read())
            except Exception:
                continue
        return None

    def _derive_http_sources(self) -> list[str]:
        """Derive HTTP base URLs from bootstrap peers."""
        sources: list[str] = []
        for addr in self.config.bootstrap_peers:
            match = re.search(r"/ip4/([^/]+)/tcp/(\d+)", addr)
            if not match:
                continue
            host = match.group(1)
            try:
                p2p_port = int(match.group(2))
            except ValueError:
                continue
            http_port = self._map_p2p_port_to_http(p2p_port)
            sources.append(f"http://{host}:{http_port}")

        # De-duplicate while preserving order
        seen = set()
        unique_sources = []
        for src in sources:
            if src not in seen:
                seen.add(src)
                unique_sources.append(src)
        return unique_sources

    def _map_p2p_port_to_http(self, p2p_port: int) -> int:
        """Map known libp2p ports to HTTP API ports."""
        if 4001 <= p2p_port <= 4010:
            return p2p_port + 4079
        return 8080

    async def stop(self) -> None:
        """Stop the daemon gracefully."""
        self.logger.info("Stopping DCPP daemon...")

        # Cancel background tasks
        for task in self._tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Stop HTTP API server if active
        if self._http_server:
            await self._http_server.stop()
            self._http_server = None

        # Stop libp2p node if active
        if self._libp2p_node:
            await self._libp2p_node.stop()
            self._libp2p_node = None

        # Close all raw TCP outbound connections
        for addr, conn in list(self._connections.items()):
            await conn.disconnect()
        self._connections.clear()

        # Close connection manager
        await self._connection_manager.close_all()

        # TODO: Send GOODBYE to connected peers before disconnecting

        self.state = NodeState.OFFLINE
        self._shutdown_event.set()
        self.logger.info("Daemon stopped")

    async def _bootstrap(self) -> None:
        """
        Connect to bootstrap peers, exchange HELLO, request peers, and recursively bootstrap.

        Per RFC Section 9.3 and Appendix B.1:
        1. If no CLI bootstrap peers, discover via DNS TXT and IPNS
        2. Connect to each bootstrap peer
        3. Exchange HELLO messages
        4. Send GET_PEERS for each collection
        5. Store received peers in peer table
        6. Recursively connect to discovered peers (limited to avoid infinite loops)
        """
        bootstrap_peers = list(self.config.bootstrap_peers)

        # In raw TCP mode (test-only), skip DNS/IPNS discovery unless peers are explicitly provided.
        if not self._use_libp2p and not bootstrap_peers:
            self.logger.warning(
                "[BOOTSTRAP] Raw TCP mode with no CLI peers specified. "
                "Skipping DNS/IPNS discovery and waiting for incoming connections."
            )
            return

        # If no CLI bootstrap peers, try DNS TXT/IPNS discovery (RFC Section 9.3)
        if not bootstrap_peers:
            self.logger.info("[BOOTSTRAP] No CLI peers specified, attempting DNS/IPNS discovery...")
            self.logger.debug(
                f"[BOOTSTRAP] Discovery config: dns={self.config.enable_dns_discovery} "
                f"domain={self.config.bootstrap_dns_domain}, "
                f"ipns={self.config.enable_ipns_discovery} name={self.config.bootstrap_ipns_name}"
            )
            discovered = await discover_bootstrap_peers(
                enable_dns=self.config.enable_dns_discovery,
                enable_ipns=self.config.enable_ipns_discovery,
                dns_domain=self.config.bootstrap_dns_domain,
                ipns_name=self.config.bootstrap_ipns_name,
            )
            if discovered:
                self.logger.info(f"[BOOTSTRAP] Discovered {len(discovered)} peer(s) via DNS/IPNS")
                for i, peer in enumerate(discovered[:5]):  # Log first 5
                    self.logger.debug(f"[BOOTSTRAP] Discovered peer {i + 1}: {peer}")
            else:
                self.logger.debug("[BOOTSTRAP] DNS/IPNS discovery returned no peers")
            bootstrap_peers.extend(discovered)

        if not bootstrap_peers:
            self.logger.warning(
                "[BOOTSTRAP] No bootstrap peers available after discovery. "
                "Node will wait for incoming connections. Use --bootstrap to specify peers manually."
            )
            return

        self.logger.info(f"[BOOTSTRAP] Starting bootstrap with {len(bootstrap_peers)} peer(s)...")

        # Track all discovered peers for recursive bootstrap
        # Key: collection_id, Value: list of (node_id, multiaddrs, coverage)
        discovered_peers: dict[str, list[tuple[bytes, list[str], float]]] = {}

        # Track connected addresses to avoid duplicate connections
        connected_addrs: set[str] = set(bootstrap_peers)

        # Connect to initial bootstrap peers
        tasks = []
        for peer_addr in bootstrap_peers:
            tasks.append(self._connect_to_bootstrap_peer(peer_addr, discovered_peers))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        successful = sum(1 for r in results if r is True)
        failed = len(bootstrap_peers) - successful
        self.logger.info(f"[BOOTSTRAP] Initial phase: {successful} connected, {failed} failed")
        if failed > 0:
            # Log failed connections for diagnostics
            for i, (peer_addr, result) in enumerate(zip(bootstrap_peers, results)):
                if result is not True:
                    error_msg = (
                        str(result) if isinstance(result, Exception) else "connection failed"
                    )
                    self.logger.debug(f"[BOOTSTRAP] Failed to connect to {peer_addr}: {error_msg}")

        # Recursive bootstrap: connect to discovered peers (limit to 5 per collection)
        max_recursive_peers = 5
        recursive_addrs: set[str] = set()

        for collection_id, peers in discovered_peers.items():
            for node_id, multiaddrs, coverage in peers[:max_recursive_peers]:
                for multiaddr in multiaddrs:
                    if multiaddr not in connected_addrs and multiaddr not in recursive_addrs:
                        recursive_addrs.add(multiaddr)

        if recursive_addrs:
            self.logger.info(f"Recursive bootstrap to {len(recursive_addrs)} discovered peer(s)...")

            recursive_tasks = []
            for peer_addr in recursive_addrs:
                connected_addrs.add(peer_addr)
                recursive_tasks.append(self._connect_to_bootstrap_peer(peer_addr, None))

            recursive_results = await asyncio.gather(*recursive_tasks, return_exceptions=True)

            recursive_successful = sum(1 for r in recursive_results if r is True)
            self.logger.info(
                f"Recursive bootstrap: {recursive_successful}/{len(recursive_addrs)} peers connected"
            )

        # Log final peer table status
        total_peers = sum(len(table.peers) for table in self.peer_tables.values())
        self.logger.info(f"[BOOTSTRAP] Complete. Total known peers: {total_peers}")
        for collection_id, table in self.peer_tables.items():
            self.logger.info(f"[BOOTSTRAP] Collection {collection_id}: {len(table.peers)} peers")
            # Log top peers for diagnostics
            for entry in list(table.peers.values())[:3]:
                self.logger.debug(
                    f"[BOOTSTRAP]   - {format_peer_id(entry.node_id)} "
                    f"coverage={entry.coverage:.1%} quality={entry.response_quality:.2f}"
                )

    async def _connect_to_bootstrap_peer(
        self,
        multiaddr: str,
        discovered_peers: dict[str, list[tuple[bytes, list[str], float]]] | None = None,
        max_retries: int = 3,
        initial_backoff: float = 1.0,
    ) -> bool:
        """
        Connect to a single bootstrap peer, exchange HELLO, and request peers.

        Per RFC Appendix B.1 (New Node Joining Network):
        1. Connect to peer
        2. Exchange HELLO messages
        3. Send GET_PEERS for each collection
        4. Store received peers in peer table
        5. Send GOODBYE before closing

        Args:
            multiaddr: Multiaddr of the bootstrap peer (e.g., /ip4/127.0.0.1/tcp/4001)
            discovered_peers: Optional dict to accumulate discovered peers for recursive bootstrap.
                             Key is collection_id, value is list of (node_id, multiaddrs, coverage).
            max_retries: Maximum number of connection attempts (default: 3).
            initial_backoff: Initial backoff delay in seconds, doubles each retry (default: 1.0).

        Returns:
            True if connection and handshake successful.
        """
        self.logger.debug(f"Connecting to bootstrap peer: {multiaddr}")

        conn = OutboundTCPConnection.from_multiaddr(multiaddr, logger=self.logger)
        if conn is None:
            self.logger.warning(f"Failed to parse multiaddr: {multiaddr}")
            return False

        # Retry with exponential backoff for connection failures (e.g., connection refused)
        backoff = initial_backoff
        for attempt in range(max_retries):
            if await conn.connect():
                break
            if attempt < max_retries - 1:
                self.logger.debug(
                    f"Connection to {multiaddr} failed, retrying in {backoff:.1f}s "
                    f"(attempt {attempt + 1}/{max_retries})"
                )
                await asyncio.sleep(backoff)
                backoff *= 2  # Exponential backoff
        else:
            self.logger.warning(f"Failed to connect to {multiaddr} after {max_retries} attempts")
            return False

        remote_node_id: bytes | None = None

        # Perform HELLO handshake
        try:
            hello = Hello(
                version=Hello.DEFAULT_VERSION,
                node_id=self._local_peer_id,
                capabilities=self.get_capabilities(),
                collections=self.config.collections,
                timestamp=int(time.time()),
                user_agent=f"dcpp-py-daemon/0.1.0 ({PROTOCOL_ID})",
            )

            # Send HELLO with full envelope framing
            payload = cbor2.dumps(hello.to_dict())
            success, request_id = await conn.send_message(MessageType.HELLO, payload)
            if not success:
                await conn.disconnect()
                return False

            # Receive HELLO response (with CRC verification)
            response = await conn.receive_message()
            if response is None:
                self.logger.warning(f"No HELLO response from {multiaddr}")
                await conn.disconnect()
                return False

            msg_type, response_payload, response_request_id = response
            if msg_type == MessageType.HELLO:
                remote_hello = cast(Hello, decode_message(MessageType.HELLO, response_payload))

                # Validate timestamp per RFC Section 13.2 (5-minute skew tolerance)
                if not validate_timestamp(remote_hello.timestamp):
                    self.logger.warning(
                        f"Rejecting HELLO from {multiaddr}: timestamp {remote_hello.timestamp} "
                        f"exceeds {CLOCK_SKEW_TOLERANCE_SECONDS}s skew tolerance"
                    )
                    await conn.disconnect()
                    return False

                remote_node_id = remote_hello.node_id
                self.logger.info(
                    f"Connected to peer {format_peer_id(remote_node_id)} "
                    f"(version: {remote_hello.version}, user_agent: {remote_hello.user_agent or 'unknown'})"
                )
                self.logger.info(f"[CONN] Connected to {multiaddr}")

                # Add the bootstrap peer to our peer tables for their collections
                for collection_id in remote_hello.collections:
                    if collection_id in self.peer_tables:
                        self.peer_tables[collection_id].upsert(
                            remote_node_id,
                            [multiaddr],
                            0.0,  # Coverage unknown from HELLO
                        )
                        self.logger.debug(
                            f"Added {format_peer_id(remote_node_id)} to peer table for {collection_id}"
                        )

            elif msg_type == MessageType.ERROR:
                self.logger.warning(f"Error response from {multiaddr}: {response_payload!r}")
                await conn.disconnect()
                return False
            else:
                self.logger.warning(f"Unexpected response type: {msg_type.name}")
                await conn.disconnect()
                return False

            # Request peers for each collection we're interested in (RFC Appendix B.1)
            for collection_id in self.config.collections:
                self.logger.debug(f"Requesting peers for {collection_id} from {multiaddr}...")

                get_peers = GetPeers(
                    collection_id=collection_id,
                    max_peers=20,
                )
                payload = cbor2.dumps(get_peers.to_dict())
                success, request_id = await conn.send_message(MessageType.GET_PEERS, payload)
                if not success:
                    self.logger.warning(f"Failed to send GET_PEERS for {collection_id}")
                    continue

                # Receive PEERS response
                response = await conn.receive_message()
                if response is None:
                    self.logger.warning(f"No PEERS response for {collection_id}")
                    continue

                msg_type, response_payload, _ = response
                if msg_type == MessageType.PEERS:
                    peers_response = cast(
                        PeersResponse, decode_message(MessageType.PEERS, response_payload)
                    )
                    self.logger.info(
                        f"Received {len(peers_response.peers)} peers for {collection_id} from {multiaddr}"
                    )

                    # Update peer table with discovered peers
                    if collection_id in self.peer_tables:
                        for peer in peers_response.peers:
                            self.peer_tables[collection_id].upsert(
                                peer.node_id,
                                peer.multiaddrs,
                                peer.coverage,
                            )

                    # Accumulate for recursive bootstrap
                    if discovered_peers is not None:
                        if collection_id not in discovered_peers:
                            discovered_peers[collection_id] = []
                        for peer in peers_response.peers:
                            discovered_peers[collection_id].append(
                                (peer.node_id, peer.multiaddrs, peer.coverage)
                            )

                elif msg_type == MessageType.ERROR:
                    self.logger.debug(
                        f"Error getting peers for {collection_id}: {response_payload!r}"
                    )
                else:
                    self.logger.debug(f"Unexpected response for GET_PEERS: {msg_type.name}")

            # Request manifests for collections where we only have stubs (RFC Appendix B.1)
            for collection_id in self.config.collections:
                # Only request if we have a stub or no manifest
                if self.is_stub_manifest(collection_id) or collection_id not in self._manifests:
                    self.logger.debug(
                        f"Requesting manifest for {collection_id} from {multiaddr}..."
                    )

                    get_manifest_msg = GetManifest(
                        collection_id=collection_id,
                        version=None,  # Request latest
                        since_version=None,
                    )
                    payload = cbor2.dumps(get_manifest_msg.to_dict())
                    success, request_id = await conn.send_message(MessageType.GET_MANIFEST, payload)
                    if not success:
                        self.logger.warning(f"Failed to send GET_MANIFEST for {collection_id}")
                        continue

                    # Receive MANIFEST response
                    response = await conn.receive_message()
                    if response is None:
                        self.logger.warning(f"No MANIFEST response for {collection_id}")
                        continue

                    msg_type, response_payload, _ = response
                    if msg_type == MessageType.MANIFEST:
                        manifest_response = cast(
                            ManifestResponse, decode_message(MessageType.MANIFEST, response_payload)
                        )
                        # Use handle_received_manifest to properly store and clear stub tracking
                        received_payload = cast(ManifestPayload, manifest_response.manifest)
                        await self.handle_received_manifest(
                            collection_id,
                            received_payload,
                            source_peer=multiaddr,
                            signature=manifest_response.signature,
                        )
                    elif msg_type == MessageType.ERROR:
                        self.logger.debug(
                            f"Error getting manifest for {collection_id} from {multiaddr}: "
                            f"peer may not have manifest yet"
                        )
                    else:
                        self.logger.debug(f"Unexpected response for GET_MANIFEST: {msg_type.name}")

            # Send GOODBYE before closing (RFC Section 6.10)
            # Valid reasons per RFC: "shutdown", "maintenance", "leaving_collection"
            goodbye = Goodbye(reason="shutdown")
            payload = cbor2.dumps(goodbye.to_dict())
            await conn.send_message(MessageType.GOODBYE, payload)
            self.logger.debug(f"Sent GOODBYE to {multiaddr}")

            # Close the connection after GOODBYE to avoid stale "connected" state
            # (remote peer will close upon receiving GOODBYE)
            await conn.disconnect()
            return True

        except Exception as e:
            self.logger.error(f"Handshake with {multiaddr} failed: {e}")
            await conn.disconnect()
            return False

    async def connect_to_peer(self, multiaddr: str) -> bool:
        """
        Connect to a peer at the given multiaddr.

        This is the public API for initiating outbound TCP connections.

        Args:
            multiaddr: Multiaddr of the peer (e.g., /ip4/192.168.1.5/tcp/4001)

        Returns:
            True if connection successful.
        """
        if multiaddr in self._connections:
            conn = self._connections[multiaddr]
            if conn.is_connected:
                return True
            # Remove stale connection
            del self._connections[multiaddr]

        return await self._connect_to_bootstrap_peer(multiaddr)

    async def _dht_announce_loop(self) -> None:
        """
        Periodically announce to DHT (RFC Section 9.1.1).

        Re-announces our presence as a guardian for each collection
        at the configured interval (default: 1 hour).

        Per RFC Section 7, announcements are gated by the state machine -
        only send when in READY, SYNCING, GUARDING, or SEEDING states.
        """
        while True:
            try:
                await asyncio.sleep(self.config.dht_reannounce_interval)

                # Check state machine before announcing (RFC Section 7)
                if not self._state_machine.is_ready_for_announce():
                    self.logger.debug(
                        f"DHT announce skipped (state={self._state_machine.node_state.name}, "
                        "not ready for announce)"
                    )
                    continue

                # Announce to DHT if libp2p is available
                # RFC Section 6.3 line 298: "the announcing node MUST be able to provide
                # the manifest immediately or upon the receiver's first GET_MANIFEST request"
                if self._libp2p_node:
                    for collection_id in self.config.collections:
                        # RFC compliance: only announce if we have a real manifest
                        if (
                            self.is_stub_manifest(collection_id)
                            or collection_id not in self._manifests
                        ):
                            self.logger.debug(
                                f"DHT re-announce skipped for {collection_id}: no real manifest available"
                            )
                            continue
                        try:
                            # Pass advertise addresses to include in DHT provider records
                            await self._libp2p_node.announce_collection(
                                collection_id, self._advertise_addrs
                            )
                            self.logger.debug(
                                f"DHT re-announce for {collection_id} "
                                f"({len(self._advertise_addrs)} advertise addr(s))"
                            )
                        except Exception as e:
                            self.logger.warning(f"DHT announce failed for {collection_id}: {e}")
                else:
                    self.logger.debug("DHT announce skipped (libp2p not available)")

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"DHT announce loop error: {e}")

    async def _announce_loop(self) -> None:
        """
        Periodically publish ANNOUNCE to GossipSub (RFC Section 6.3).
        """
        while True:
            try:
                await asyncio.sleep(self.config.announce_interval)
                if not self._libp2p_node:
                    continue
                await self._publish_announce(self.config.collections)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"GossipSub announce loop error: {e}")

    async def _health_probe_loop(self) -> None:
        """
        Periodically probe peers (RFC Section 10).

        Probes top peers for each collection to verify they're still
        healthy and have the expected content.
        """
        while True:
            try:
                await asyncio.sleep(self.config.probe_interval)

                connected_peers: set[bytes] = set()
                if self._use_libp2p and self._libp2p_node:
                    connected_peers = set(self._libp2p_node.connected_peers())

                for collection_id, table in self.peer_tables.items():
                    # Get top 10 peers to probe
                    peers_to_probe = table.get_top_peers(10)

                    if not peers_to_probe:
                        continue

                    self.logger.debug(
                        f"Health probe round for {collection_id}: {len(peers_to_probe)} peer(s)"
                    )

                    for peer in peers_to_probe:
                        if self._use_libp2p and self._libp2p_node:
                            if peer.node_id not in connected_peers:
                                continue
                            success, rtt_ms = await self._probe_peer_libp2p(
                                peer.node_id,
                                collection_id,
                            )
                        else:
                            if not peer.multiaddrs:
                                continue
                            # Probe the first available multiaddr
                            success, rtt_ms = await self._probe_peer(
                                peer.multiaddrs[0],
                                collection_id,
                            )

                        # Record result in peer table
                        table.record_probe_result(
                            peer.node_id,
                            success=success,
                            response_time_ms=rtt_ms,
                        )

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health probe loop error: {e}")

    async def _probe_peer(
        self,
        multiaddr: str,
        collection_id: str,
    ) -> tuple[bool, float]:
        """
        Send a HEALTH_PROBE to a peer and wait for HEALTH_RESPONSE.

        Args:
            multiaddr: Peer's multiaddr
            collection_id: Collection to probe for

        Returns:
            Tuple of (success, rtt_ms)
        """
        start_time = time.time()

        try:
            # Get or create connection via connection manager
            conn = await self._connection_manager.get_or_create(multiaddr)
            if conn is None:
                return (False, 0.0)

            # Create health probe message (simplified - no actual challenges)
            # In full implementation, this would include random CID challenges
            probe_payload = cbor2.dumps(
                {
                    "collection_id": collection_id,
                    "challenges": [],
                    "nonce": os.urandom(16),
                }
            )

            success, request_id = await conn.send_message(
                MessageType.HEALTH_PROBE,
                probe_payload,
            )
            if not success:
                self._connection_manager.record_failure(multiaddr)
                return (False, 0.0)

            # Wait for response
            response = await conn.receive_message()
            if response is None:
                self._connection_manager.record_failure(multiaddr)
                return (False, 0.0)

            msg_type, _, _ = response
            if msg_type != MessageType.HEALTH_RESPONSE:
                self._connection_manager.record_failure(multiaddr)
                return (False, 0.0)

            rtt_ms = (time.time() - start_time) * 1000
            self._connection_manager.record_success(multiaddr, rtt_ms)
            return (True, rtt_ms)
        except Exception as e:
            self.logger.debug(f"Probe to {multiaddr} failed: {e}")
            self._connection_manager.record_failure(multiaddr)
            return (False, 0.0)

    async def _probe_peer_libp2p(
        self,
        peer_id: bytes,
        collection_id: str,
    ) -> tuple[bool, float]:
        """
        Send a HEALTH_PROBE to a peer over libp2p and wait for HEALTH_RESPONSE.

        Args:
            peer_id: Peer's libp2p peer ID bytes
            collection_id: Collection to probe for

        Returns:
            Tuple of (success, rtt_ms)
        """
        start_time = time.time()

        if not self._libp2p_node:
            return (False, 0.0)

        try:
            probe_payload = cbor2.dumps(
                {
                    "collection_id": collection_id,
                    "challenges": [],
                    "nonce": os.urandom(16),
                }
            )

            self.logger.info(f"HEALTH_PROBE sent to {format_peer_id(peer_id)} for {collection_id}")

            response = await self._libp2p_node.host.send_dcpp_request(
                peer_id,
                MessageType.HEALTH_PROBE,
                probe_payload,
            )
            if response is None:
                self.logger.warning(
                    f"HEALTH_PROBE failed for {format_peer_id(peer_id)}: no response"
                )
                return (False, 0.0)
            if response.message_type != MessageType.HEALTH_RESPONSE:
                self.logger.warning(
                    f"HEALTH_PROBE failed for {format_peer_id(peer_id)}: "
                    f"unexpected response {response.message_type}"
                )
                return (False, 0.0)

            rtt_ms = (time.time() - start_time) * 1000.0
            self.logger.info(
                f"Health probe SUCCESS for {format_peer_id(peer_id)} "
                f"(collection {collection_id}) in {rtt_ms:.1f}ms"
            )
            return (True, rtt_ms)
        except Exception as e:
            self.logger.warning(f"Health probe failed for {format_peer_id(peer_id)}: {e}")
            return (False, 0.0)

    async def _peer_maintenance_loop(self) -> None:
        """
        Periodically clean up stale peers and refresh bootstrap.

        Tasks:
        1. Remove stale peers from peer tables
        2. Clean up failed connections
        3. Refresh bootstrap if peer count is low
        """
        min_peers_per_collection = 5

        while True:
            try:
                await asyncio.sleep(3600)  # 1 hour

                # Clean up stale peers from all tables
                total_removed = 0
                for collection_id, table in self.peer_tables.items():
                    removed = table.cleanup_stale()
                    if removed > 0:
                        self.logger.info(f"Removed {removed} stale peer(s) from {collection_id}")
                        total_removed += removed

                # Clean up failed connections
                await self._connection_manager.cleanup()

                # Check if we need to refresh bootstrap
                needs_bootstrap = False
                for collection_id, table in self.peer_tables.items():
                    if table.peer_count() < min_peers_per_collection:
                        self.logger.info(
                            f"Collection {collection_id} has only {table.peer_count()} peer(s), "
                            f"refreshing bootstrap..."
                        )
                        needs_bootstrap = True
                        break

                if needs_bootstrap:
                    await self._bootstrap()

                if total_removed > 0:
                    self.logger.info(f"Peer maintenance complete: {total_removed} peer(s) removed")
                else:
                    self.logger.debug("Peer maintenance complete: no changes")

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Peer maintenance loop error: {e}")

    def get_capabilities(self) -> list[str]:
        """Get node capabilities."""
        caps = []
        if self.config.enable_guardian:
            caps.append("guardian")
        if self.config.enable_seeder:
            caps.append("seeder")
        if self.config.enable_private:
            caps.append("private")
        return caps


# =============================================================================
# CLI Entry Point
# =============================================================================


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="dcpp-daemon",
        description="DCPP Network Daemon - Distributed Content Preservation Protocol",
    )

    parser.add_argument(
        "--listen",
        "-l",
        action="append",
        help="Listen address (multiaddr format, can be specified multiple times)",
    )
    parser.add_argument(
        "--bootstrap",
        "-b",
        action="append",
        help="Bootstrap peer address (multiaddr format)",
    )
    parser.add_argument(
        "--storage",
        "-s",
        help="Storage path for content",
    )
    parser.add_argument(
        "--collection",
        "-c",
        dest="collections",
        action="append",
        help="Collection ID to guard",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "json", "pretty"],
        default="text",
        help="Log output format: text (default), json (structured), or pretty (colored terminal)",
    )
    parser.add_argument(
        "--no-libp2p",
        action="store_true",
        help="Disable libp2p and use raw TCP (non-compliant with RFC Section 3.1)",
    )
    parser.add_argument(
        "--bootstrap-dns",
        nargs="?",
        const="_dcpp-bootstrap.dcpp.network",
        metavar="DOMAIN",
        help="Enable DNS TXT bootstrap discovery (default domain: _dcpp-bootstrap.dcpp.network)",
    )
    parser.add_argument(
        "--bootstrap-ipns",
        nargs="?",
        const="/ipns/bootstrap.dcpp.network",
        metavar="NAME",
        help="Enable IPNS bootstrap discovery (default: /ipns/bootstrap.dcpp.network)",
    )
    parser.add_argument(
        "--no-bootstrap-discovery",
        action="store_true",
        help="Disable automatic DNS TXT and IPNS bootstrap peer discovery",
    )

    # External address configuration (NAT traversal / WAN deployment)
    parser.add_argument(
        "--advertise-addr",
        dest="advertise_addrs",
        action="append",
        metavar="MULTIADDR",
        help="Explicit multiaddr to advertise to peers (can be specified multiple times)",
    )
    parser.add_argument(
        "--external-addr-source",
        choices=["none", "static", "http", "env"],
        default="none",
        help="How to compute external address: none (use listen), static (use --external-addr), "
        "http (fetch public IP), env (read DCPP_EXTERNAL_ADDR)",
    )
    parser.add_argument(
        "--external-addr",
        metavar="MULTIADDR",
        help="External address when --external-addr-source=static (e.g., /ip4/203.0.113.1/tcp/4001)",
    )
    parser.add_argument(
        "--enable-relay",
        action="store_true",
        help="Enable libp2p relay client for NAT traversal",
    )
    parser.add_argument(
        "--enable-hole-punch",
        action="store_true",
        help="Enable libp2p hole punching for direct connections",
    )
    parser.add_argument(
        "--dial-timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="Timeout for bootstrap dial attempts (default: 30.0)",
    )

    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"dcpp-daemon 0.1.0 ({PROTOCOL_ID})",
    )

    # HTTP API options
    parser.add_argument(
        "--http-api",
        metavar="ADDR",
        help="HTTP API listen address (default: 0.0.0.0:8080)",
    )
    parser.add_argument(
        "--no-http-api",
        action="store_true",
        help="Disable HTTP API server",
    )

    return parser


class PrettyFormatter(logging.Formatter):
    """Pretty colored formatter for terminal output."""

    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[34m",  # Blue
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
    }
    ICONS = {
        "DEBUG": "◆",
        "INFO": "●",
        "WARNING": "⚠",
        "ERROR": "✖",
        "CRITICAL": "✖",
    }
    RESET = "\033[0m"
    DIM = "\033[2m"

    def format(self, record: logging.LogRecord) -> str:
        # Get color and icon for level
        color = self.COLORS.get(record.levelname, "")
        icon = self.ICONS.get(record.levelname, "?")

        # Format timestamp as HH:MM:SS
        timestamp = self.formatTime(record, "%H:%M:%S")

        # Truncate logger name if too long
        name = record.name
        if len(name) > 25:
            name = "..." + name[-22:]

        # Format the message
        message = record.getMessage()

        return (
            f"{self.DIM}{timestamp}{self.RESET} "
            f"{color}{icon} {record.levelname:5}{self.RESET} "
            f"[{self.DIM}{name:>25}{self.RESET}] "
            f"{message}"
        )


class JsonFormatter(logging.Formatter):
    """JSON structured formatter for log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        import json
        from datetime import datetime, timezone

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "fields": {"message": record.getMessage()},
            "target": record.name,
            "filename": record.filename,
            "line_number": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


def setup_logging(config: DaemonConfig) -> None:
    """Configure logging based on format type."""
    level = getattr(logging, config.log_level)

    # Remove existing handlers
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    # Create handler
    handler = logging.StreamHandler()
    handler.setLevel(level)

    # Set formatter based on format type
    if config.log_format_type == "pretty":
        handler.setFormatter(PrettyFormatter())
    elif config.log_format_type == "json":
        handler.setFormatter(JsonFormatter())
    else:  # text
        handler.setFormatter(logging.Formatter(config.log_format))

    # Configure root logger
    root_logger.setLevel(level)
    root_logger.addHandler(handler)


async def run_daemon(config: DaemonConfig) -> None:
    """Run the daemon with signal handling."""
    daemon = DCPPDaemon(config)

    loop = asyncio.get_running_loop()

    def signal_handler() -> None:
        asyncio.create_task(daemon.stop())

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    await daemon.start()


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    config = DaemonConfig.from_args(args)
    setup_logging(config)

    logger = logging.getLogger("dcpp.daemon")
    logger.info("=" * 60)
    logger.info("DCPP Daemon v0.1.0")

    if config.use_libp2p and LIBP2P_AVAILABLE:
        logger.info("Transport: libp2p with Noise encryption (RFC compliant)")
    elif config.use_libp2p and not LIBP2P_AVAILABLE:
        logger.error("libp2p not available but required for RFC compliance.")
        logger.error("Install with: pip install libp2p")
        logger.error("Or use --no-libp2p to explicitly allow non-compliant raw TCP mode.")
        logger.error("Exiting. Raw TCP fallback requires explicit opt-in via --no-libp2p.")
        return 1
    else:
        logger.warning("Using raw TCP mode (non-compliant with RFC Section 3.1)")

    logger.info(f"Storage backend: FileSystemStorage at {config.storage_path}")
    if config.http_api_addr:
        logger.info(f"HTTP API: {config.http_api_addr}")
    else:
        logger.info("HTTP API: disabled (--no-http-api)")
    # Note: Actual BitTorrent backend is logged when daemon initializes (_get_bittorrent_backend)
    logger.info("=" * 60)

    try:
        # libp2p runs in a separate thread (trio), daemon uses asyncio
        asyncio.run(run_daemon(config))
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        logger.error(f"Daemon error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
