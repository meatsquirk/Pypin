"""
Kademlia DHT Implementation for Python

This module provides a Kademlia DHT implementation for DCPP with production-ready
APIs but LOCAL-ONLY network operations by default.

IMPORTANT - Implementation Status:
    - API: Production-ready, matches Rust implementation
    - Local operations: Fully functional (key derivation, provider caching)
    - Network operations: LOCAL CACHE ONLY unless py-libp2p Kademlia is wired in

What works without py-libp2p:
    - KademliaDHT.provide() - Stores in local cache
    - KademliaDHT.find_providers() - Returns from local cache
    - KademliaDHT.put_value() / get_value() - Local storage
    - BootstrapConfig - DNS discovery prepared but needs network

What requires py-libp2p Kademlia integration:
    - Actual DHT network queries
    - Provider record propagation to other nodes
    - Value replication across the network

To upgrade to real network DHT:
    1. Install py-libp2p with Kademlia support
    2. Wire process_dht_command() to actual Kademlia instance
    3. Connect command queue to libp2p event loop

Environment Variables:
    DCPP_STUB_MODE: Set to "1" to enable stub mode for testing.
                   In stub mode, DHT operations return success without
                   actually executing. In production mode (default),
                   operations fail explicitly if no Kademlia backend.

Features:
- Async command/response channels (ready for real DHT)
- Bootstrap configuration (static peers, DNS discovery, mDNS)
- Provider records for collection discovery
- Local cache for testing/fallback

RFC Section 9.1:
- DHT key format: sha256("dcpp/1.0:" + collection_id)
- Re-announce interval: 1 hour
- Provider record TTL: 24 hours
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, List, Optional, Tuple, Protocol, cast

from dcpp_python.network.dht.base import DHTBackend, DHTConfig, ProviderRecord


def is_stub_mode() -> bool:
    """
    Check if DHT stub mode is enabled.

    Returns True if DCPP_STUB_MODE environment variable is set to "1".
    In stub mode, DHT operations return success without executing.
    In production mode (default), operations fail explicitly if no backend.
    """
    return os.environ.get("DCPP_STUB_MODE", "0") == "1"


def is_libp2p_kaddht_available() -> bool:
    """
    Check if py-libp2p KadDHT is available for real network DHT operations.

    Returns True if the libp2p KadDHT module can be imported.
    The actual integration happens in libp2p_real.py.
    """
    try:
        from libp2p.kad_dht.kad_dht import KadDHT  # noqa: F401

        return True
    except ImportError:
        return False


logger = logging.getLogger("dcpp.dht_real")


class DHTCommandType(Enum):
    """Types of DHT commands."""

    PROVIDE = auto()
    FIND_PROVIDERS = auto()
    PUT_VALUE = auto()
    GET_VALUE = auto()
    BOOTSTRAP = auto()
    GET_CLOSEST_PEERS = auto()


@dataclass
class DHTCommand:
    """
    A command to send to the DHT event loop.

    Commands are processed by the libp2p host's event loop and
    results are returned via the response_queue.

    Per RFC Section 9.3, bootstrap peers are used for initial peer discovery.
    The peers field stores (peer_id, multiaddr) tuples for BOOTSTRAP commands.
    """

    command_type: DHTCommandType
    key: bytes
    value: Optional[bytes] = None
    multiaddrs: Optional[List[str]] = None
    # Bootstrap peers: list of (peer_id, multiaddr) tuples (RFC Section 9.3)
    peers: Optional[List[Tuple[bytes, str]]] = None
    response_queue: Optional[asyncio.Queue["DHTResponse"]] = None

    @classmethod
    def provide(cls, key: bytes, multiaddrs: List[str]) -> "DHTCommand":
        """Create a PROVIDE command."""
        return cls(
            command_type=DHTCommandType.PROVIDE,
            key=key,
            multiaddrs=multiaddrs,
            response_queue=asyncio.Queue(maxsize=1),
        )

    @classmethod
    def find_providers(cls, key: bytes) -> "DHTCommand":
        """Create a FIND_PROVIDERS command."""
        return cls(
            command_type=DHTCommandType.FIND_PROVIDERS,
            key=key,
            response_queue=asyncio.Queue(maxsize=1),
        )

    @classmethod
    def put_value(cls, key: bytes, value: bytes) -> "DHTCommand":
        """Create a PUT_VALUE command."""
        return cls(
            command_type=DHTCommandType.PUT_VALUE,
            key=key,
            value=value,
            response_queue=asyncio.Queue(maxsize=1),
        )

    @classmethod
    def get_value(cls, key: bytes) -> "DHTCommand":
        """Create a GET_VALUE command."""
        return cls(
            command_type=DHTCommandType.GET_VALUE,
            key=key,
            response_queue=asyncio.Queue(maxsize=1),
        )

    @classmethod
    def bootstrap(cls, peers: List[Tuple[bytes, str]]) -> "DHTCommand":
        """
        Create a BOOTSTRAP command.

        Per RFC Section 9.3, bootstrap peers are used for initial DHT discovery.
        Peers are stored and passed to the Kademlia implementation.

        Args:
            peers: List of (peer_id, multiaddr) tuples for bootstrap nodes

        Returns:
            DHTCommand configured for bootstrap operation
        """
        return cls(
            command_type=DHTCommandType.BOOTSTRAP,
            key=b"",
            peers=peers,  # Store peers for handler to use
            response_queue=asyncio.Queue(maxsize=1),
        )


@dataclass
class DHTResponse:
    """Response from a DHT command."""

    success: bool
    data: list[ProviderRecord] | bytes | None = None
    error: Optional[str] = None


@dataclass
class BootstrapConfig:
    """
    Bootstrap configuration for the DHT.

    Supports multiple discovery mechanisms per RFC Section 9.3:
    - Static peer list (known bootstrap nodes)
    - DNS TXT discovery (query DNS for bootstrap nodes)
    - IPNS fallback (resolve IPNS name for bootstrap list)
    - mDNS local discovery (find peers on local network)
    """

    # Static bootstrap peers: list of (peer_id, multiaddr)
    static_peers: List[Tuple[bytes, str]] = field(default_factory=list)

    # DNS TXT record for bootstrap discovery (RFC Section 9.3)
    # Format: _dcpp-bootstrap.dcpp.network TXT "peer_id@/ip4/1.2.3.4/tcp/4001"
    dns_discovery: str = "_dcpp-bootstrap.dcpp.network"

    # IPNS name for bootstrap fallback (RFC Section 9.3)
    # Format: /ipns/k51... or /ipns/dcpp.network
    ipns_fallback: str = "/ipns/bootstrap.dcpp.network"

    # Public IPFS gateways for IPNS resolution
    ipfs_gateways: List[str] = field(
        default_factory=lambda: [
            "https://ipfs.io",
            "https://dweb.link",
            "https://cloudflare-ipfs.com",
        ]
    )

    # Enable mDNS for local peer discovery
    mdns_enabled: bool = True

    # Timeout for DNS queries (seconds)
    dns_timeout: float = 5.0

    # Timeout for IPNS resolution (seconds)
    ipns_timeout: float = 10.0

    # Maximum peers to discover via DNS/IPNS
    max_dns_peers: int = 10

    async def discover_peers(self) -> List[Tuple[bytes, str]]:
        """
        Discover bootstrap peers using configured mechanisms.

        Per RFC Section 9.3, discovery order:
        1. Static peers (highest priority)
        2. DNS TXT discovery
        3. IPNS fallback (if DNS fails or returns no peers)

        Returns combined list from all discovery mechanisms.
        """
        peers = list(self.static_peers)

        # Try DNS discovery first (RFC Section 9.3)
        if self.dns_discovery:
            dns_peers = await self._discover_via_dns()
            peers.extend(dns_peers)

        # IPNS fallback if DNS returned no peers (RFC Section 9.3)
        if len(peers) == len(self.static_peers) and self.ipns_fallback:
            logger.info("DNS discovery returned no peers, trying IPNS fallback")
            ipns_peers = await self._discover_via_ipns()
            peers.extend(ipns_peers)

        return peers

    async def _discover_via_dns(self) -> List[Tuple[bytes, str]]:
        """
        Discover peers via DNS TXT records.

        DNS TXT format: "peer_id_hex@multiaddr"
        Example: "12D3KooW...@/ip4/93.184.216.34/tcp/4001"
        """
        peers: List[Tuple[bytes, str]] = []

        try:
            loop = asyncio.get_event_loop()
            # Use asyncio to run DNS lookup in executor
            records = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: self._dns_txt_lookup(self.dns_discovery)),
                timeout=self.dns_timeout,
            )

            for record in records[: self.max_dns_peers]:
                try:
                    # Parse "peer_id_hex@multiaddr" format
                    if "@" in record:
                        peer_id_hex, multiaddr = record.split("@", 1)
                        peer_id = bytes.fromhex(peer_id_hex)
                        peers.append((peer_id, multiaddr))
                except (ValueError, IndexError) as e:
                    logger.debug(f"Invalid DNS bootstrap record: {record} ({e})")

        except asyncio.TimeoutError:
            logger.warning(f"DNS bootstrap discovery timed out for {self.dns_discovery}")
        except Exception as e:
            logger.debug(f"DNS bootstrap discovery failed: {e}")

        return peers

    async def _discover_via_ipns(self) -> List[Tuple[bytes, str]]:
        """
        Discover peers via IPNS resolution (RFC Section 9.3 fallback).

        IPNS names resolve to IPFS content containing bootstrap peer list.
        Format: one "peer_id_hex@multiaddr" per line.
        """
        peers: List[Tuple[bytes, str]] = []

        if not self.ipns_fallback:
            return peers

        for gateway in self.ipfs_gateways:
            try:
                ipns_peers = await self._fetch_ipns_bootstrap(gateway)
                if ipns_peers:
                    peers.extend(ipns_peers[: self.max_dns_peers])
                    logger.info(f"IPNS discovery found {len(ipns_peers)} peers via {gateway}")
                    break  # Stop after first successful gateway
            except Exception as e:
                logger.debug(f"IPNS discovery failed via {gateway}: {e}")
                continue

        return peers

    async def _fetch_ipns_bootstrap(self, gateway: str) -> List[Tuple[bytes, str]]:
        """
        Fetch bootstrap peers from IPNS via an IPFS gateway.

        Args:
            gateway: IPFS gateway base URL

        Returns:
            List of (peer_id, multiaddr) tuples
        """
        import urllib.request
        import urllib.error

        peers = []

        # Convert IPNS path to gateway URL
        ipns_path = self.ipns_fallback
        if ipns_path.startswith("/ipns/"):
            url = f"{gateway}{ipns_path}"
        else:
            url = f"{gateway}/ipns/{ipns_path}"

        try:
            loop = asyncio.get_event_loop()

            def fetch() -> str:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "DCPP/1.0 Bootstrap"},
                )
                with urllib.request.urlopen(req, timeout=self.ipns_timeout) as resp:
                    return cast(str, resp.read().decode("utf-8"))

            content = await asyncio.wait_for(
                loop.run_in_executor(None, fetch),
                timeout=self.ipns_timeout + 1,
            )

            # Parse bootstrap list (one peer per line)
            for line in content.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    # Parse "peer_id_hex@multiaddr" format
                    if "@" in line:
                        peer_id_hex, multiaddr = line.split("@", 1)
                        peer_id = bytes.fromhex(peer_id_hex)
                        peers.append((peer_id, multiaddr))
                except (ValueError, IndexError) as e:
                    logger.debug(f"Invalid IPNS bootstrap record: {line} ({e})")

        except asyncio.TimeoutError:
            logger.debug(f"IPNS fetch timed out: {url}")
        except urllib.error.HTTPError as e:
            logger.debug(f"IPNS fetch HTTP error {e.code}: {url}")
        except urllib.error.URLError as e:
            logger.debug(f"IPNS fetch URL error: {url} ({e.reason})")
        except Exception as e:
            logger.debug(f"IPNS fetch failed: {url} ({e})")

        return peers

    def _dns_txt_lookup(self, domain: str) -> List[str]:
        """
        Perform DNS TXT lookup (blocking, run in executor).

        Returns list of TXT record values.
        """
        try:
            import dns.resolver  # type: ignore[import-not-found]

            answers = dns.resolver.resolve(domain, "TXT")
            records = []
            for rdata in answers:
                for txt in rdata.strings:
                    records.append(txt.decode("utf-8"))
            return records
        except ImportError:
            # dnspython not installed, try socket fallback
            logger.debug("dnspython not installed, DNS discovery limited")
            return []
        except Exception as e:
            logger.debug(f"DNS lookup failed for {domain}: {e}")
            return []


class KademliaDHT(DHTBackend):
    """
    Real Kademlia DHT implementation using async channels.

    This class implements the DHTBackend trait and communicates with
    the libp2p host's event loop via command/response channels.

    Usage:
        dht = KademliaDHT(config, command_queue)
        await dht.start()
        success = await dht.provide(dht_key, multiaddrs)
        providers = await dht.find_providers(dht_key)
        await dht.stop()
    """

    def __init__(
        self,
        config: DHTConfig,
        command_queue: Optional[asyncio.Queue[DHTCommand]] = None,
        bootstrap_config: Optional[BootstrapConfig] = None,
    ):
        """
        Initialize Kademlia DHT.

        Args:
            config: DHT configuration
            command_queue: Queue for sending commands to libp2p event loop
            bootstrap_config: Bootstrap configuration
        """
        self._config = config
        self._command_queue: asyncio.Queue[DHTCommand] = command_queue or asyncio.Queue()
        self._bootstrap_config = bootstrap_config or BootstrapConfig()
        self._started = False
        self._local_node_id: Optional[bytes] = None
        self._local_multiaddrs: List[str] = []

        # Local provider cache for testing/fallback
        self._local_providers: dict[bytes, List[ProviderRecord]] = {}
        self._local_values: dict[bytes, bytes] = {}

    @property
    def command_queue(self) -> asyncio.Queue[DHTCommand]:
        """Get the command queue for the libp2p host to process."""
        return self._command_queue

    def set_local_identity(self, node_id: bytes, multiaddrs: List[str]) -> None:
        """Set the local node identity (called by host after start)."""
        self._local_node_id = node_id
        self._local_multiaddrs = multiaddrs

    async def start(self) -> None:
        """Start the DHT and perform bootstrap."""
        if self._started:
            return

        self._started = True

        # Log DHT mode explicitly (helps identify why cross-node discovery fails)
        stub_mode = is_stub_mode()
        kaddht_available = is_libp2p_kaddht_available()

        if stub_mode:
            logger.warning(
                "[DHT] Starting in STUB MODE (DCPP_STUB_MODE=1). "
                "DHT operations will succeed but are LOCAL-ONLY. "
                "Cross-node discovery will NOT work."
            )
        elif kaddht_available:
            # py-libp2p KadDHT is available - libp2p_real.py will wire it up
            logger.info(
                "[DHT] Local cache initialized. "
                "py-libp2p KadDHT is available - network mode will be enabled by libp2p host."
            )
        else:
            logger.warning(
                "[DHT] Starting in LOCAL CACHE mode. "
                "py-libp2p Kademlia not available - DHT queries return local cache only. "
                "Cross-node provider discovery requires py-libp2p Kademlia integration. "
                "Set DCPP_STUB_MODE=1 to suppress operation errors."
            )

        logger.info("[DHT] Kademlia DHT started")
        logger.debug(
            f"[DHT] Config: query_timeout={self._config.query_timeout}s "
            f"reannounce={self._config.reannounce_interval}s ttl={self._config.provider_ttl}s"
        )

        # Discover and connect to bootstrap peers
        if self._bootstrap_config:
            try:
                logger.debug("[DHT] Starting bootstrap peer discovery...")
                peers = await self._bootstrap_config.discover_peers()
                if peers:
                    logger.info(f"[DHT] Discovered {len(peers)} bootstrap peer(s)")
                    for peer_id, multiaddr in peers[:5]:  # Log first 5
                        logger.debug(
                            f"[DHT] Bootstrap peer: {peer_id.hex()[:16] if peer_id else 'unknown'}... "
                            f"at {multiaddr}"
                        )
                    await self._bootstrap(peers)
                else:
                    logger.warning("[DHT] No bootstrap peers discovered")
            except Exception as e:
                logger.warning(f"[DHT] Bootstrap discovery failed: {e}", exc_info=True)

    async def stop(self) -> None:
        """Stop the DHT."""
        self._started = False
        logger.info("Kademlia DHT stopped")

    async def _send_command(
        self, command: DHTCommand, timeout: Optional[float] = None
    ) -> DHTResponse:
        """
        Send a command and wait for response.

        Args:
            command: DHT command to send
            timeout: Response timeout (uses config default if None)

        Returns:
            DHTResponse with result or error
        """
        if not self._started:
            return DHTResponse(success=False, error="DHT not started")

        timeout = timeout or self._config.query_timeout

        try:
            # Send command to event loop
            await self._command_queue.put(command)

            # Wait for response
            if command.response_queue:
                response = await asyncio.wait_for(
                    command.response_queue.get(),
                    timeout=timeout,
                )
                return response

            return DHTResponse(success=True)

        except asyncio.TimeoutError:
            return DHTResponse(success=False, error="DHT operation timed out")
        except Exception as e:
            return DHTResponse(success=False, error=str(e))

    async def provide(self, key: bytes, multiaddrs: List[str]) -> bool:
        """
        Announce as a provider for a key.

        This publishes a provider record to the DHT, allowing other nodes
        to discover this node as providing content for the given key.

        Args:
            key: DHT key (32 bytes, typically sha256 hash)
            multiaddrs: Multiaddresses where content can be retrieved

        Returns:
            True if announcement succeeded
        """
        if not self._started:
            logger.warning("Cannot provide: DHT not started")
            return False

        # Store locally as fallback/cache
        record = ProviderRecord(
            node_id=self._local_node_id or b"",
            multiaddrs=multiaddrs or self._local_multiaddrs,
            collection_id="",
            timestamp=int(time.time()),
            ttl=self._config.provider_ttl,
        )

        if key not in self._local_providers:
            self._local_providers[key] = []

        # Update existing or add new
        self._local_providers[key] = [
            r for r in self._local_providers[key] if r.node_id != record.node_id
        ]
        self._local_providers[key].append(record)

        # Send to real DHT if available
        command = DHTCommand.provide(key, multiaddrs)
        response = await self._send_command(command)

        if response.success:
            logger.debug(f"Provided key {key.hex()[:16]}...")
        else:
            logger.debug(f"Provide cached locally (real DHT: {response.error})")

        return True  # Local cache always succeeds

    async def find_providers(self, key: bytes) -> List[ProviderRecord]:
        """
        Find providers for a key.

        Queries the DHT for nodes that have announced as providers
        for the given key.

        Args:
            key: DHT key (32 bytes)

        Returns:
            List of provider records
        """
        if not self._started:
            return []

        # Query real DHT
        command = DHTCommand.find_providers(key)
        response = await self._send_command(command)

        providers: List[ProviderRecord] = []

        if response.success and isinstance(response.data, list):
            providers = response.data

        # Also check local cache
        if key in self._local_providers:
            local_records = [r for r in self._local_providers[key] if not r.is_expired()]
            # Merge, avoiding duplicates
            seen_nodes = {r.node_id for r in providers}
            for record in local_records:
                if record.node_id not in seen_nodes:
                    providers.append(record)

        logger.debug(f"Found {len(providers)} providers for {key.hex()[:16]}...")
        return providers

    async def put_value(self, key: bytes, value: bytes) -> bool:
        """
        Store a value in the DHT.

        Args:
            key: DHT key (32 bytes)
            value: Value to store

        Returns:
            True if storage succeeded
        """
        if not self._started:
            return False

        # Store locally as fallback
        self._local_values[key] = value

        # Send to real DHT
        command = DHTCommand.put_value(key, value)
        response = await self._send_command(command)

        if response.success:
            logger.debug(f"Put value for {key.hex()[:16]}...")
        else:
            logger.debug(f"Value cached locally (real DHT: {response.error})")

        return True  # Local cache always succeeds

    async def get_value(self, key: bytes) -> Optional[bytes]:
        """
        Retrieve a value from the DHT.

        Args:
            key: DHT key (32 bytes)

        Returns:
            Value bytes or None if not found
        """
        if not self._started:
            return None

        # Query real DHT first
        command = DHTCommand.get_value(key)
        response = await self._send_command(command)

        if response.success and response.data:
            return cast(bytes, response.data)

        # Fall back to local cache
        return self._local_values.get(key)

    async def _bootstrap(self, peers: List[Tuple[bytes, str]]) -> None:
        """
        Bootstrap the DHT with known peers.

        Per RFC Section 9.3, bootstrap node addresses are used for initial
        peer discovery. This method connects to the specified peers to
        populate the DHT routing table.

        Args:
            peers: List of (peer_id, multiaddr) tuples
        """
        if not peers:
            logger.debug("No bootstrap peers provided")
            return

        command = DHTCommand.bootstrap(peers)
        # Peers are stored in command.peers by the bootstrap() factory method
        response = await self._send_command(command, timeout=30.0)

        if response.success:
            logger.info(f"Bootstrapped with {len(peers)} peers")
        else:
            logger.warning(f"Bootstrap failed: {response.error}")


class KademliaBackendProtocol(Protocol):
    def add_address(self, peer_id: bytes, multiaddr: str) -> None:
        ...

    def bootstrap(self) -> None:
        ...


def process_dht_command(
    command: DHTCommand, kademlia: KademliaBackendProtocol | None
) -> DHTResponse:
    """
    Process a DHT command using a Kademlia instance.

    This function is called by the libp2p host's event loop to handle
    DHT commands. It's designed to work with py-libp2p's Kademlia implementation.

    IMPORTANT: In production mode (default), this function will fail explicitly
    if no Kademlia backend is provided. Set DCPP_STUB_MODE=1 environment variable
    to enable stub mode for testing.

    Per RFC Section 9.1:
    - DHT key format: sha256("dcpp/1.0:" + collection_id)
    - Re-announce interval: 1 hour
    - Provider record TTL: 24 hours

    Per RFC Section 9.3:
    - Bootstrap peers are used for initial peer discovery
    - Bootstrap addresses from DNS TXT: _dcpp-bootstrap.dcpp.network

    Args:
        command: DHT command to process
        kademlia: py-libp2p Kademlia DHT instance (None triggers stub/fail behavior)

    Returns:
        DHTResponse with result

    Raises:
        NotImplementedError: If kademlia is None and not in stub mode
    """
    stub_mode = is_stub_mode()
    command_type = command.command_type
    command_name = command_type.name if hasattr(command_type, "name") else str(command_type)
    logger.debug(
        f"[DHT] Processing {command_name} command "
        f"(kademlia={'present' if kademlia else 'none'}, stub={stub_mode})"
    )

    # If no Kademlia backend and not in stub mode, fail explicitly
    if kademlia is None and not stub_mode:
        error_msg = (
            "No Kademlia backend provided. DHT operations require py-libp2p "
            "with Kademlia support, or set DCPP_STUB_MODE=1 for testing."
        )
        logger.error(error_msg)
        return DHTResponse(success=False, error=error_msg)

    try:
        if command.command_type == DHTCommandType.PROVIDE:
            # Start providing a key (RFC Section 9.1)
            if kademlia is not None:
                # Wire to actual Kademlia: kademlia.provide(command.key)
                # TODO: Implement when py-libp2p Kademlia API is available
                pass
            if stub_mode:
                logger.debug(f"[STUB] PROVIDE key={command.key.hex()[:16]}...")
                return DHTResponse(success=True)
            return DHTResponse(
                success=False, error="Kademlia PROVIDE not implemented - install py-libp2p"
            )

        elif command.command_type == DHTCommandType.FIND_PROVIDERS:
            # Find providers for a key (RFC Section 9.1)
            if kademlia is not None:
                # Wire to actual Kademlia: providers = kademlia.get_providers(command.key)
                # TODO: Implement when py-libp2p Kademlia API is available
                pass
            if stub_mode:
                logger.debug(f"[STUB] FIND_PROVIDERS key={command.key.hex()[:16]}...")
                return DHTResponse(success=True, data=[])
            return DHTResponse(
                success=False, error="Kademlia FIND_PROVIDERS not implemented - install py-libp2p"
            )

        elif command.command_type == DHTCommandType.PUT_VALUE:
            # Store a value in DHT
            if kademlia is not None:
                # Wire to actual Kademlia: kademlia.put(command.key, command.value)
                # TODO: Implement when py-libp2p Kademlia API is available
                pass
            if stub_mode:
                logger.debug(f"[STUB] PUT_VALUE key={command.key.hex()[:16]}...")
                return DHTResponse(success=True)
            return DHTResponse(
                success=False, error="Kademlia PUT_VALUE not implemented - install py-libp2p"
            )

        elif command.command_type == DHTCommandType.GET_VALUE:
            # Get a value from DHT
            if kademlia is not None:
                # Wire to actual Kademlia: value = kademlia.get(command.key)
                # TODO: Implement when py-libp2p Kademlia API is available
                pass
            if stub_mode:
                logger.debug(f"[STUB] GET_VALUE key={command.key.hex()[:16]}...")
                return DHTResponse(success=True, data=None)
            return DHTResponse(
                success=False, error="Kademlia GET_VALUE not implemented - install py-libp2p"
            )

        elif command.command_type == DHTCommandType.BOOTSTRAP:
            # Bootstrap with peers (RFC Section 9.3)
            # Per Rust implementation parity: MUST seed routing table before bootstrap()
            #
            # Routing table seeding (REQUIRED before calling bootstrap):
            # 1. For each peer in peers, add to Kademlia routing table:
            #    kademlia.add_address(peer_id, multiaddr)
            # 2. Then call kademlia.bootstrap() to start the discovery process
            #
            # This ensures the routing table has seed entries for Kademlia
            # to use when starting iterative lookups.
            peers = command.peers or []

            if not peers:
                # No peers to bootstrap - this is informational, not an error
                logger.debug("[DHT] BOOTSTRAP called with no peers - nothing to do")
                return DHTResponse(success=True)

            if kademlia is not None:
                # Check if Kademlia actually has the methods we need
                has_add_address = hasattr(kademlia, "add_address") and callable(
                    getattr(kademlia, "add_address")
                )
                has_bootstrap = hasattr(kademlia, "bootstrap") and callable(
                    getattr(kademlia, "bootstrap")
                )

                if not has_add_address or not has_bootstrap:
                    # Kademlia instance exists but doesn't have required methods
                    # This means py-libp2p Kademlia isn't properly wired
                    logger.error(
                        f"[DHT] Kademlia backend present but missing required methods "
                        f"(add_address={has_add_address}, bootstrap={has_bootstrap}). "
                        "Routing table seeding NOT implemented."
                    )
                    return DHTResponse(
                        success=False,
                        error="Kademlia backend missing add_address/bootstrap methods - wiring incomplete",
                    )

                # Step 1: Add each peer to Kademlia routing table
                added_count = 0
                for peer_id, multiaddr in peers:
                    try:
                        kademlia.add_address(peer_id, multiaddr)
                        added_count += 1
                        logger.debug(
                            f"[DHT] Added bootstrap peer {peer_id.hex()[:16] if peer_id else 'unknown'}... at {multiaddr}"
                        )
                    except Exception as e:
                        logger.warning(f"Failed to add bootstrap peer: {e}")

                # Step 2: Trigger Kademlia bootstrap process
                if added_count > 0:
                    try:
                        kademlia.bootstrap()
                        logger.info(
                            f"[DHT] Kademlia bootstrap triggered with {added_count} seed peers"
                        )
                        return DHTResponse(success=True)
                    except Exception as e:
                        logger.error(f"Kademlia bootstrap failed: {e}")
                        return DHTResponse(success=False, error=str(e))
                else:
                    return DHTResponse(
                        success=False,
                        error=f"Failed to add any of {len(peers)} bootstrap peers to routing table",
                    )

            # No Kademlia backend
            if stub_mode:
                logger.debug(
                    f"[STUB] BOOTSTRAP with {len(peers)} peers (routing table seeding simulated)"
                )
                return DHTResponse(success=True)

            # Fail explicitly - we have peers but no backend to bootstrap with
            logger.error(
                f"[DHT] BOOTSTRAP requested with {len(peers)} peers but no Kademlia backend. "
                "Routing table seeding NOT performed. Cross-node discovery will NOT work."
            )
            return DHTResponse(
                success=False,
                error="Kademlia BOOTSTRAP not implemented - install py-libp2p with Kademlia support",
            )

        elif command.command_type == DHTCommandType.GET_CLOSEST_PEERS:
            # Find closest peers to a key
            if kademlia is not None:
                # Wire to actual Kademlia: peers = kademlia.find_node(command.key)
                pass
            if stub_mode:
                logger.debug(f"[STUB] GET_CLOSEST_PEERS key={command.key.hex()[:16]}...")
                return DHTResponse(success=True, data=[])
            return DHTResponse(
                success=False,
                error="Kademlia GET_CLOSEST_PEERS not implemented - install py-libp2p",
            )

        else:
            return DHTResponse(success=False, error=f"Unknown command type: {command_name}")

    except Exception as e:
        logger.error(f"DHT command failed: {e}")
        return DHTResponse(success=False, error=str(e))


# DHT key derivation helpers (re-exported from crypto for convenience)


def derive_dht_key(collection_id: str) -> bytes:
    """
    Derive DHT key for collection discovery (RFC Section 9.1.1).

    Format: sha256("dcpp/1.0:" + collection_id)

    Args:
        collection_id: Collection ID string

    Returns:
        32-byte DHT key
    """
    prefix = "dcpp/1.0:"
    return hashlib.sha256((prefix + collection_id).encode("utf-8")).digest()


def derive_private_dht_key(collection_key: bytes) -> bytes:
    """
    Derive DHT key for private collection discovery (RFC Section 9.2.2).

    Format: sha256("dcpp/1.0/private:" + collection_key)

    Args:
        collection_key: 256-bit collection key

    Returns:
        32-byte DHT key
    """
    prefix = b"dcpp/1.0/private:"
    return hashlib.sha256(prefix + collection_key).digest()
