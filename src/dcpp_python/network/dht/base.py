"""
DCPP DHT Integration

Implements Kademlia DHT discovery for DCPP (RFC Section 9).
Provides collection discovery and peer announcement via DHT provider records.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable

from dcpp_python.crypto.signing import derive_dht_key, derive_private_dht_key
from .interfaces import DHTBackendProtocol


logger = logging.getLogger("dcpp.dht")


@dataclass
class ProviderRecord:
    """DHT provider record for a collection."""

    node_id: bytes
    multiaddrs: list[str]
    collection_id: str
    timestamp: int
    ttl: int = 86400  # 24 hours default

    def is_expired(self) -> bool:
        """Check if record has expired."""
        return time.time() > self.timestamp + self.ttl


@dataclass
class DHTConfig:
    """DHT configuration."""

    # Bootstrap peers (multiaddr format)
    bootstrap_peers: list[str] = field(default_factory=list)
    # Reannounce interval (seconds)
    reannounce_interval: int = 3600  # 1 hour
    # Provider record TTL (seconds)
    provider_ttl: int = 86400  # 24 hours
    # Max providers to fetch per query
    max_providers: int = 20
    # Query timeout (seconds)
    query_timeout: float = 30.0
    # Kademlia k parameter (bucket size)
    k_value: int = 20
    # Kademlia alpha parameter (concurrency)
    alpha_value: int = 3


class DHTBackend(ABC):
    """Abstract base class for DHT backends."""

    @abstractmethod
    async def start(self) -> None:
        """Start the DHT."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the DHT."""
        pass

    @abstractmethod
    async def provide(self, key: bytes, multiaddrs: list[str]) -> bool:
        """
        Announce as a provider for a key.

        Args:
            key: DHT key (32 bytes)
            multiaddrs: Multiaddresses to announce

        Returns:
            True if announcement succeeded
        """
        pass

    @abstractmethod
    async def find_providers(self, key: bytes) -> list[ProviderRecord]:
        """
        Find providers for a key.

        Args:
            key: DHT key (32 bytes)

        Returns:
            List of provider records
        """
        pass

    @abstractmethod
    async def put_value(self, key: bytes, value: bytes) -> bool:
        """Store a value in the DHT."""
        pass

    @abstractmethod
    async def get_value(self, key: bytes) -> bytes | None:
        """Retrieve a value from the DHT."""
        pass


class CollectionDiscovery:
    """
    Collection discovery service using DHT.

    Handles:
    - Announcing as a guardian for collections
    - Finding guardians for collections
    - Subscribing to collection updates (via pubsub topic)
    """

    def __init__(self, dht: DHTBackendProtocol, node_id: bytes, config: DHTConfig | None = None):
        """
        Initialize collection discovery.

        Args:
            dht: DHT backend implementation
            node_id: This node's peer ID
            config: DHT configuration
        """
        self.dht = dht
        self.node_id = node_id
        self.config = config or DHTConfig()
        self._announced_collections: dict[str, int] = {}  # collection_id -> last_announce_time
        self._reannounce_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start the discovery service."""
        await self.dht.start()
        self._reannounce_task = asyncio.create_task(self._reannounce_loop())
        logger.info("Collection discovery service started")

    async def stop(self) -> None:
        """Stop the discovery service."""
        if self._reannounce_task:
            self._reannounce_task.cancel()
            try:
                await self._reannounce_task
            except asyncio.CancelledError:
                pass
        await self.dht.stop()
        logger.info("Collection discovery service stopped")

    async def announce_collection(
        self,
        collection_id: str,
        multiaddrs: list[str],
        collection_key: bytes | None = None,
    ) -> bool:
        """
        Announce as a guardian for a collection.

        Args:
            collection_id: Collection ID (e.g., "eth:0xBC4CA0")
            multiaddrs: This node's multiaddresses
            collection_key: For private collections, the collection key

        Returns:
            True if announcement succeeded
        """
        # Derive DHT key
        if collection_key:
            dht_key = derive_private_dht_key(collection_key)
        else:
            dht_key = derive_dht_key(collection_id)

        logger.debug(f"Announcing collection {collection_id} with key {dht_key.hex()[:16]}...")

        success = await self.dht.provide(dht_key, multiaddrs)

        if success:
            self._announced_collections[collection_id] = int(time.time())
            logger.info(f"Announced as guardian for {collection_id}")
        else:
            logger.warning(f"Failed to announce for {collection_id}")

        return success

    async def find_guardians(
        self,
        collection_id: str,
        collection_key: bytes | None = None,
    ) -> list[ProviderRecord]:
        """
        Find guardians for a collection.

        Args:
            collection_id: Collection ID
            collection_key: For private collections, the collection key

        Returns:
            List of guardian provider records
        """
        # Derive DHT key
        if collection_key:
            dht_key = derive_private_dht_key(collection_key)
        else:
            dht_key = derive_dht_key(collection_id)

        logger.debug(f"Finding guardians for {collection_id}...")

        providers = await self.dht.find_providers(dht_key)

        # Filter expired records
        valid_providers = [p for p in providers if not p.is_expired()]

        logger.info(f"Found {len(valid_providers)} guardians for {collection_id}")
        return valid_providers

    async def _reannounce_loop(self) -> None:
        """Periodically reannounce all collections."""
        while True:
            try:
                await asyncio.sleep(self.config.reannounce_interval)

                # Reannounce all collections
                for collection_id in list(self._announced_collections.keys()):
                    # Get multiaddrs (would come from libp2p host)
                    # For now, this is a placeholder
                    multiaddrs: list[str] = []
                    await self.announce_collection(collection_id, multiaddrs)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Reannounce loop error: {e}")


class LocalDHT(DHTBackend):
    """
    Local in-memory DHT for testing.

    Simulates DHT behavior without actual network communication.
    Useful for unit tests and development.
    """

    def __init__(self) -> None:
        self._providers: dict[bytes, list[ProviderRecord]] = {}
        self._values: dict[bytes, bytes] = {}
        self._started = False

    async def start(self) -> None:
        self._started = True
        logger.info("Local DHT started (test mode)")

    async def stop(self) -> None:
        self._started = False
        logger.info("Local DHT stopped")

    async def provide(self, key: bytes, multiaddrs: list[str]) -> bool:
        if not self._started:
            return False

        record = ProviderRecord(
            node_id=b"local",
            multiaddrs=multiaddrs,
            collection_id="",
            timestamp=int(time.time()),
        )

        if key not in self._providers:
            self._providers[key] = []

        # Update or add record
        self._providers[key] = [r for r in self._providers[key] if r.node_id != record.node_id]
        self._providers[key].append(record)

        return True

    async def find_providers(self, key: bytes) -> list[ProviderRecord]:
        if not self._started:
            return []

        return [r for r in self._providers.get(key, []) if not r.is_expired()]

    async def put_value(self, key: bytes, value: bytes) -> bool:
        if not self._started:
            return False
        self._values[key] = value
        return True

    async def get_value(self, key: bytes) -> bytes | None:
        if not self._started:
            return None
        return self._values.get(key)


class SimulatedNetworkDHT(DHTBackend):
    """
    Simulated network DHT for integration testing.

    Multiple instances can be connected to simulate a network.
    """

    # Class-level shared state for simulation
    _network_providers: dict[bytes, list[ProviderRecord]] = {}
    _network_values: dict[bytes, bytes] = {}
    _nodes: list["SimulatedNetworkDHT"] = []

    def __init__(self, node_id: bytes, multiaddrs: list[str]):
        self.node_id = node_id
        self.multiaddrs = multiaddrs
        self._started = False

    async def start(self) -> None:
        self._started = True
        SimulatedNetworkDHT._nodes.append(self)
        logger.info(f"Simulated DHT node {self.node_id.hex()[:8]} joined network")

    async def stop(self) -> None:
        self._started = False
        if self in SimulatedNetworkDHT._nodes:
            SimulatedNetworkDHT._nodes.remove(self)
        logger.info(f"Simulated DHT node {self.node_id.hex()[:8]} left network")

    async def provide(self, key: bytes, multiaddrs: list[str]) -> bool:
        if not self._started:
            return False

        record = ProviderRecord(
            node_id=self.node_id,
            multiaddrs=multiaddrs or self.multiaddrs,
            collection_id="",
            timestamp=int(time.time()),
        )

        if key not in SimulatedNetworkDHT._network_providers:
            SimulatedNetworkDHT._network_providers[key] = []

        # Remove existing record from same node
        SimulatedNetworkDHT._network_providers[key] = [
            r for r in SimulatedNetworkDHT._network_providers[key] if r.node_id != self.node_id
        ]
        SimulatedNetworkDHT._network_providers[key].append(record)

        return True

    async def find_providers(self, key: bytes) -> list[ProviderRecord]:
        if not self._started:
            return []

        return [
            r for r in SimulatedNetworkDHT._network_providers.get(key, []) if not r.is_expired()
        ]

    async def put_value(self, key: bytes, value: bytes) -> bool:
        if not self._started:
            return False
        SimulatedNetworkDHT._network_values[key] = value
        return True

    async def get_value(self, key: bytes) -> bytes | None:
        if not self._started:
            return None
        return SimulatedNetworkDHT._network_values.get(key)

    @classmethod
    def reset_network(cls) -> None:
        """Reset the simulated network (for testing)."""
        cls._network_providers.clear()
        cls._network_values.clear()
        cls._nodes.clear()


# PubSub topic derivation (RFC Section 9.1.2)


def derive_pubsub_topic(collection_id: str) -> str:
    """
    Derive pubsub topic for collection announcements (RFC Section 9.2).

    Format: /dcpp/1.0/collection/{collection_id}

    Args:
        collection_id: Collection ID

    Returns:
        Pubsub topic string
    """
    return f"/dcpp/1.0/collection/{collection_id}"


def derive_private_pubsub_topic(collection_key: bytes) -> str:
    """
    Derive pubsub topic for private collection announcements (RFC Section 9.2.3).

    Format: /dcpp/1.0/private/{sha256("dcpp/1.0/private:" + collection_key).hex()}

    Args:
        collection_key: 256-bit collection key

    Returns:
        Pubsub topic string
    """
    from dcpp_python.crypto.signing import derive_private_dht_key

    topic_key = derive_private_dht_key(collection_key)
    return f"/dcpp/1.0/private/{topic_key.hex()}"
