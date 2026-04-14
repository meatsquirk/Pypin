"""
Tests for DCPP DHT Module (dht.py)

Tests for LocalDHT, SimulatedNetworkDHT, CollectionDiscovery, and related classes.
"""

import asyncio
import time

import pytest

from dcpp_python.dht import (
    ProviderRecord,
    DHTConfig,
    DHTBackend,
    LocalDHT,
    SimulatedNetworkDHT,
    CollectionDiscovery,
    derive_pubsub_topic,
    derive_private_pubsub_topic,
)
from dcpp_python.crypto import derive_dht_key, derive_private_dht_key


# =============================================================================
# ProviderRecord Tests
# =============================================================================

class TestProviderRecord:
    """Tests for ProviderRecord dataclass."""

    def test_create_record(self):
        """Create a provider record."""
        record = ProviderRecord(
            node_id=b"test_node",
            multiaddrs=["/ip4/127.0.0.1/tcp/4001"],
            collection_id="test:collection",
            timestamp=int(time.time()),
            ttl=3600
        )

        assert record.node_id == b"test_node"
        assert len(record.multiaddrs) == 1
        assert record.ttl == 3600

    def test_is_expired_fresh(self):
        """Fresh record should not be expired."""
        record = ProviderRecord(
            node_id=b"fresh",
            multiaddrs=[],
            collection_id="test",
            timestamp=int(time.time()),
            ttl=3600
        )

        assert record.is_expired() is False

    def test_is_expired_old(self):
        """Old record should be expired."""
        record = ProviderRecord(
            node_id=b"old",
            multiaddrs=[],
            collection_id="test",
            timestamp=int(time.time()) - 7200,  # 2 hours ago
            ttl=3600  # 1 hour TTL
        )

        assert record.is_expired() is True

    def test_default_ttl(self):
        """Default TTL should be 24 hours."""
        record = ProviderRecord(
            node_id=b"default",
            multiaddrs=[],
            collection_id="test",
            timestamp=int(time.time())
        )

        assert record.ttl == 86400


# =============================================================================
# DHTConfig Tests
# =============================================================================

class TestDHTConfig:
    """Tests for DHTConfig dataclass."""

    def test_default_config(self):
        """Default config should have sensible defaults."""
        config = DHTConfig()

        assert config.bootstrap_peers == []
        assert config.reannounce_interval == 3600  # 1 hour
        assert config.provider_ttl == 86400  # 24 hours
        assert config.max_providers == 20
        assert config.query_timeout == 30.0
        assert config.k_value == 20  # Kademlia k parameter
        assert config.alpha_value == 3  # Kademlia alpha parameter

    def test_custom_config(self):
        """Custom config values should be set."""
        config = DHTConfig(
            bootstrap_peers=["/ip4/1.2.3.4/tcp/4001"],
            reannounce_interval=1800,
            max_providers=50
        )

        assert config.bootstrap_peers == ["/ip4/1.2.3.4/tcp/4001"]
        assert config.reannounce_interval == 1800
        assert config.max_providers == 50


# =============================================================================
# LocalDHT Tests
# =============================================================================

class TestLocalDHT:
    """Tests for LocalDHT (in-memory test DHT)."""

    @pytest.fixture
    def dht(self):
        return LocalDHT()

    @pytest.mark.asyncio
    async def test_start_stop(self, dht):
        """DHT can start and stop."""
        await dht.start()
        assert dht._started is True

        await dht.stop()
        assert dht._started is False

    @pytest.mark.asyncio
    async def test_provide_stores_record(self, dht):
        """Provide stores a record."""
        await dht.start()

        key = b"\x00" * 32
        multiaddrs = ["/ip4/127.0.0.1/tcp/4001"]

        result = await dht.provide(key, multiaddrs)
        assert result is True

        await dht.stop()

    @pytest.mark.asyncio
    async def test_provide_fails_when_stopped(self, dht):
        """Provide fails when DHT is not started."""
        key = b"\x00" * 32
        result = await dht.provide(key, [])
        assert result is False

    @pytest.mark.asyncio
    async def test_find_providers_retrieves_records(self, dht):
        """Find providers retrieves stored records."""
        await dht.start()

        key = b"\x11" * 32
        multiaddrs = ["/ip4/127.0.0.1/tcp/4001", "/ip4/127.0.0.1/udp/4001/quic"]

        await dht.provide(key, multiaddrs)
        providers = await dht.find_providers(key)

        assert len(providers) >= 1
        assert providers[0].multiaddrs == multiaddrs

        await dht.stop()

    @pytest.mark.asyncio
    async def test_find_providers_empty_key(self, dht):
        """Find providers returns empty for unknown key."""
        await dht.start()

        providers = await dht.find_providers(b"\xff" * 32)
        assert providers == []

        await dht.stop()

    @pytest.mark.asyncio
    async def test_find_providers_fails_when_stopped(self, dht):
        """Find providers fails when DHT is not started."""
        providers = await dht.find_providers(b"\x00" * 32)
        assert providers == []

    @pytest.mark.asyncio
    async def test_put_get_value(self, dht):
        """Put and get values."""
        await dht.start()

        key = b"\x22" * 32
        value = b"test_value_data"

        result = await dht.put_value(key, value)
        assert result is True

        retrieved = await dht.get_value(key)
        assert retrieved == value

        await dht.stop()

    @pytest.mark.asyncio
    async def test_get_value_missing(self, dht):
        """Get value returns None for missing key."""
        await dht.start()

        value = await dht.get_value(b"\xaa" * 32)
        assert value is None

        await dht.stop()

    @pytest.mark.asyncio
    async def test_put_get_fails_when_stopped(self, dht):
        """Put/get fails when DHT is not started."""
        assert await dht.put_value(b"\x00" * 32, b"test") is False
        assert await dht.get_value(b"\x00" * 32) is None

    @pytest.mark.asyncio
    async def test_provide_updates_existing_record(self, dht):
        """Provide updates existing record for same node."""
        await dht.start()

        key = b"\x33" * 32

        # First provide
        await dht.provide(key, ["/ip4/1.2.3.4/tcp/4001"])

        # Second provide (should update, not duplicate)
        await dht.provide(key, ["/ip4/5.6.7.8/tcp/4001"])

        providers = await dht.find_providers(key)
        # Should still have 1 record (updated)
        assert len(providers) == 1
        assert providers[0].multiaddrs == ["/ip4/5.6.7.8/tcp/4001"]

        await dht.stop()


# =============================================================================
# SimulatedNetworkDHT Tests
# =============================================================================

class TestSimulatedNetworkDHT:
    """Tests for SimulatedNetworkDHT (multi-node simulation)."""

    @pytest.fixture(autouse=True)
    def reset_network(self):
        """Reset the simulated network before each test."""
        SimulatedNetworkDHT.reset_network()
        yield
        SimulatedNetworkDHT.reset_network()

    @pytest.mark.asyncio
    async def test_create_node(self):
        """Create a simulated DHT node."""
        node = SimulatedNetworkDHT(
            node_id=b"node1",
            multiaddrs=["/ip4/127.0.0.1/tcp/4001"]
        )

        assert node.node_id == b"node1"
        assert not node._started

    @pytest.mark.asyncio
    async def test_node_joins_network(self):
        """Node joins the simulated network on start."""
        node = SimulatedNetworkDHT(
            node_id=b"node1",
            multiaddrs=["/ip4/127.0.0.1/tcp/4001"]
        )

        await node.start()
        assert node._started is True
        assert node in SimulatedNetworkDHT._nodes

        await node.stop()
        assert node._started is False
        assert node not in SimulatedNetworkDHT._nodes

    @pytest.mark.asyncio
    async def test_multiple_nodes_share_state(self):
        """Multiple nodes share network state."""
        node1 = SimulatedNetworkDHT(b"node1", ["/ip4/1.2.3.4/tcp/4001"])
        node2 = SimulatedNetworkDHT(b"node2", ["/ip4/5.6.7.8/tcp/4001"])

        await node1.start()
        await node2.start()

        # Node1 provides
        key = b"\x00" * 32
        await node1.provide(key, ["/ip4/1.2.3.4/tcp/4001"])

        # Node2 should find it
        providers = await node2.find_providers(key)
        assert len(providers) == 1
        assert providers[0].node_id == b"node1"

        await node1.stop()
        await node2.stop()

    @pytest.mark.asyncio
    async def test_multiple_providers(self):
        """Multiple nodes can provide for same key."""
        node1 = SimulatedNetworkDHT(b"node1", ["/ip4/1.2.3.4/tcp/4001"])
        node2 = SimulatedNetworkDHT(b"node2", ["/ip4/5.6.7.8/tcp/4001"])
        node3 = SimulatedNetworkDHT(b"node3", ["/ip4/9.10.11.12/tcp/4001"])

        await node1.start()
        await node2.start()
        await node3.start()

        key = b"\x11" * 32

        await node1.provide(key, [])
        await node2.provide(key, [])

        # Node3 finds both providers
        providers = await node3.find_providers(key)
        assert len(providers) == 2
        node_ids = {p.node_id for p in providers}
        assert node_ids == {b"node1", b"node2"}

        await node1.stop()
        await node2.stop()
        await node3.stop()

    @pytest.mark.asyncio
    async def test_put_get_value_shared(self):
        """Values are shared across nodes."""
        node1 = SimulatedNetworkDHT(b"node1", [])
        node2 = SimulatedNetworkDHT(b"node2", [])

        await node1.start()
        await node2.start()

        key = b"\x22" * 32
        value = b"shared_value"

        await node1.put_value(key, value)
        retrieved = await node2.get_value(key)

        assert retrieved == value

        await node1.stop()
        await node2.stop()

    @pytest.mark.asyncio
    async def test_reset_network_clears_all(self):
        """Reset network clears all state."""
        node = SimulatedNetworkDHT(b"node1", [])
        await node.start()

        await node.provide(b"\x00" * 32, [])
        await node.put_value(b"\x11" * 32, b"value")

        SimulatedNetworkDHT.reset_network()

        # State should be cleared
        assert len(SimulatedNetworkDHT._network_providers) == 0
        assert len(SimulatedNetworkDHT._network_values) == 0
        assert len(SimulatedNetworkDHT._nodes) == 0


# =============================================================================
# CollectionDiscovery Tests
# =============================================================================

class TestCollectionDiscovery:
    """Tests for CollectionDiscovery service."""

    @pytest.fixture
    def discovery(self):
        dht = LocalDHT()
        return CollectionDiscovery(
            dht=dht,
            node_id=b"test_node_id",
            config=DHTConfig(reannounce_interval=1)  # Short interval for testing
        )

    @pytest.mark.asyncio
    async def test_start_stop(self, discovery):
        """Discovery service can start and stop."""
        await discovery.start()
        assert discovery.dht._started is True

        await discovery.stop()
        assert discovery.dht._started is False

    @pytest.mark.asyncio
    async def test_announce_collection(self, discovery):
        """Announce collection adds provider record."""
        await discovery.start()

        result = await discovery.announce_collection(
            collection_id="test:collection",
            multiaddrs=["/ip4/127.0.0.1/tcp/4001"]
        )

        assert result is True
        assert "test:collection" in discovery._announced_collections

        await discovery.stop()

    @pytest.mark.asyncio
    async def test_announce_private_collection(self, discovery):
        """Announce private collection uses different key derivation."""
        await discovery.start()

        collection_key = b"\xaa" * 32
        result = await discovery.announce_collection(
            collection_id="private:collection",
            multiaddrs=["/ip4/127.0.0.1/tcp/4001"],
            collection_key=collection_key
        )

        assert result is True

        await discovery.stop()

    @pytest.mark.asyncio
    async def test_find_guardians(self, discovery):
        """Find guardians returns providers."""
        await discovery.start()

        # Announce first
        await discovery.announce_collection(
            collection_id="test:find",
            multiaddrs=["/ip4/127.0.0.1/tcp/4001"]
        )

        # Find
        guardians = await discovery.find_guardians("test:find")
        assert len(guardians) >= 1

        await discovery.stop()

    @pytest.mark.asyncio
    async def test_find_guardians_private(self, discovery):
        """Find guardians for private collection uses collection key."""
        await discovery.start()

        collection_key = b"\xbb" * 32

        await discovery.announce_collection(
            collection_id="private:find",
            multiaddrs=["/ip4/127.0.0.1/tcp/4001"],
            collection_key=collection_key
        )

        guardians = await discovery.find_guardians(
            "private:find",
            collection_key=collection_key
        )
        assert len(guardians) >= 1

        await discovery.stop()

    @pytest.mark.asyncio
    async def test_find_guardians_filters_expired(self, discovery):
        """Find guardians filters expired records."""
        await discovery.start()

        # Directly insert an expired record
        dht_key = derive_dht_key("test:expired")
        expired_record = ProviderRecord(
            node_id=b"expired_node",
            multiaddrs=["/ip4/1.2.3.4/tcp/4001"],
            collection_id="test:expired",
            timestamp=int(time.time()) - 200000,  # Very old
            ttl=3600
        )
        discovery.dht._providers[dht_key] = [expired_record]

        guardians = await discovery.find_guardians("test:expired")
        assert len(guardians) == 0  # Expired should be filtered

        await discovery.stop()


# =============================================================================
# PubSub Topic Derivation Tests
# =============================================================================

class TestPubsubTopicDerivation:
    """Tests for pubsub topic derivation functions."""

    def test_derive_pubsub_topic(self):
        """Pubsub topic has correct format."""
        topic = derive_pubsub_topic("test:collection")
        assert topic == "/dcpp/1.0/collection/test:collection"

    def test_derive_pubsub_topic_different_collections(self):
        """Different collections have different topics."""
        topic1 = derive_pubsub_topic("collection:a")
        topic2 = derive_pubsub_topic("collection:b")
        assert topic1 != topic2

    def test_derive_private_pubsub_topic(self):
        """Private pubsub topic uses collection key."""
        collection_key = b"\x00" * 32
        topic = derive_private_pubsub_topic(collection_key)

        assert topic.startswith("/dcpp/1.0/private/")
        # Should contain hex-encoded key hash
        assert len(topic) > len("/dcpp/1.0/private/")

    def test_derive_private_pubsub_topic_deterministic(self):
        """Private pubsub topic is deterministic."""
        collection_key = b"\x11" * 32
        topic1 = derive_private_pubsub_topic(collection_key)
        topic2 = derive_private_pubsub_topic(collection_key)
        assert topic1 == topic2

    def test_derive_private_pubsub_topic_different_keys(self):
        """Different keys produce different topics."""
        topic1 = derive_private_pubsub_topic(b"\x00" * 32)
        topic2 = derive_private_pubsub_topic(b"\x11" * 32)
        assert topic1 != topic2
