"""
Tests for Real Kademlia DHT Implementation
"""

import asyncio
import pytest
from dcpp_python.dht import DHTConfig, ProviderRecord
from dcpp_python.dht_real import (
    KademliaDHT,
    DHTCommand,
    DHTCommandType,
    DHTResponse,
    BootstrapConfig,
    derive_dht_key,
    derive_private_dht_key,
)


class TestDHTCommand:
    """Tests for DHT command creation."""

    def test_create_provide_command(self):
        key = b"\x00" * 32
        addrs = ["/ip4/127.0.0.1/tcp/4001"]
        cmd = DHTCommand.provide(key, addrs)

        assert cmd.command_type == DHTCommandType.PROVIDE
        assert cmd.key == key
        assert cmd.multiaddrs == addrs
        assert cmd.response_queue is not None

    def test_create_find_providers_command(self):
        key = b"\x00" * 32
        cmd = DHTCommand.find_providers(key)

        assert cmd.command_type == DHTCommandType.FIND_PROVIDERS
        assert cmd.key == key
        assert cmd.response_queue is not None

    def test_create_put_value_command(self):
        key = b"\x00" * 32
        value = b"test value"
        cmd = DHTCommand.put_value(key, value)

        assert cmd.command_type == DHTCommandType.PUT_VALUE
        assert cmd.key == key
        assert cmd.value == value
        assert cmd.response_queue is not None

    def test_create_get_value_command(self):
        key = b"\x00" * 32
        cmd = DHTCommand.get_value(key)

        assert cmd.command_type == DHTCommandType.GET_VALUE
        assert cmd.key == key
        assert cmd.response_queue is not None

    def test_create_bootstrap_command(self):
        peers = [(b"peer1", "/ip4/1.2.3.4/tcp/4001")]
        cmd = DHTCommand.bootstrap(peers)

        assert cmd.command_type == DHTCommandType.BOOTSTRAP
        assert cmd.response_queue is not None


class TestDHTResponse:
    """Tests for DHT response handling."""

    def test_success_response(self):
        response = DHTResponse(success=True, data=["provider1"])
        assert response.success is True
        assert response.data == ["provider1"]
        assert response.error is None

    def test_error_response(self):
        response = DHTResponse(success=False, error="Connection failed")
        assert response.success is False
        assert response.error == "Connection failed"


class TestBootstrapConfig:
    """Tests for bootstrap configuration."""

    def test_default_config(self):
        config = BootstrapConfig()
        assert config.static_peers == []
        assert config.dns_discovery == "_dcpp-bootstrap.dcpp.network"
        assert config.mdns_enabled is True

    def test_static_peers(self):
        peers = [
            (b"peer1", "/ip4/1.2.3.4/tcp/4001"),
            (b"peer2", "/ip4/5.6.7.8/tcp/4001"),
        ]
        config = BootstrapConfig(static_peers=peers)
        assert config.static_peers == peers

    @pytest.mark.asyncio
    async def test_discover_peers_static_only(self):
        peers = [(b"peer1", "/ip4/1.2.3.4/tcp/4001")]
        config = BootstrapConfig(
            static_peers=peers,
            dns_discovery="",  # Disable DNS
        )

        discovered = await config.discover_peers()
        assert discovered == peers

    @pytest.mark.asyncio
    async def test_discover_peers_dns_timeout(self):
        config = BootstrapConfig(
            static_peers=[],
            dns_discovery="nonexistent.invalid.domain.test",
            dns_timeout=0.1,  # Very short timeout
        )

        # Should not raise, just return empty list
        discovered = await config.discover_peers()
        assert isinstance(discovered, list)


class TestKademliaDHT:
    """Tests for KademliaDHT class."""

    @pytest.fixture
    def config(self):
        return DHTConfig(
            reannounce_interval=60,
            provider_ttl=3600,
            query_timeout=5.0,
        )

    @pytest.fixture
    def dht(self, config):
        return KademliaDHT(config)

    @pytest.mark.asyncio
    async def test_start_stop(self, dht):
        await dht.start()
        assert dht._started is True

        await dht.stop()
        assert dht._started is False

    @pytest.mark.asyncio
    async def test_provide_not_started(self, dht):
        key = b"\x00" * 32
        result = await dht.provide(key, [])
        assert result is False

    @pytest.mark.asyncio
    async def test_provide_local_cache(self, dht):
        await dht.start()
        dht.set_local_identity(b"node1", ["/ip4/127.0.0.1/tcp/4001"])

        key = b"\x00" * 32
        addrs = ["/ip4/127.0.0.1/tcp/4001"]

        result = await dht.provide(key, addrs)
        assert result is True

        # Should be in local cache
        assert key in dht._local_providers

        await dht.stop()

    @pytest.mark.asyncio
    async def test_find_providers_local_cache(self, dht):
        await dht.start()
        dht.set_local_identity(b"node1", ["/ip4/127.0.0.1/tcp/4001"])

        key = b"\x00" * 32
        addrs = ["/ip4/127.0.0.1/tcp/4001"]

        # Provide first
        await dht.provide(key, addrs)

        # Then find
        providers = await dht.find_providers(key)
        assert len(providers) >= 1

        await dht.stop()

    @pytest.mark.asyncio
    async def test_put_get_value_local_cache(self, dht):
        await dht.start()

        key = b"\x01" * 32
        value = b"test value data"

        # Put value
        result = await dht.put_value(key, value)
        assert result is True

        # Get value
        retrieved = await dht.get_value(key)
        assert retrieved == value

        await dht.stop()

    @pytest.mark.asyncio
    async def test_get_value_not_found(self, dht):
        await dht.start()

        key = b"\x99" * 32
        result = await dht.get_value(key)
        assert result is None

        await dht.stop()

    @pytest.mark.asyncio
    async def test_find_providers_not_found(self, dht):
        await dht.start()

        key = b"\x99" * 32
        providers = await dht.find_providers(key)
        assert providers == []

        await dht.stop()

    @pytest.mark.asyncio
    async def test_command_queue(self, config):
        queue = asyncio.Queue()
        dht = KademliaDHT(config, command_queue=queue)

        assert dht.command_queue is queue

    @pytest.mark.asyncio
    async def test_set_local_identity(self, dht):
        node_id = b"test_node"
        addrs = ["/ip4/1.2.3.4/tcp/4001"]

        dht.set_local_identity(node_id, addrs)

        assert dht._local_node_id == node_id
        assert dht._local_multiaddrs == addrs


class TestDHTKeyDerivation:
    """Tests for DHT key derivation functions."""

    def test_derive_dht_key(self):
        collection_id = "eth:0xBC4CA0"
        key = derive_dht_key(collection_id)

        assert len(key) == 32
        # Same input should give same output
        assert derive_dht_key(collection_id) == key
        # Different input should give different output
        assert derive_dht_key("eth:0xABC123") != key

    def test_derive_private_dht_key(self):
        collection_key = b"\x00" * 32
        key = derive_private_dht_key(collection_key)

        assert len(key) == 32
        # Same input should give same output
        assert derive_private_dht_key(collection_key) == key
        # Different input should give different output
        assert derive_private_dht_key(b"\x01" * 32) != key

    def test_public_private_keys_differ(self):
        # Even with related inputs, public and private keys should differ
        collection_id = "test"
        public_key = derive_dht_key(collection_id)

        collection_key = collection_id.encode("utf-8").ljust(32, b"\x00")
        private_key = derive_private_dht_key(collection_key)

        assert public_key != private_key


class TestProviderRecordExpiry:
    """Tests for provider record expiry handling."""

    @pytest.mark.asyncio
    async def test_expired_records_filtered(self):
        config = DHTConfig(provider_ttl=1)  # 1 second TTL
        dht = KademliaDHT(config)
        await dht.start()

        key = b"\x00" * 32
        dht.set_local_identity(b"node1", ["/ip4/127.0.0.1/tcp/4001"])

        # Provide with short TTL
        await dht.provide(key, ["/ip4/127.0.0.1/tcp/4001"])

        # Manually set record timestamp to past
        if key in dht._local_providers:
            for record in dht._local_providers[key]:
                record.timestamp = 0  # Very old

        # Find should filter expired records
        providers = await dht.find_providers(key)
        assert len(providers) == 0

        await dht.stop()


class TestDHTIntegration:
    """Integration tests for DHT with multiple nodes."""

    @pytest.mark.asyncio
    async def test_two_node_discovery(self):
        config = DHTConfig()

        dht1 = KademliaDHT(config)
        dht2 = KademliaDHT(config)

        await dht1.start()
        await dht2.start()

        dht1.set_local_identity(b"node1" + b"\x00" * 27, ["/ip4/1.2.3.4/tcp/4001"])
        dht2.set_local_identity(b"node2" + b"\x00" * 27, ["/ip4/5.6.7.8/tcp/4001"])

        # Node 1 provides a key
        key = derive_dht_key("eth:0xBC4CA0")
        await dht1.provide(key, ["/ip4/1.2.3.4/tcp/4001"])

        # In real DHT, node 2 would find node 1
        # Here we just verify the local behavior works
        providers = await dht1.find_providers(key)
        assert len(providers) == 1

        await dht1.stop()
        await dht2.stop()
