"""
DHT Compliance Tests for DCPP Wire Protocol

Tests for RFC Section 9 - Peer Discovery and DHT requirements.
"""

import asyncio
import os
import pytest

from dcpp_python.dht_real import (
    DHTCommand,
    DHTCommandType,
    DHTResponse,
    BootstrapConfig,
    KademliaDHT,
    process_dht_command,
    derive_dht_key,
    derive_private_dht_key,
    is_stub_mode,
)
from dcpp_python.dht import DHTConfig


class TestDHTKeyDerivation:
    """Tests for RFC Section 9.1 DHT key derivation."""

    def test_derive_dht_key_prefix(self):
        """RFC 9.1.1: DHT key uses 'dcpp/1.0:' prefix."""
        import hashlib

        collection_id = "my:collection"
        key = derive_dht_key(collection_id)

        expected = hashlib.sha256(b"dcpp/1.0:" + collection_id.encode()).digest()
        assert key == expected

    def test_derive_dht_key_32_bytes(self):
        """RFC 9.1.1: DHT key MUST be 32 bytes (sha256)."""
        key = derive_dht_key("test:collection")
        assert len(key) == 32

    def test_derive_private_dht_key_prefix(self):
        """RFC 9.2.2: Private DHT key uses 'dcpp/1.0/private:' prefix."""
        import hashlib

        collection_key = b"\xaa" * 32
        key = derive_private_dht_key(collection_key)

        expected = hashlib.sha256(b"dcpp/1.0/private:" + collection_key).digest()
        assert key == expected

    def test_derive_private_dht_key_32_bytes(self):
        """RFC 9.2.2: Private DHT key MUST be 32 bytes."""
        key = derive_private_dht_key(b"\x00" * 32)
        assert len(key) == 32

    def test_keys_unique_per_collection(self):
        """Different collections MUST produce different DHT keys."""
        key1 = derive_dht_key("collection:a")
        key2 = derive_dht_key("collection:b")
        key3 = derive_dht_key("collection:c")

        assert key1 != key2
        assert key2 != key3
        assert key1 != key3


class TestDHTCommandDataclass:
    """Tests for DHTCommand structure per RFC Section 9."""

    def test_provide_command(self):
        """Test PROVIDE command creation."""
        cmd = DHTCommand.provide(
            key=b"\x00" * 32,
            multiaddrs=["/ip4/127.0.0.1/tcp/4001"]
        )
        assert cmd.command_type == DHTCommandType.PROVIDE
        assert cmd.key == b"\x00" * 32
        assert cmd.multiaddrs == ["/ip4/127.0.0.1/tcp/4001"]
        assert cmd.response_queue is not None

    def test_find_providers_command(self):
        """Test FIND_PROVIDERS command creation."""
        cmd = DHTCommand.find_providers(key=b"\x11" * 32)
        assert cmd.command_type == DHTCommandType.FIND_PROVIDERS
        assert cmd.key == b"\x11" * 32

    def test_put_value_command(self):
        """Test PUT_VALUE command creation."""
        cmd = DHTCommand.put_value(key=b"\x22" * 32, value=b"test_value")
        assert cmd.command_type == DHTCommandType.PUT_VALUE
        assert cmd.key == b"\x22" * 32
        assert cmd.value == b"test_value"

    def test_get_value_command(self):
        """Test GET_VALUE command creation."""
        cmd = DHTCommand.get_value(key=b"\x33" * 32)
        assert cmd.command_type == DHTCommandType.GET_VALUE
        assert cmd.key == b"\x33" * 32

    def test_bootstrap_command_stores_peers(self):
        """RFC 9.3: Bootstrap command MUST store peers list."""
        peers = [
            (b"peer1_id", "/ip4/1.2.3.4/tcp/4001"),
            (b"peer2_id", "/ip4/5.6.7.8/tcp/4001"),
        ]
        cmd = DHTCommand.bootstrap(peers)
        assert cmd.command_type == DHTCommandType.BOOTSTRAP
        assert cmd.peers == peers
        assert len(cmd.peers) == 2


class TestDHTStubMode:
    """Tests for DCPP_STUB_MODE behavior per RFC requirements."""

    def test_stub_mode_env_check(self):
        """DCPP_STUB_MODE environment variable controls stub mode."""
        # Save original
        original = os.environ.get("DCPP_STUB_MODE")

        try:
            os.environ["DCPP_STUB_MODE"] = "1"
            assert is_stub_mode() is True

            os.environ["DCPP_STUB_MODE"] = "0"
            assert is_stub_mode() is False

            del os.environ["DCPP_STUB_MODE"]
            assert is_stub_mode() is False
        finally:
            if original:
                os.environ["DCPP_STUB_MODE"] = original
            elif "DCPP_STUB_MODE" in os.environ:
                del os.environ["DCPP_STUB_MODE"]

    def test_process_command_fails_without_kademlia_not_stub(self):
        """Without Kademlia and not in stub mode, commands MUST fail."""
        original = os.environ.get("DCPP_STUB_MODE")
        try:
            os.environ["DCPP_STUB_MODE"] = "0"

            cmd = DHTCommand.provide(b"\x00" * 32, ["/ip4/127.0.0.1/tcp/4001"])
            response = process_dht_command(cmd, kademlia=None)

            assert response.success is False
            assert "No Kademlia backend" in response.error
        finally:
            if original:
                os.environ["DCPP_STUB_MODE"] = original

    def test_process_command_succeeds_in_stub_mode(self):
        """In stub mode, commands succeed without real Kademlia."""
        original = os.environ.get("DCPP_STUB_MODE")
        try:
            os.environ["DCPP_STUB_MODE"] = "1"

            # Test PROVIDE
            cmd = DHTCommand.provide(b"\x00" * 32, ["/ip4/127.0.0.1/tcp/4001"])
            response = process_dht_command(cmd, kademlia=None)
            assert response.success is True

            # Test FIND_PROVIDERS
            cmd = DHTCommand.find_providers(b"\x00" * 32)
            response = process_dht_command(cmd, kademlia=None)
            assert response.success is True
            assert response.data == []

            # Test PUT_VALUE
            cmd = DHTCommand.put_value(b"\x00" * 32, b"value")
            response = process_dht_command(cmd, kademlia=None)
            assert response.success is True

            # Test GET_VALUE
            cmd = DHTCommand.get_value(b"\x00" * 32)
            response = process_dht_command(cmd, kademlia=None)
            assert response.success is True

            # Test BOOTSTRAP
            cmd = DHTCommand.bootstrap([(b"peer", "/ip4/1.2.3.4/tcp/4001")])
            response = process_dht_command(cmd, kademlia=None)
            assert response.success is True

        finally:
            if original:
                os.environ["DCPP_STUB_MODE"] = original

    def test_process_unknown_command_fails(self):
        """Unknown command types MUST fail."""
        original = os.environ.get("DCPP_STUB_MODE")
        try:
            os.environ["DCPP_STUB_MODE"] = "1"

            # Create command with invalid type (simulate)
            cmd = DHTCommand(
                command_type=999,  # Invalid type
                key=b"\x00" * 32
            )
            response = process_dht_command(cmd, kademlia=None)
            assert response.success is False
            assert "Unknown command type" in response.error
        finally:
            if original:
                os.environ["DCPP_STUB_MODE"] = original


class TestBootstrapConfig:
    """Tests for BootstrapConfig per RFC Section 9.3."""

    def test_default_dns_discovery(self):
        """RFC 9.3: Default DNS discovery domain."""
        config = BootstrapConfig()
        assert config.dns_discovery == "_dcpp-bootstrap.dcpp.network"

    def test_default_ipns_fallback(self):
        """RFC 9.3: IPNS fallback should be configured."""
        config = BootstrapConfig()
        assert config.ipns_fallback == "/ipns/bootstrap.dcpp.network"

    def test_static_peers_priority(self):
        """RFC 9.3: Static peers should be included first."""
        config = BootstrapConfig(
            static_peers=[
                (b"peer1", "/ip4/1.2.3.4/tcp/4001"),
                (b"peer2", "/ip4/5.6.7.8/tcp/4001"),
            ]
        )
        assert len(config.static_peers) == 2

    @pytest.mark.asyncio
    async def test_discover_peers_includes_static(self):
        """discover_peers MUST include static peers."""
        config = BootstrapConfig(
            static_peers=[
                (b"peer1", "/ip4/1.2.3.4/tcp/4001"),
            ],
            dns_discovery="",  # Disable DNS
            ipns_fallback="",  # Disable IPNS
        )
        peers = await config.discover_peers()
        assert len(peers) == 1
        assert peers[0] == (b"peer1", "/ip4/1.2.3.4/tcp/4001")

    def test_ipfs_gateways_configured(self):
        """IPNS resolution should have fallback gateways."""
        config = BootstrapConfig()
        assert len(config.ipfs_gateways) >= 1
        assert any("ipfs.io" in gw for gw in config.ipfs_gateways)


class TestKademliaDHT:
    """Tests for KademliaDHT class."""

    @pytest.mark.asyncio
    async def test_dht_start_stop(self):
        """DHT can be started and stopped."""
        config = DHTConfig()
        dht = KademliaDHT(config)

        await dht.start()
        assert dht._started is True

        await dht.stop()
        assert dht._started is False

    @pytest.mark.asyncio
    async def test_dht_local_cache_provide(self):
        """DHT stores providers in local cache."""
        config = DHTConfig()
        dht = KademliaDHT(config)
        await dht.start()

        key = b"\x00" * 32
        success = await dht.provide(key, ["/ip4/127.0.0.1/tcp/4001"])

        assert success is True
        assert key in dht._local_providers

        await dht.stop()

    @pytest.mark.asyncio
    async def test_dht_local_cache_find_providers(self):
        """DHT retrieves from local cache."""
        config = DHTConfig()
        dht = KademliaDHT(config)
        await dht.start()

        key = b"\x11" * 32
        await dht.provide(key, ["/ip4/127.0.0.1/tcp/4001"])

        providers = await dht.find_providers(key)
        assert len(providers) >= 1

        await dht.stop()

    @pytest.mark.asyncio
    async def test_dht_local_cache_put_get_value(self):
        """DHT stores and retrieves values from local cache."""
        config = DHTConfig()
        dht = KademliaDHT(config)
        await dht.start()

        key = b"\x22" * 32
        value = b"test_value_data"

        await dht.put_value(key, value)
        retrieved = await dht.get_value(key)

        assert retrieved == value

        await dht.stop()

    @pytest.mark.asyncio
    async def test_dht_operations_fail_when_not_started(self):
        """DHT operations should handle not-started state."""
        config = DHTConfig()
        dht = KademliaDHT(config)

        # Not started
        success = await dht.provide(b"\x00" * 32, [])
        assert success is False

        providers = await dht.find_providers(b"\x00" * 32)
        assert providers == []

        value = await dht.get_value(b"\x00" * 32)
        assert value is None

    @pytest.mark.asyncio
    async def test_dht_set_local_identity(self):
        """DHT accepts local identity configuration."""
        config = DHTConfig()
        dht = KademliaDHT(config)

        node_id = b"test_node_id"
        multiaddrs = ["/ip4/127.0.0.1/tcp/4001"]

        dht.set_local_identity(node_id, multiaddrs)

        assert dht._local_node_id == node_id
        assert dht._local_multiaddrs == multiaddrs
