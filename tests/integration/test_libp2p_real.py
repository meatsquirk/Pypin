"""
Tests for Real libp2p Host Implementation

Note: These tests use mocks since the actual libp2p library may not be installed.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Import types that are always available
from dcpp_python.libp2p_real import (
    HostEvent,
    HostEventData,
    DCPPRequest,
    DCPPResponse,
    RealHostConfig,
    DCPP_PROTOCOL_ID,
    read_framed_message,
    RealHost,
)
from dcpp_python.framing import Profile1Framer
from dcpp_python.messages import MessageType
from dcpp_python.dht_real import DHTCommand


class TestHostEventData:
    """Tests for HostEventData."""

    def test_peer_connected_event(self):
        event = HostEventData(
            event_type=HostEvent.PEER_CONNECTED,
            peer_id=b"test_peer",
        )
        assert event.event_type == HostEvent.PEER_CONNECTED
        assert event.peer_id == b"test_peer"

    def test_dcpp_request_event(self):
        from dcpp_python.messages import MessageType
        event = HostEventData(
            event_type=HostEvent.DCPP_REQUEST,
            peer_id=b"peer1",
            message_type=MessageType.HELLO,
            payload=b"test_payload",
        )
        assert event.event_type == HostEvent.DCPP_REQUEST
        assert event.message_type == MessageType.HELLO
        assert event.payload == b"test_payload"

    def test_gossip_message_event(self):
        event = HostEventData(
            event_type=HostEvent.GOSSIP_MESSAGE,
            peer_id=b"peer1",
            topic="/dcpp/1.0/collection/test",
            data=b"message_data",
        )
        assert event.event_type == HostEvent.GOSSIP_MESSAGE
        assert event.topic == "/dcpp/1.0/collection/test"

    def test_dht_providers_found_event(self):
        event = HostEventData(
            event_type=HostEvent.DHT_PROVIDERS_FOUND,
            key=b"dht_key",
        )
        assert event.event_type == HostEvent.DHT_PROVIDERS_FOUND
        assert event.key == b"dht_key"


class TestDCPPRequest:
    """Tests for DCPPRequest."""

    def test_create_request(self):
        from dcpp_python.messages import MessageType
        request = DCPPRequest(
            message_type=MessageType.GET_PEERS,
            payload=b"payload",
        )
        assert request.message_type == MessageType.GET_PEERS
        assert request.payload == b"payload"


class TestDCPPResponse:
    """Tests for DCPPResponse."""

    def test_create_response(self):
        from dcpp_python.messages import MessageType
        response = DCPPResponse(
            message_type=MessageType.PEERS,
            payload=b"response_payload",
        )
        assert response.message_type == MessageType.PEERS
        assert response.payload == b"response_payload"


class TestRealHostConfig:
    """Tests for RealHostConfig."""

    def test_default_config(self):
        config = RealHostConfig()
        assert config.listen_addrs == ["/ip4/0.0.0.0/tcp/4001"]
        assert config.bootstrap_peers == []
        assert config.enable_dht is True
        assert config.enable_gossipsub is True

    def test_custom_config(self):
        peers = [(b"peer1", "/ip4/1.2.3.4/tcp/4001")]
        config = RealHostConfig(
            listen_addrs=["/ip4/127.0.0.1/tcp/5001"],
            bootstrap_peers=peers,
            dht_server_mode=True,
            enable_dht=False,
        )
        assert config.listen_addrs == ["/ip4/127.0.0.1/tcp/5001"]
        assert config.bootstrap_peers == peers
        assert config.dht_server_mode is True
        assert config.enable_dht is False

    def test_dht_config_options(self):
        config = RealHostConfig(
            dht_reannounce_interval=7200,
            dht_provider_ttl=43200,
        )
        assert config.dht_reannounce_interval == 7200
        assert config.dht_provider_ttl == 43200

    def test_gossipsub_config_options(self):
        config = RealHostConfig(
            gossipsub_heartbeat_interval=0.5,
            gossipsub_message_cache_ttl=60,
        )
        assert config.gossipsub_heartbeat_interval == 0.5
        assert config.gossipsub_message_cache_ttl == 60


class _FakeStream:
    def __init__(self, chunks, delay: float = 0.0):
        self._chunks = list(chunks)
        self._delay = delay

    async def read(self, n: int) -> bytes:
        if self._delay:
            await asyncio.sleep(self._delay)
        if not self._chunks:
            return b""
        chunk = self._chunks.pop(0)
        if len(chunk) > n:
            self._chunks.insert(0, chunk[n:])
            return chunk[:n]
        return chunk


class TestReadFramedMessage:
    @pytest.mark.asyncio
    async def test_read_framed_message_success(self, monkeypatch):
        monkeypatch.setenv("DCPP_STREAM_READ_TIMEOUT", "1")
        payload = b"hello"
        frame = Profile1Framer.encode(MessageType.HELLO, payload, request_id=123)
        chunks = [frame[:3], frame[3:10], frame[10:25], frame[25:]]
        stream = _FakeStream(chunks)

        data = await read_framed_message(stream)

        assert data == frame

    @pytest.mark.asyncio
    async def test_read_framed_message_timeout(self, monkeypatch):
        monkeypatch.setenv("DCPP_STREAM_READ_TIMEOUT", "0.01")
        payload = b"hello"
        frame = Profile1Framer.encode(MessageType.HELLO, payload, request_id=123)
        stream = _FakeStream([frame], delay=0.1)

        with pytest.raises(TimeoutError):
            await read_framed_message(stream)


class _FakeKadDHT:
    def __init__(self):
        self.added = []
        self.bootstraps = 0

    def add_address(self, peer_id, addr):
        self.added.append((peer_id, addr))

    def bootstrap(self):
        self.bootstraps += 1


class TestDhtBootstrapWiring:
    @pytest.mark.asyncio
    async def test_bootstrap_seeds_routing_table(self, monkeypatch):
        import types
        import dcpp_python.libp2p_real as libp2p_real

        monkeypatch.setattr(libp2p_real, "PeerID", lambda b: b, raising=False)
        monkeypatch.setattr(
            libp2p_real,
            "multiaddr",
            types.SimpleNamespace(Multiaddr=lambda addr: addr),
            raising=False,
        )

        host = RealHost.__new__(RealHost)
        host._trio_token = None
        host._libp2p_kad_dht = _FakeKadDHT()

        command = DHTCommand.bootstrap([(b"peer", "/ip4/1.2.3.4/tcp/4001")])
        response = await host._process_dht_command_with_real_kad(command)

        assert response.success is True
        assert host._libp2p_kad_dht.bootstraps == 1
        assert len(host._libp2p_kad_dht.added) == 1


class TestHostEvents:
    """Tests for HostEvent enum."""

    def test_all_events_defined(self):
        events = [
            HostEvent.PEER_CONNECTED,
            HostEvent.PEER_DISCONNECTED,
            HostEvent.DCPP_REQUEST,
            HostEvent.DCPP_RESPONSE,
            HostEvent.DCPP_REQUEST_FAILED,
            HostEvent.PROVIDER_FOUND,
            HostEvent.DHT_PROVIDERS_FOUND,
            HostEvent.GOSSIP_MESSAGE,
            HostEvent.GOSSIP_SUBSCRIBED,
        ]
        assert len(events) == 9


class TestProtocolID:
    """Tests for protocol constants."""

    def test_dcpp_protocol_id(self):
        assert DCPP_PROTOCOL_ID == "/dcpp/1.0.0"


# Mock-based tests for when libp2p is not available
class TestRealHostMocked:
    """Tests for RealHost using mocks."""

    @pytest.fixture
    def mock_libp2p(self):
        """Mock the libp2p imports."""
        with patch.dict('sys.modules', {
            'libp2p': MagicMock(),
            'libp2p.crypto.secp256k1': MagicMock(),
            'libp2p.crypto.ed25519': MagicMock(),
            'libp2p.network.stream.net_stream_interface': MagicMock(),
            'libp2p.peer.id': MagicMock(),
            'libp2p.peer.peerinfo': MagicMock(),
            'libp2p.typing': MagicMock(),
            'multiaddr': MagicMock(),
        }):
            yield

    def test_config_without_libp2p(self):
        """Config can be created without libp2p."""
        config = RealHostConfig()
        assert config is not None

    @pytest.mark.asyncio
    async def test_start_uses_dedicated_x25519_noise_key_when_supported(self, monkeypatch):
        """RealHost.start should wire a dedicated X25519 key into NoiseTransport."""
        import types
        import dcpp_python.network.libp2p.real as libp2p_real

        captured = {}

        class FakeNoiseTransport:
            def __init__(self, libp2p_keypair, noise_privkey):
                captured["libp2p_keypair"] = libp2p_keypair
                captured["noise_privkey"] = noise_privkey

        class FakeHost:
            def get_id(self):
                return types.SimpleNamespace(to_bytes=lambda: b"peer-id")

            def set_stream_handler(self, protocol_id, handler):
                captured["protocol_id"] = protocol_id
                captured["handler"] = handler

        class FakeThread:
            def __init__(self, target, name, daemon):
                self._target = target

            def start(self):
                host._host_ready.set()

        def fake_new_host(*, key_pair, sec_opt, muxer_preference):
            captured["sec_opt"] = sec_opt
            captured["muxer_preference"] = muxer_preference
            return FakeHost()

        fake_noise_private_key = object()

        monkeypatch.setattr(libp2p_real, "NoiseTransport", FakeNoiseTransport)
        monkeypatch.setattr(
            libp2p_real,
            "create_new_x25519_key_pair",
            lambda: types.SimpleNamespace(private_key=fake_noise_private_key),
        )
        monkeypatch.setattr(libp2p_real, "new_host", fake_new_host)
        monkeypatch.setattr(
            libp2p_real,
            "multiaddr",
            types.SimpleNamespace(Multiaddr=lambda addr: addr),
            raising=False,
        )
        monkeypatch.setattr(libp2p_real.threading, "Thread", FakeThread)

        config = libp2p_real.RealHostConfig(enable_dht=False, enable_gossipsub=False)
        host = libp2p_real.RealHost(config)

        await host.start()

        assert captured["muxer_preference"] == "YAMUX"
        assert captured["noise_privkey"] is fake_noise_private_key
        assert list(captured["sec_opt"].keys()) == [libp2p_real.NOISE_PROTOCOL_ID]


class TestDCPPRealNodeMocked:
    """Tests for DCPPRealNode functionality."""

    def test_collection_topic_format(self):
        """Test that collection topics follow correct format."""
        collection_id = "eth:0xBC4CA0"
        expected_topic = f"/dcpp/1.0/collection/{collection_id}"

        # Verify topic format
        assert expected_topic == "/dcpp/1.0/collection/eth:0xBC4CA0"

    def test_dht_key_derivation(self):
        """Test DHT key derivation for collections."""
        from dcpp_python.dht_real import derive_dht_key

        collection_id = "eth:0xBC4CA0"
        key = derive_dht_key(collection_id)

        assert len(key) == 32
        # Same input should give same output
        assert derive_dht_key(collection_id) == key


class TestIntegrationWithDHT:
    """Integration tests with KademliaDHT."""

    @pytest.fixture
    def dht(self):
        from dcpp_python.dht import DHTConfig
        from dcpp_python.dht_real import KademliaDHT, BootstrapConfig

        config = DHTConfig()
        return KademliaDHT(config)

    @pytest.mark.asyncio
    async def test_dht_provide_find(self, dht):
        """Test DHT provide and find operations."""
        await dht.start()

        key = b"\x00" * 32
        dht.set_local_identity(b"node1", ["/ip4/127.0.0.1/tcp/4001"])

        # Provide
        success = await dht.provide(key, ["/ip4/127.0.0.1/tcp/4001"])
        assert success is True

        # Find
        providers = await dht.find_providers(key)
        assert len(providers) >= 1

        await dht.stop()


class TestGossipSubFunctionality:
    """Tests for GossipSub-related functionality."""

    def test_event_data_with_topic(self):
        """Test event data carries topic information."""
        event = HostEventData(
            event_type=HostEvent.GOSSIP_MESSAGE,
            topic="/dcpp/1.0/collection/test",
            data=b"announcement",
            peer_id=b"sender",
        )

        assert event.topic == "/dcpp/1.0/collection/test"
        assert event.data == b"announcement"

    def test_subscribed_event(self):
        """Test subscription event."""
        event = HostEventData(
            event_type=HostEvent.GOSSIP_SUBSCRIBED,
            topic="/dcpp/1.0/collection/eth:0xABC",
        )

        assert event.event_type == HostEvent.GOSSIP_SUBSCRIBED
        assert "eth:0xABC" in event.topic
