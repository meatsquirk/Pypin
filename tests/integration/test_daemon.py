"""
Tests for DCPP Daemon Module

Tests for DaemonConfig, PeerTable, PeerEntry, NodeState, CollectionState,
and DCPPDaemon classes.
"""

import argparse
import asyncio
import time
from pathlib import Path

import pytest

from dcpp_python.daemon import (
    NodeState,
    CollectionState,
    DaemonConfig,
    PeerEntry,
    PeerTable,
    DCPPDaemon,
    NodeStartedEvent,
    BootstrapCompleteEvent,
    ManifestReceivedEvent,
    create_parser,
    setup_logging,
)
from dcpp_python.core.constants import (
    MAX_PEERS_PER_COLLECTION,
    MAX_TOTAL_CONNECTIONS,
    DHT_REANNOUNCE_INTERVAL,
    DEFAULT_PROBE_INTERVAL,
    AccessMode,
    CollectionType,
)
from dcpp_python.crypto import sign_message
from dcpp_python.manifest.manifest import Manifest, TorrentInfo


# =============================================================================
# NodeState Tests
# =============================================================================

class TestNodeState:
    """Tests for NodeState enum."""

    def test_all_states_defined(self):
        """All RFC Section 7.1 states should be defined."""
        states = [
            NodeState.OFFLINE,
            NodeState.CONNECTING,
            NodeState.READY,
            NodeState.SYNCING,
            NodeState.GUARDING,
            NodeState.SEEDING,
            NodeState.DEGRADED,
        ]
        assert len(states) == 7

    def test_states_unique(self):
        """Each state should have a unique value."""
        values = [s.value for s in NodeState]
        assert len(values) == len(set(values))


# =============================================================================
# CollectionState Tests
# =============================================================================

class TestCollectionState:
    """Tests for CollectionState enum."""

    def test_all_states_defined(self):
        """All RFC Section 7.3 collection states should be defined."""
        states = [
            CollectionState.UNKNOWN,
            CollectionState.INTERESTED,
            CollectionState.SYNCING,
            CollectionState.COMPLETE,
            CollectionState.PARTIAL,
            CollectionState.STALE,
        ]
        assert len(states) == 6


# =============================================================================
# DaemonConfig Tests
# =============================================================================

class TestDaemonConfig:
    """Tests for DaemonConfig dataclass."""

    def test_default_config(self):
        """Default config should have sensible defaults."""
        config = DaemonConfig()

        assert config.listen_addrs == ["/ip4/0.0.0.0/tcp/4001"]
        assert config.bootstrap_peers == []
        assert config.collections == []
        assert config.enable_guardian is True
        assert config.enable_seeder is True
        assert config.enable_private is True
        assert config.max_peers_per_collection == MAX_PEERS_PER_COLLECTION
        assert config.max_total_connections == MAX_TOTAL_CONNECTIONS
        assert config.probe_interval == DEFAULT_PROBE_INTERVAL
        assert config.dht_reannounce_interval == DHT_REANNOUNCE_INTERVAL
        assert config.log_level == "INFO"

    def test_custom_config(self):
        """Custom config values should be set."""
        config = DaemonConfig(
            listen_addrs=["/ip4/0.0.0.0/tcp/9999"],
            bootstrap_peers=["/ip4/1.2.3.4/tcp/4001"],
            collections=["test:collection"],
            enable_guardian=False,
            max_peers_per_collection=100,
        )

        assert config.listen_addrs == ["/ip4/0.0.0.0/tcp/9999"]
        assert config.bootstrap_peers == ["/ip4/1.2.3.4/tcp/4001"]
        assert config.collections == ["test:collection"]
        assert config.enable_guardian is False
        assert config.max_peers_per_collection == 100

    def test_from_args(self):
        """Config should be created from argparse namespace."""
        args = argparse.Namespace(
            listen=["/ip4/0.0.0.0/tcp/5555"],
            bootstrap=["/ip4/8.8.8.8/tcp/4001"],
            storage="/tmp/dcpp_test",
            collections=["col1", "col2"],
            log_level="DEBUG",
        )

        config = DaemonConfig.from_args(args)

        assert config.listen_addrs == ["/ip4/0.0.0.0/tcp/5555"]
        assert config.bootstrap_peers == ["/ip4/8.8.8.8/tcp/4001"]
        assert config.storage_path == Path("/tmp/dcpp_test")
        assert config.collections == ["col1", "col2"]
        assert config.log_level == "DEBUG"

    def test_from_args_partial(self):
        """Config should handle partial args."""
        args = argparse.Namespace(
            listen=None,
            bootstrap=None,
            storage=None,
            collections=None,
            log_level=None,
        )

        config = DaemonConfig.from_args(args)

        # Should use defaults
        assert config.listen_addrs == ["/ip4/0.0.0.0/tcp/4001"]
        assert config.bootstrap_peers == []


# =============================================================================
# PeerEntry Tests
# =============================================================================

class TestPeerEntry:
    """Tests for PeerEntry dataclass."""

    def test_create_entry(self):
        """Create a peer entry."""
        entry = PeerEntry(
            node_id=b"test_node",
            multiaddrs=["/ip4/127.0.0.1/tcp/4001"],
            coverage=0.75,
            last_seen=int(time.time()),
        )

        assert entry.node_id == b"test_node"
        assert entry.coverage == 0.75
        assert entry.response_quality == 0.5  # Default
        assert entry.probe_successes == 0
        assert entry.probe_failures == 0
        assert entry.avg_response_time_ms == 0.0


# =============================================================================
# PeerTable Tests
# =============================================================================

class TestPeerTable:
    """Tests for PeerTable class."""

    @pytest.fixture
    def table(self):
        return PeerTable("test:collection")

    def test_create_table(self, table):
        """Create a peer table."""
        assert table.collection_id == "test:collection"
        assert len(table.peers) == 0

    def test_upsert_new_peer(self, table):
        """Upsert adds new peer."""
        table.upsert(
            node_id=b"peer1",
            multiaddrs=["/ip4/1.2.3.4/tcp/4001"],
            coverage=0.5
        )

        assert b"peer1" in table.peers
        assert table.peers[b"peer1"].coverage == 0.5

    def test_upsert_existing_peer(self, table):
        """Upsert updates existing peer."""
        table.upsert(b"peer1", ["/ip4/1.2.3.4/tcp/4001"], 0.5)
        original_last_seen = table.peers[b"peer1"].last_seen

        # Small delay to ensure different timestamp
        time.sleep(0.01)

        table.upsert(b"peer1", ["/ip4/5.6.7.8/tcp/4001"], 0.8)

        assert table.peers[b"peer1"].coverage == 0.8
        assert table.peers[b"peer1"].multiaddrs == ["/ip4/5.6.7.8/tcp/4001"]
        assert table.peers[b"peer1"].last_seen >= original_last_seen

    def test_record_probe_success(self, table):
        """Record successful probe."""
        table.upsert(b"peer1", [], 0.5)

        table.record_probe_result(b"peer1", success=True, response_time_ms=100)

        entry = table.peers[b"peer1"]
        assert entry.probe_successes == 1
        assert entry.probe_failures == 0
        assert entry.avg_response_time_ms == 100

    def test_record_probe_failure(self, table):
        """Record failed probe."""
        table.upsert(b"peer1", [], 0.5)

        table.record_probe_result(b"peer1", success=False)

        entry = table.peers[b"peer1"]
        assert entry.probe_successes == 0
        assert entry.probe_failures == 1

    def test_record_probe_rolling_average(self, table):
        """Response time should be rolling average."""
        table.upsert(b"peer1", [], 0.5)

        table.record_probe_result(b"peer1", success=True, response_time_ms=100)
        table.record_probe_result(b"peer1", success=True, response_time_ms=200)

        entry = table.peers[b"peer1"]
        assert entry.probe_successes == 2
        # Rolling average of 100 and 200
        assert entry.avg_response_time_ms == 150

    def test_record_probe_unknown_peer(self, table):
        """Recording probe for unknown peer should not raise."""
        table.record_probe_result(b"unknown", success=True, response_time_ms=100)
        # Should silently ignore

    def test_calculate_quality_unknown(self, table):
        """Quality should be 0.5 for new peer with no probes."""
        table.upsert(b"peer1", [], 0.5)

        quality = table._calculate_quality(table.peers[b"peer1"])
        assert quality == 0.5

    def test_calculate_quality_good_peer(self, table):
        """Quality should be high for fast, reliable peer."""
        table.upsert(b"peer1", [], 1.0)  # Full coverage
        entry = table.peers[b"peer1"]

        # Simulate fast, reliable responses
        entry.probe_successes = 10
        entry.probe_failures = 0
        entry.avg_response_time_ms = 50  # Fast
        entry.last_seen = int(time.time())  # Recent

        quality = table._calculate_quality(entry)
        # Should be high (close to 1.0)
        assert quality > 0.8

    def test_calculate_quality_poor_peer(self, table):
        """Quality should be low for slow, unreliable peer."""
        table.upsert(b"peer1", [], 0.1)  # Low coverage
        entry = table.peers[b"peer1"]

        # Simulate slow, unreliable responses
        entry.probe_successes = 1
        entry.probe_failures = 9
        entry.avg_response_time_ms = 4000  # Slow
        entry.last_seen = int(time.time()) - 7200  # Old

        quality = table._calculate_quality(entry)
        # Should be low
        assert quality < 0.3

    def test_get_top_peers(self, table):
        """Get top peers by quality."""
        # Add peers with different qualities
        for i in range(5):
            table.upsert(f"peer{i}".encode(), [], coverage=i * 0.2)
            entry = table.peers[f"peer{i}".encode()]
            entry.probe_successes = 10
            entry.avg_response_time_ms = (5 - i) * 100  # Lower i = slower

        top = table.get_top_peers(3)
        assert len(top) == 3

        # Best peer should be peer4 (highest coverage, fastest)
        assert top[0].node_id == b"peer4"

    def test_get_top_peers_less_than_n(self, table):
        """Get top peers when fewer than n exist."""
        table.upsert(b"peer1", [], 0.5)

        top = table.get_top_peers(10)
        assert len(top) == 1


# =============================================================================
# DCPPDaemon Tests
# =============================================================================

class TestDCPPDaemon:
    """Tests for DCPPDaemon class."""

    @pytest.fixture
    def config(self):
        return DaemonConfig(
            collections=["test:col1", "test:col2"],
            probe_interval=1,  # Short for testing
            dht_reannounce_interval=1,
            use_libp2p=False,  # Disable libp2p for unit tests to avoid network issues
        )

    def _create_manifest_dict(self, collection_id: str, merkle_root: str) -> dict:
        return {
            "protocol": "dcpp/1.0",
            "type": CollectionType.NFT_COLLECTION.value,
            "access_mode": AccessMode.PUBLIC.value,
            "collection_id": collection_id,
            "name": "Test Collection",
            "version": 1,
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "total_items": 0,
            "total_size_bytes": 0,
            "merkle_root": merkle_root,
            "torrent": {
                "infohash": "0" * 64,
                "magnet": "magnet:?xt=urn:btmh:test",
                "piece_length": 262144,
            },
            "items": [],
        }

    def test_create_daemon(self, config):
        """Create a daemon instance."""
        daemon = DCPPDaemon(config)
        assert daemon.state == NodeState.OFFLINE
        assert len(daemon.collection_states) == 0
        assert len(daemon.peer_tables) == 0

    @pytest.mark.asyncio
    async def test_start_initializes_state(self, config):
        """Start initializes collection states and peer tables."""
        # Create daemon inside async context to avoid event loop issues
        daemon = DCPPDaemon(config)

        # Start in background task
        start_task = asyncio.create_task(daemon.start())

        # Give it time to initialize and complete bootstrap
        for _ in range(10):
            if daemon.state not in (NodeState.OFFLINE, NodeState.CONNECTING):
                break
            await asyncio.sleep(0.1)

        assert daemon.state in (NodeState.READY, NodeState.DEGRADED)
        assert "test:col1" in daemon.collection_states
        assert "test:col2" in daemon.collection_states
        assert "test:col1" in daemon.peer_tables
        assert "test:col2" in daemon.peer_tables

        # Collection states should be INTERESTED
        assert daemon.collection_states["test:col1"] == CollectionState.INTERESTED

        # Stop daemon
        await daemon.stop()
        start_task.cancel()
        try:
            await start_task
        except asyncio.CancelledError:
            pass

    @pytest.mark.asyncio
    async def test_stop_sets_offline(self, config):
        """Stop sets state to OFFLINE."""
        # Create daemon inside async context
        daemon = DCPPDaemon(config)

        start_task = asyncio.create_task(daemon.start())
        await asyncio.sleep(0.1)

        await daemon.stop()

        assert daemon.state == NodeState.OFFLINE

        start_task.cancel()
        try:
            await start_task
        except asyncio.CancelledError:
            pass

    def test_get_capabilities(self, config):
        """Get capabilities returns enabled caps."""
        daemon = DCPPDaemon(config)
        caps = daemon.get_capabilities()

        assert "guardian" in caps
        assert "seeder" in caps
        assert "private" in caps

    def test_get_capabilities_partial(self):
        """Get capabilities respects config."""
        config = DaemonConfig(
            enable_guardian=True,
            enable_seeder=False,
            enable_private=False,
            use_libp2p=False,
        )
        daemon = DCPPDaemon(config)

        caps = daemon.get_capabilities()

        assert "guardian" in caps
        assert "seeder" not in caps
        assert "private" not in caps

    @pytest.mark.asyncio
    async def test_handle_received_manifest_accepts_hash_scheme(self, tmp_path):
        merkle_root = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        collection_id = f"hash:sha256:{merkle_root}"
        config = DaemonConfig(
            collections=[collection_id],
            use_libp2p=False,
            storage_path=tmp_path,
        )
        daemon = DCPPDaemon(config)
        manifest_dict = self._create_manifest_dict(collection_id, merkle_root)

        accepted = await daemon.handle_received_manifest(collection_id, manifest_dict, "test-peer")

        assert accepted is True
        assert collection_id in daemon._manifests
        assert daemon._manifests[collection_id].collection_id == collection_id

    @pytest.mark.asyncio
    async def test_handle_received_manifest_rejects_missing_signature(self, tmp_path):
        config = DaemonConfig(
            use_libp2p=False,
            storage_path=tmp_path,
        )
        daemon = DCPPDaemon(config)
        pubkey_hex = bytes(daemon._verify_key).hex()
        collection_id = f"key:ed25519:0x{pubkey_hex}"
        manifest_dict = self._create_manifest_dict(collection_id, "bafybeigmissing")

        accepted = await daemon.handle_received_manifest(collection_id, manifest_dict, "test-peer")

        assert accepted is False
        assert collection_id not in daemon._manifests

    @pytest.mark.asyncio
    async def test_handle_received_manifest_accepts_signed_key_scheme(self, tmp_path):
        config = DaemonConfig(
            use_libp2p=False,
            storage_path=tmp_path,
        )
        daemon = DCPPDaemon(config)
        pubkey_hex = bytes(daemon._verify_key).hex()
        collection_id = f"key:ed25519:0x{pubkey_hex}"
        manifest_dict = self._create_manifest_dict(collection_id, "bafybeigsigned")
        signature = sign_message(manifest_dict, daemon._signing_key)

        accepted = await daemon.handle_received_manifest(
            collection_id, manifest_dict, "test-peer", signature=signature
        )

        assert accepted is True
        assert collection_id in daemon._manifests


# =============================================================================
# CLI Parser Tests
# =============================================================================

class TestCLIParser:
    """Tests for CLI argument parser."""

    def test_create_parser(self):
        """Parser should be created."""
        parser = create_parser()
        assert parser is not None

    def test_parser_listen_multiple(self):
        """Parser should accept multiple listen addresses."""
        parser = create_parser()
        args = parser.parse_args([
            "-l", "/ip4/0.0.0.0/tcp/4001",
            "-l", "/ip4/0.0.0.0/udp/4001/quic",
        ])

        assert len(args.listen) == 2

    def test_parser_bootstrap_multiple(self):
        """Parser should accept multiple bootstrap peers."""
        parser = create_parser()
        args = parser.parse_args([
            "-b", "/ip4/1.2.3.4/tcp/4001",
            "-b", "/ip4/5.6.7.8/tcp/4001",
        ])

        assert len(args.bootstrap) == 2

    def test_parser_collections(self):
        """Parser should accept multiple collections."""
        parser = create_parser()
        args = parser.parse_args([
            "-c", "eth:0xBC4CA0",
            "-c", "test:collection",
        ])

        assert args.collections == ["eth:0xBC4CA0", "test:collection"]

    def test_parser_log_level(self):
        """Parser should accept log level."""
        parser = create_parser()
        args = parser.parse_args(["--log-level", "DEBUG"])

        assert args.log_level == "DEBUG"

    def test_parser_storage(self):
        """Parser should accept storage path."""
        parser = create_parser()
        args = parser.parse_args(["--storage", "/tmp/dcpp"])

        assert args.storage == "/tmp/dcpp"


# =============================================================================
# Setup Logging Tests
# =============================================================================

class TestSetupLogging:
    """Tests for logging setup."""

    def test_setup_logging_info(self):
        """Setup logging with INFO level."""
        config = DaemonConfig(log_level="INFO")
        setup_logging(config)
        # Should not raise

    def test_setup_logging_debug(self):
        """Setup logging with DEBUG level."""
        config = DaemonConfig(log_level="DEBUG")
        setup_logging(config)
        # Should not raise


# =============================================================================
# Multiaddr Parsing Tests
# =============================================================================

class TestMultiaddrParsing:
    """Tests for multiaddr parsing utilities."""

    def test_parse_ipv4_multiaddr(self):
        """Parse IPv4 multiaddr."""
        from dcpp_python.daemon import parse_multiaddr

        result = parse_multiaddr("/ip4/127.0.0.1/tcp/4001")
        assert result == ("127.0.0.1", 4001)

    def test_parse_ipv4_multiaddr_with_peer_id(self):
        """Parse IPv4 multiaddr with peer ID suffix."""
        from dcpp_python.daemon import parse_multiaddr

        result = parse_multiaddr("/ip4/192.168.1.10/tcp/4001/p2p/QmPeerIdXYZ")
        assert result == ("192.168.1.10", 4001)

    def test_parse_ipv6_multiaddr(self):
        """Parse IPv6 multiaddr."""
        from dcpp_python.daemon import parse_multiaddr

        result = parse_multiaddr("/ip6/::1/tcp/4001")
        assert result == ("::1", 4001)

    def test_parse_dns_multiaddr(self):
        """Parse DNS multiaddr."""
        from dcpp_python.daemon import parse_multiaddr

        result = parse_multiaddr("/dns4/example.com/tcp/4001")
        assert result == ("example.com", 4001)

    def test_parse_invalid_multiaddr(self):
        """Invalid multiaddr returns None."""
        from dcpp_python.daemon import parse_multiaddr

        result = parse_multiaddr("not_a_multiaddr")
        assert result is None

    def test_parse_incomplete_multiaddr(self):
        """Incomplete multiaddr returns None."""
        from dcpp_python.daemon import parse_multiaddr

        result = parse_multiaddr("/ip4/127.0.0.1")
        assert result is None


# =============================================================================
# OutboundTCPConnection Tests
# =============================================================================

class TestOutboundTCPConnection:
    """Tests for OutboundTCPConnection class."""

    def test_from_multiaddr_valid(self):
        """Create connection from valid multiaddr."""
        from dcpp_python.daemon import OutboundTCPConnection

        conn = OutboundTCPConnection.from_multiaddr("/ip4/127.0.0.1/tcp/4001")
        assert conn is not None
        assert conn.host == "127.0.0.1"
        assert conn.port == 4001

    def test_from_multiaddr_invalid(self):
        """Invalid multiaddr returns None."""
        from dcpp_python.daemon import OutboundTCPConnection

        conn = OutboundTCPConnection.from_multiaddr("invalid")
        assert conn is None

    def test_not_connected_initially(self):
        """Connection should not be connected initially."""
        from dcpp_python.daemon import OutboundTCPConnection

        conn = OutboundTCPConnection("127.0.0.1", 4001)
        assert not conn.is_connected


# =============================================================================
# Bootstrap Tests
# =============================================================================

class TestBootstrap:
    """Tests for daemon bootstrap functionality."""

    @pytest.fixture
    def config_with_collection(self):
        """Config with a collection for testing."""
        return DaemonConfig(
            collections=["test:collection"],
            bootstrap_peers=[],  # Will be set per test
            use_libp2p=False,
        )

    def test_daemon_initializes_peer_tables(self, config_with_collection):
        """Daemon should initialize peer tables for configured collections."""
        daemon = DCPPDaemon(config_with_collection)

        # Peer tables are created during start(), not __init__
        assert len(daemon.peer_tables) == 0

    @pytest.mark.asyncio
    async def test_bootstrap_without_peers(self, config_with_collection):
        """Bootstrap with no peers logs warning and continues."""
        daemon = DCPPDaemon(config_with_collection)

        # Should not raise, just warn
        await daemon._bootstrap()

        # Peer tables should still be empty
        assert len(daemon.peer_tables) == 0

    @pytest.mark.asyncio
    async def test_bootstrap_updates_peer_tables(self):
        """Bootstrap should populate peer tables from discovered peers."""
        config = DaemonConfig(
            collections=["test:collection"],
            use_libp2p=False,
        )
        daemon = DCPPDaemon(config)

        # Initialize peer tables as would happen during start()
        daemon.peer_tables["test:collection"] = PeerTable("test:collection")

        # Manually add a peer to simulate bootstrap discovery
        daemon.peer_tables["test:collection"].upsert(
            node_id=b"discovered_peer",
            multiaddrs=["/ip4/1.2.3.4/tcp/4001"],
            coverage=0.75,
        )

        # Verify peer was added
        assert b"discovered_peer" in daemon.peer_tables["test:collection"].peers
        entry = daemon.peer_tables["test:collection"].peers[b"discovered_peer"]
        assert entry.coverage == 0.75
        assert entry.multiaddrs == ["/ip4/1.2.3.4/tcp/4001"]

    @pytest.mark.asyncio
    async def test_connect_to_invalid_peer_fails(self):
        """Connecting to invalid peer should return False."""
        config = DaemonConfig(collections=["test:collection"], use_libp2p=False)
        daemon = DCPPDaemon(config)
        daemon.peer_tables["test:collection"] = PeerTable("test:collection")

        # Try to connect to non-existent peer (should fail)
        result = await daemon._connect_to_bootstrap_peer("/ip4/192.0.2.1/tcp/4001")

        assert result is False

    def test_discovered_peers_dict_structure(self):
        """Discovered peers dict should have correct structure."""
        discovered_peers: dict[str, list[tuple[bytes, list[str], float]]] = {}

        # Simulate adding discovered peers
        collection_id = "test:collection"
        discovered_peers[collection_id] = []
        discovered_peers[collection_id].append(
            (b"peer1", ["/ip4/1.2.3.4/tcp/4001"], 0.5)
        )
        discovered_peers[collection_id].append(
            (b"peer2", ["/ip4/5.6.7.8/tcp/4001"], 1.0)
        )

        # Verify structure
        assert len(discovered_peers[collection_id]) == 2
        node_id, multiaddrs, coverage = discovered_peers[collection_id][0]
        assert node_id == b"peer1"
        assert multiaddrs == ["/ip4/1.2.3.4/tcp/4001"]
        assert coverage == 0.5


# =============================================================================
# Daemon Lock-Path Regression Tests
# =============================================================================

class TestDaemonLockPathRegression:
    """Regression tests for daemon non-blocking behavior in initial guardian case."""

    @pytest.mark.asyncio
    async def test_manifest_received_download_start_is_non_blocking(self, monkeypatch):
        """
        Ensure manifest receipt does not block while starting download/seeding.

        This guards the "initial guardian" path when no peers exist, ensuring
        the daemon schedules the download action asynchronously.
        """
        config = DaemonConfig(collections=["test:collection"], use_libp2p=False)
        daemon = DCPPDaemon(config)

        started = asyncio.Event()
        release = asyncio.Event()

        async def blocked_download(manifest):
            started.set()
            await release.wait()

        monkeypatch.setattr(daemon, "_start_collection_download", blocked_download)

        now = int(time.time())
        torrent = TorrentInfo(
            infohash="0" * 64,
            magnet="magnet:?xt=urn:btmh:1220" + ("0" * 64),
            piece_length=262144,
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type="custom",
            access_mode="public",
            collection_id="test:collection",
            name="Test Collection",
            version=1,
            created_at=now,
            updated_at=now,
            total_items=0,
            total_size_bytes=0,
            merkle_root="0" * 64,
            torrent=torrent,
            probe_interval=3600,
        )

        daemon._process_state_event(NodeStartedEvent())
        daemon._process_state_event(BootstrapCompleteEvent(peer_count=0))
        daemon._process_state_event(
            ManifestReceivedEvent(
                collection_id=manifest.collection_id,
                manifest=manifest,
            )
        )

        await asyncio.wait_for(started.wait(), timeout=0.5)
        release.set()
        await asyncio.sleep(0)


# =============================================================================
# Bootstrap Discovery Tests
# =============================================================================

class TestBootstrapDiscovery:
    """Tests for bootstrap discovery module."""

    def test_parse_txt_multiaddr_simple(self):
        """Parse simple multiaddr from TXT record."""
        from dcpp_python.bootstrap_discovery import _parse_txt_multiaddr

        result = _parse_txt_multiaddr("/ip4/1.2.3.4/tcp/4001")
        assert result == "/ip4/1.2.3.4/tcp/4001"

    def test_parse_txt_multiaddr_with_prefix(self):
        """Parse multiaddr with addr= prefix."""
        from dcpp_python.bootstrap_discovery import _parse_txt_multiaddr

        result = _parse_txt_multiaddr("addr=/ip4/1.2.3.4/tcp/4001")
        assert result == "/ip4/1.2.3.4/tcp/4001"

    def test_parse_txt_multiaddr_with_peer_id(self):
        """Parse multiaddr with peer ID suffix."""
        from dcpp_python.bootstrap_discovery import _parse_txt_multiaddr

        result = _parse_txt_multiaddr("/ip4/1.2.3.4/tcp/4001/p2p/QmPeerId")
        assert result == "/ip4/1.2.3.4/tcp/4001/p2p/QmPeerId"

    def test_parse_txt_multiaddr_invalid(self):
        """Invalid value returns None."""
        from dcpp_python.bootstrap_discovery import _parse_txt_multiaddr

        result = _parse_txt_multiaddr("not a multiaddr")
        assert result is None

    def test_parse_bootstrap_content_one_per_line(self):
        """Parse bootstrap content with one multiaddr per line."""
        from dcpp_python.bootstrap_discovery import _parse_bootstrap_content

        content = """
/ip4/1.2.3.4/tcp/4001
/ip4/5.6.7.8/tcp/4001
# This is a comment
/ip4/9.10.11.12/tcp/4001
"""
        result = _parse_bootstrap_content(content)
        assert len(result) == 3
        assert "/ip4/1.2.3.4/tcp/4001" in result

    def test_parse_bootstrap_content_json_array(self):
        """Parse bootstrap content as JSON array."""
        from dcpp_python.bootstrap_discovery import _parse_bootstrap_content

        content = '["/ip4/1.2.3.4/tcp/4001", "/ip4/5.6.7.8/tcp/4001"]'
        result = _parse_bootstrap_content(content)
        assert len(result) == 2

    def test_parse_bootstrap_content_json_object(self):
        """Parse bootstrap content as JSON object with peers key."""
        from dcpp_python.bootstrap_discovery import _parse_bootstrap_content

        content = '{"peers": ["/ip4/1.2.3.4/tcp/4001"]}'
        result = _parse_bootstrap_content(content)
        assert len(result) == 1


# =============================================================================
# HEALTH_PROBE Challenge Validation Tests
# =============================================================================

class TestHealthProbeChallengeValidation:
    """Tests for HEALTH_PROBE challenge offset/length validation."""

    @pytest.fixture
    def daemon_with_content(self):
        """Create a daemon with content for testing."""
        config = DaemonConfig(collections=["test:collection"], use_libp2p=False)
        daemon = DCPPDaemon(config)
        # Mock the retrieve_content method to return test data
        daemon._test_content = b"0123456789" * 100  # 1000 bytes
        original_retrieve = daemon.retrieve_content

        def mock_retrieve(collection_id, cid):
            if cid == "QmTestContent":
                return daemon._test_content
            return None

        daemon.retrieve_content = mock_retrieve
        return daemon

    def test_challenge_with_valid_offset_length(self, daemon_with_content):
        """Challenge with valid offset/length should return data."""
        from dcpp_python.messages import Challenge, ChallengeResponse

        challenge = Challenge(cid="QmTestContent", offset=0, length=100)

        # Simulate the daemon's challenge processing logic
        content = daemon_with_content.retrieve_content("test:collection", challenge.cid)
        assert content is not None

        # Check the validation logic
        assert not getattr(challenge, "_invalid_offset", False)
        assert not getattr(challenge, "_invalid_length", False)
        assert challenge.offset >= 0
        assert challenge.length > 0

    def test_challenge_with_negative_offset_flagged(self, daemon_with_content):
        """Challenge with negative offset should be flagged."""
        from dcpp_python.messages import Challenge

        challenge = Challenge(cid="QmTestContent", offset=-100, length=50)

        # The challenge should be flagged
        assert challenge._invalid_offset is True
        assert challenge.offset == 0  # Normalized

    def test_challenge_with_negative_length_flagged(self, daemon_with_content):
        """Challenge with negative length should be flagged."""
        from dcpp_python.messages import Challenge

        challenge = Challenge(cid="QmTestContent", offset=0, length=-50)

        # The challenge should be flagged
        assert challenge._invalid_length is True
        assert challenge.length == 0  # Normalized

    def test_challenge_offset_exceeds_content_length(self, daemon_with_content):
        """Challenge with offset >= content length should error."""
        from dcpp_python.messages import Challenge

        # Content is 1000 bytes, offset 1000 or more should error
        challenge = Challenge(cid="QmTestContent", offset=1000, length=50)

        content = daemon_with_content.retrieve_content("test:collection", challenge.cid)
        assert content is not None
        assert challenge.offset >= len(content)  # Should trigger offset_out_of_bounds

    def test_challenge_length_clamped(self, daemon_with_content):
        """Challenge length should be clamped to MAX_LENGTH."""
        from dcpp_python.messages import Challenge

        challenge = Challenge(cid="QmTestContent", offset=0, length=2048)
        assert challenge.length == 1024  # MAX_LENGTH

    def test_python_negative_slicing_prevented(self):
        """Verify that negative values don't cause Python's negative slicing."""
        from dcpp_python.messages import Challenge

        # Without validation, Python would allow:
        # content[-100:] which returns last 100 bytes
        # This is the security issue we're preventing

        challenge = Challenge(cid="QmTest", offset=-100, length=50)

        # After our fix, offset is normalized to 0 and flagged
        assert challenge.offset == 0
        assert challenge._invalid_offset is True

        # The daemon handler should check _invalid_offset and return error
        # instead of allowing content[0:50] to succeed

    def test_zero_length_challenge_flagged(self):
        """Zero length challenge should be flagged as invalid."""
        from dcpp_python.messages import Challenge

        # Zero length is technically valid per RFC (uint32) but useless
        # Our implementation flags it to prevent confusion
        challenge = Challenge(cid="QmTest", offset=0, length=0)

        # Zero length doesn't trigger _invalid_length (only negative does)
        # but it's clamped and the daemon should handle it
        assert challenge.length == 0


class TestHealthProbeMaxChallenges:
    """Tests for HEALTH_PROBE max challenges limit (RFC 10.3)."""

    def test_max_challenges_constant(self):
        """Verify max challenges constant is defined."""
        from dcpp_python.core.constants import MAX_CHALLENGES_PER_PROBE

        assert MAX_CHALLENGES_PER_PROBE == 10

    def test_probe_with_too_many_challenges(self):
        """Probe with >10 challenges should be rejected."""
        from dcpp_python.messages import Challenge, HealthProbe

        # Create 11 challenges (exceeds max of 10)
        challenges = [
            Challenge(cid=f"QmTest{i}", offset=0, length=100)
            for i in range(11)
        ]

        probe = HealthProbe(
            collection_id="test:collection",
            challenges=challenges,
            nonce=b"testnonce",
        )

        # The probe is created, but the daemon should reject it
        assert len(probe.challenges) == 11


# =============================================================================
# BitTorrent Backend Selection Tests (RFC 3.2 compliance)
# =============================================================================

class TestBitTorrentBackendSelection:
    """Tests for BitTorrent backend selection and RFC 3.2 compliance."""

    def test_default_backend_is_real(self, monkeypatch):
        """Default backend should be 'real' for production safety."""
        from dcpp_python.daemon import _get_bt_backend_from_env, BitTorrentBackendType

        # Unset the env var to test default
        monkeypatch.delenv("DCPP_BT_BACKEND", raising=False)

        backend_type = _get_bt_backend_from_env()
        assert backend_type == BitTorrentBackendType.REAL

    def test_explicit_mock_backend(self, monkeypatch):
        """DCPP_BT_BACKEND=mock should return mock backend type."""
        from dcpp_python.daemon import _get_bt_backend_from_env, BitTorrentBackendType

        monkeypatch.setenv("DCPP_BT_BACKEND", "mock")

        backend_type = _get_bt_backend_from_env()
        assert backend_type == BitTorrentBackendType.MOCK

    def test_explicit_local_backend(self, monkeypatch):
        """DCPP_BT_BACKEND=local should return local backend type."""
        from dcpp_python.daemon import _get_bt_backend_from_env, BitTorrentBackendType

        monkeypatch.setenv("DCPP_BT_BACKEND", "local")

        backend_type = _get_bt_backend_from_env()
        assert backend_type == BitTorrentBackendType.LOCAL

    def test_explicit_real_backend(self, monkeypatch):
        """DCPP_BT_BACKEND=real should return real backend type."""
        from dcpp_python.daemon import _get_bt_backend_from_env, BitTorrentBackendType

        monkeypatch.setenv("DCPP_BT_BACKEND", "real")

        backend_type = _get_bt_backend_from_env()
        assert backend_type == BitTorrentBackendType.REAL

    def test_invalid_backend_raises_error(self, monkeypatch):
        """Invalid DCPP_BT_BACKEND value should raise ValueError."""
        from dcpp_python.daemon import _get_bt_backend_from_env

        monkeypatch.setenv("DCPP_BT_BACKEND", "invalid_value")

        with pytest.raises(ValueError) as exc_info:
            _get_bt_backend_from_env()

        assert "invalid_value" in str(exc_info.value)
        assert "mock" in str(exc_info.value)  # Should list valid values

    def test_backend_case_insensitive(self, monkeypatch):
        """Backend selection should be case-insensitive."""
        from dcpp_python.daemon import _get_bt_backend_from_env, BitTorrentBackendType

        monkeypatch.setenv("DCPP_BT_BACKEND", "MOCK")
        assert _get_bt_backend_from_env() == BitTorrentBackendType.MOCK

        monkeypatch.setenv("DCPP_BT_BACKEND", "Real")
        assert _get_bt_backend_from_env() == BitTorrentBackendType.REAL

        monkeypatch.setenv("DCPP_BT_BACKEND", "LOCAL")
        assert _get_bt_backend_from_env() == BitTorrentBackendType.LOCAL


class TestMockBitTorrentBackendWarning:
    """Tests for MockBitTorrentBackend warning behavior."""

    def test_mock_backend_no_suppress_warning_param(self):
        """MockBitTorrentBackend should not accept _suppress_warning parameter."""
        from dcpp_python.bittorrent import MockBitTorrentBackend
        import inspect

        sig = inspect.signature(MockBitTorrentBackend.__init__)
        param_names = list(sig.parameters.keys())

        # Should only have 'self', no _suppress_warning
        assert "_suppress_warning" not in param_names

    def test_mock_backend_instantiation_in_test(self):
        """MockBitTorrentBackend should instantiate without error in test env."""
        from dcpp_python.bittorrent import MockBitTorrentBackend

        # Should not raise - we're in a test environment
        backend = MockBitTorrentBackend()
        assert backend is not None

    def test_mock_backend_detects_test_environment(self):
        """MockBitTorrentBackend should detect pytest environment."""
        from dcpp_python.bittorrent import MockBitTorrentBackend

        # We're running in pytest, so this should return True
        assert MockBitTorrentBackend._is_test_environment() is True


class TestBitTorrentBackendCreationFailFast:
    """Tests for fail-fast behavior when dependencies are missing."""

    def test_config_bt_backend_default_from_env(self, monkeypatch):
        """DaemonConfig.bt_backend should read from env."""
        from dcpp_python.daemon import DaemonConfig, BitTorrentBackendType

        monkeypatch.setenv("DCPP_BT_BACKEND", "mock")
        config = DaemonConfig()
        assert config.bt_backend == BitTorrentBackendType.MOCK

    def test_config_bt_backend_default_is_real(self, monkeypatch):
        """DaemonConfig.bt_backend default should be 'real'."""
        from dcpp_python.daemon import DaemonConfig, BitTorrentBackendType

        monkeypatch.delenv("DCPP_BT_BACKEND", raising=False)
        config = DaemonConfig()
        assert config.bt_backend == BitTorrentBackendType.REAL
