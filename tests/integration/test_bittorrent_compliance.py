"""
BitTorrent RFC 12 Compliance Tests for DCPP Wire Protocol

Tests for RFC Section 12 - BitTorrent v2 requirements and piece size validation.
"""

import os
import hashlib
import tempfile
from pathlib import Path

import pytest

from dcpp_python.bittorrent import (
    TorrentStatus,
    TorrentStats,
    TorrentMetadata,
    TorrentFile,
    Piece,
    MockBitTorrentBackend,
    DCPPTorrentManager,
    MIN_PIECE_SIZE,
    MAX_PIECE_SIZE,
    recommended_piece_length,
)
from dcpp_python.bittorrent_real import (
    RealBitTorrentBackend,
    recommended_piece_length_bep52,
    validate_piece_length_rfc12,
    is_local_only_allowed,
    PIECE_SIZE_256KB,
    PIECE_SIZE_1MB,
    PIECE_SIZE_4MB,
)


# =============================================================================
# RFC Section 12: Piece Size Requirements (BEP 52 bands)
# =============================================================================

class TestRFC12PieceSizeBands:
    """Tests for RFC Section 12 - Piece size band requirements."""

    def test_rfc12_band_small_256kb(self):
        """RFC 12: Collections <1GB MUST use 256KB pieces."""
        # Just under 1GB
        size = 1024 * 1024 * 1024 - 1  # 1GB - 1 byte
        expected = PIECE_SIZE_256KB
        assert recommended_piece_length_bep52(size) == expected

        # 500MB
        size = 500 * 1024 * 1024
        assert recommended_piece_length_bep52(size) == expected

    def test_rfc12_band_medium_1mb(self):
        """RFC 12: Collections 1-10GB MUST use 1MB pieces."""
        # Exactly 1GB
        size = 1024 * 1024 * 1024  # 1GB
        expected = PIECE_SIZE_1MB
        assert recommended_piece_length_bep52(size) == expected

        # 5GB
        size = 5 * 1024 * 1024 * 1024
        assert recommended_piece_length_bep52(size) == expected

        # Just under 10GB
        size = 10 * 1024 * 1024 * 1024 - 1
        assert recommended_piece_length_bep52(size) == expected

    def test_rfc12_band_large_4mb(self):
        """RFC 12: Collections >10GB MUST use 4MB pieces."""
        # Exactly 10GB
        size = 10 * 1024 * 1024 * 1024  # 10GB
        expected = PIECE_SIZE_4MB
        assert recommended_piece_length_bep52(size) == expected

        # 50GB
        size = 50 * 1024 * 1024 * 1024
        assert recommended_piece_length_bep52(size) == expected

    def test_validate_piece_length_correct_band(self, tmp_path):
        """RFC 12: validate_piece_length_rfc12 accepts correct band."""
        # 500MB -> 256KB
        validate_piece_length_rfc12(PIECE_SIZE_256KB, 500 * 1024 * 1024)

        # 5GB -> 1MB
        validate_piece_length_rfc12(PIECE_SIZE_1MB, 5 * 1024 * 1024 * 1024)

        # 50GB -> 4MB
        validate_piece_length_rfc12(PIECE_SIZE_4MB, 50 * 1024 * 1024 * 1024)

    def test_validate_piece_length_wrong_band_rejected(self):
        """RFC 12: validate_piece_length_rfc12 rejects wrong band."""
        # 500MB with 1MB pieces (should be 256KB)
        with pytest.raises(ValueError, match="RFC Section 12"):
            validate_piece_length_rfc12(PIECE_SIZE_1MB, 500 * 1024 * 1024)

        # 5GB with 256KB pieces (should be 1MB)
        with pytest.raises(ValueError, match="RFC Section 12"):
            validate_piece_length_rfc12(PIECE_SIZE_256KB, 5 * 1024 * 1024 * 1024)

        # 50GB with 1MB pieces (should be 4MB)
        with pytest.raises(ValueError, match="RFC Section 12"):
            validate_piece_length_rfc12(PIECE_SIZE_1MB, 50 * 1024 * 1024 * 1024)

    def test_validate_piece_length_zero_rejected(self):
        """RFC 12: piece_length=0 is rejected - explicit value required."""
        # 0 is not a valid piece length - must specify correct band
        with pytest.raises(ValueError, match="RFC Section 12"):
            validate_piece_length_rfc12(0, 500 * 1024 * 1024)


# =============================================================================
# RFC Section 12: Local-Only Gating
# =============================================================================

class TestRFC12LocalOnlyGating:
    """Tests for RFC Section 12 - DCPP_BT_ALLOW_LOCAL environment variable."""

    def test_local_only_env_check(self):
        """DCPP_BT_ALLOW_LOCAL environment variable controls local-only mode."""
        original = os.environ.get("DCPP_BT_ALLOW_LOCAL")

        try:
            os.environ["DCPP_BT_ALLOW_LOCAL"] = "1"
            assert is_local_only_allowed() is True

            os.environ["DCPP_BT_ALLOW_LOCAL"] = "0"
            assert is_local_only_allowed() is False

            del os.environ["DCPP_BT_ALLOW_LOCAL"]
            assert is_local_only_allowed() is False
        finally:
            if original:
                os.environ["DCPP_BT_ALLOW_LOCAL"] = original
            elif "DCPP_BT_ALLOW_LOCAL" in os.environ:
                del os.environ["DCPP_BT_ALLOW_LOCAL"]

    def test_create_torrent_requires_torf_or_local_flag(self, tmp_path):
        """RFC 12: create_torrent requires torf or DCPP_BT_ALLOW_LOCAL=1."""
        original = os.environ.get("DCPP_BT_ALLOW_LOCAL")

        try:
            os.environ["DCPP_BT_ALLOW_LOCAL"] = "0"

            backend = RealBitTorrentBackend(download_dir=tmp_path)

            # Create test content
            content_dir = tmp_path / "content"
            content_dir.mkdir()
            (content_dir / "test.txt").write_text("test content")

            # With local flag off, behavior depends on whether torf is installed
            try:
                metadata = backend.create_torrent(
                    source_dir=content_dir,
                    piece_length=0,
                    name="gating_test"
                )
                # If we get here, torf IS installed and BEP 52 mode is active
                assert metadata is not None
                assert len(metadata.info_hash) == 32  # SHA-256
            except ImportError as e:
                # Expected when torf is NOT installed and local flag is off
                assert "torf" in str(e).lower()
                assert "DCPP_BT_ALLOW_LOCAL" in str(e)

        finally:
            if original:
                os.environ["DCPP_BT_ALLOW_LOCAL"] = original
            elif "DCPP_BT_ALLOW_LOCAL" in os.environ:
                del os.environ["DCPP_BT_ALLOW_LOCAL"]

    def test_create_torrent_local_flag_bypasses_torf_requirement(self, tmp_path):
        """RFC 12: DCPP_BT_ALLOW_LOCAL=1 allows local-only torrent creation."""
        original = os.environ.get("DCPP_BT_ALLOW_LOCAL")

        try:
            os.environ["DCPP_BT_ALLOW_LOCAL"] = "1"

            backend = RealBitTorrentBackend(download_dir=tmp_path)

            # Create test content
            content_dir = tmp_path / "content"
            content_dir.mkdir()
            (content_dir / "test.txt").write_text("test content for local mode")

            # With local flag ON, should succeed even without torf
            metadata = backend.create_torrent(
                source_dir=content_dir,
                piece_length=0,
                name="local_bypass_test"
            )

            # Verify torrent was created with correct structure
            assert metadata is not None
            assert len(metadata.info_hash) == 32  # SHA-256 length
            assert len(metadata.info_hash_v1) == 20  # SHA-1 length
            assert metadata.magnet_uri.startswith("magnet:?")

        finally:
            if original:
                os.environ["DCPP_BT_ALLOW_LOCAL"] = original
            elif "DCPP_BT_ALLOW_LOCAL" in os.environ:
                del os.environ["DCPP_BT_ALLOW_LOCAL"]


# =============================================================================
# BitTorrent v2 (BEP 52) Info Hash - LOCAL-ONLY MODE TESTS
# =============================================================================

class TestLocalModeInfoHash:
    """Tests for local-only mode info hash generation.

    IMPORTANT: These tests run in LOCAL-ONLY MODE (DCPP_BT_ALLOW_LOCAL=1)
    which generates info hashes WITHOUT using the torf library. The hashes
    produced in this mode are NOT BEP 52 compliant - they only have correct
    lengths but are computed differently than proper BitTorrent v2 hashes.

    For true RFC 12 / BEP 52 compliance testing, use pytest.importorskip("torf")
    and test with the TorfBackend which produces proper bencoded info hashes.

    These tests validate:
    - Hash length requirements (32 bytes for v2, 20 bytes for v1)
    - Magnet URI format
    - Basic local-only mode functionality
    """

    @pytest.fixture(autouse=True)
    def enable_local_mode(self):
        """Enable local-only mode for testing without torf."""
        original = os.environ.get("DCPP_BT_ALLOW_LOCAL")
        os.environ["DCPP_BT_ALLOW_LOCAL"] = "1"
        yield
        if original:
            os.environ["DCPP_BT_ALLOW_LOCAL"] = original
        elif "DCPP_BT_ALLOW_LOCAL" in os.environ:
            del os.environ["DCPP_BT_ALLOW_LOCAL"]

    def test_local_mode_info_hash_v2_length(self, tmp_path):
        """Local-only mode: info_hash MUST be 32 bytes (matches BEP 52 length).

        NOTE: This only validates length, not actual BEP 52 hash computation.
        """
        backend = RealBitTorrentBackend(download_dir=tmp_path)

        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "test.txt").write_text("test content for local mode")

        metadata = backend.create_torrent(
            source_dir=content_dir,
            piece_length=0,
            name="local_test"
        )

        # Length matches BEP 52 (SHA-256 = 32 bytes)
        # But actual hash computation differs from proper BEP 52
        assert len(metadata.info_hash) == 32

    def test_local_mode_info_hash_v1_length(self, tmp_path):
        """Local-only mode: info_hash_v1 MUST be 20 bytes (matches BEP 3 length).

        NOTE: This only validates length, not actual BEP 3 hash computation.
        """
        backend = RealBitTorrentBackend(download_dir=tmp_path)

        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "test.txt").write_text("hybrid torrent test")

        metadata = backend.create_torrent(
            source_dir=content_dir,
            piece_length=0,
            name="local_hybrid_test"
        )

        # Length matches BEP 3 (SHA-1 = 20 bytes)
        assert len(metadata.info_hash_v1) == 20

    def test_local_mode_magnet_uri_format(self, tmp_path):
        """Local-only mode: Magnet URI includes both hash types in correct format."""
        backend = RealBitTorrentBackend(download_dir=tmp_path)

        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "test.txt").write_text("magnet test")

        metadata = backend.create_torrent(
            source_dir=content_dir,
            piece_length=0,
            name="local_magnet_test"
        )

        # Format matches expected structure (but hashes are not BEP-compliant)
        assert "xt=urn:btih:" in metadata.magnet_uri
        assert "xt=urn:btmh:1220" in metadata.magnet_uri  # 1220 = sha2-256 multicodec


class TestBEP52Compliance:
    """Tests for true BEP 52 compliance (requires torf library).

    These tests are skipped if torf is not available.
    """

    @pytest.fixture(autouse=True)
    def require_torf(self):
        """Skip tests if torf library is not available."""
        pytest.importorskip("torf", reason="torf library required for BEP 52 compliance tests")

    def test_bep52_compliant_info_hash(self, tmp_path):
        """RFC 12/BEP 52: Info hash MUST be computed from bencoded info dict.

        This test would verify actual BEP 52 compliance with torf library.
        """
        import torf

        from dcpp_python.network.bittorrent.real import TorfBackend, get_backend

        backend = get_backend(download_dir=tmp_path)
        assert isinstance(backend, TorfBackend)

        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "test.txt").write_text("bep52 compliance test")

        piece_length = 262144  # 256 KiB (RFC 12 default for small content)
        metadata = backend.create_torrent(
            source_dir=content_dir,
            piece_length=piece_length,
            name="bep52_test",
        )

        t = torf.Torrent(path=content_dir, name="bep52_test")
        t.piece_size = piece_length
        t.generate()

        expected_hash_hex = None
        if hasattr(t, "infohash_v2") and t.infohash_v2:
            expected_hash_hex = t.infohash_v2
        elif t.infohash:
            expected_hash_hex = t.infohash

        assert expected_hash_hex is not None
        assert metadata.info_hash == bytes.fromhex(expected_hash_hex)
        assert len(metadata.info_hash) in (20, 32)
        expected_piece_hashes = list(t.hashes) if t.hashes else []
        assert metadata.piece_hashes_v2 == expected_piece_hashes
        assert metadata.piece_hashes_v2
        assert all(len(h) in (20, 32) for h in metadata.piece_hashes_v2)


# =============================================================================
# TorrentStats Tests
# =============================================================================

class TestTorrentStats:
    """Tests for TorrentStats dataclass."""

    def test_completion_empty(self):
        """Completion should be 0 when no pieces."""
        stats = TorrentStats(total_pieces=0)
        assert stats.completion == 0.0

    def test_completion_partial(self):
        """Completion should be have/total."""
        stats = TorrentStats(total_pieces=100, have_pieces=50)
        assert stats.completion == 0.5

    def test_completion_full(self):
        """Completion should be 1.0 when complete."""
        stats = TorrentStats(total_pieces=100, have_pieces=100)
        assert stats.completion == 1.0


# =============================================================================
# MockBitTorrentBackend Tests
# =============================================================================

class TestMockBitTorrentBackend:
    """Tests for MockBitTorrentBackend."""

    @pytest.fixture
    def backend(self):
        return MockBitTorrentBackend()

    def test_create_torrent(self, backend, tmp_path):
        """Mock backend creates torrent metadata."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()

        metadata = backend.create_torrent(
            source_dir=content_dir,
            piece_length=262144,
            name="test_torrent"
        )

        assert len(metadata.info_hash) == 32
        assert metadata.piece_length == 262144
        assert "magnet:?" in metadata.magnet_uri

    def test_add_magnet(self, backend, tmp_path):
        """Mock backend adds magnet URI."""
        magnet = "magnet:?xt=urn:btih:" + "0" * 40
        info_hash = backend.add_magnet(magnet, tmp_path)

        assert len(info_hash) == 32
        assert backend.get_status(info_hash) == TorrentStatus.METADATA

    def test_add_torrent(self, backend, tmp_path):
        """Mock backend adds torrent metadata."""
        metadata = TorrentMetadata(
            info_hash=b"\x00" * 32,
            piece_length=262144,
            files=[],
            total_size=1000
        )

        info_hash = backend.add_torrent(metadata, tmp_path)
        assert info_hash == metadata.info_hash
        assert backend.get_status(info_hash) == TorrentStatus.DOWNLOADING

    def test_remove_torrent(self, backend, tmp_path):
        """Mock backend removes torrents."""
        magnet = "magnet:?xt=urn:btih:" + "1" * 40
        info_hash = backend.add_magnet(magnet, tmp_path)

        assert backend.remove_torrent(info_hash) is True
        assert backend.get_status(info_hash) is None
        assert backend.remove_torrent(info_hash) is False

    def test_pause_resume(self, backend, tmp_path):
        """Mock backend pauses and resumes torrents."""
        metadata = TorrentMetadata(
            info_hash=b"\x11" * 32,
            piece_length=262144,
            files=[],
            total_size=1000
        )
        backend.add_torrent(metadata, tmp_path)

        # Pause
        backend.pause(metadata.info_hash)
        assert backend.get_status(metadata.info_hash) == TorrentStatus.PAUSED

        # Resume
        backend.resume(metadata.info_hash)
        assert backend.get_status(metadata.info_hash) == TorrentStatus.DOWNLOADING

    def test_add_mock_piece(self, backend, tmp_path):
        """Mock backend stores and retrieves pieces."""
        metadata = TorrentMetadata(
            info_hash=b"\x22" * 32,
            piece_length=262144,
            files=[],
            total_size=1000
        )
        backend.add_torrent(metadata, tmp_path)

        piece_data = b"test_piece_data"
        backend.add_mock_piece(metadata.info_hash, 0, piece_data)

        retrieved = backend.get_piece(metadata.info_hash, 0)
        assert retrieved == piece_data

    def test_verify_piece(self, backend, tmp_path):
        """Mock backend verifies pieces."""
        metadata = TorrentMetadata(
            info_hash=b"\x33" * 32,
            piece_length=262144,
            files=[],
            total_size=1000
        )
        backend.add_torrent(metadata, tmp_path)

        piece_data = b"verify_test_data"
        backend.add_mock_piece(metadata.info_hash, 0, piece_data)

        # Correct data verifies
        assert backend.verify_piece(metadata.info_hash, 0, piece_data) is True

        # Wrong data fails
        assert backend.verify_piece(metadata.info_hash, 0, b"wrong_data") is False

    def test_get_stats(self, backend, tmp_path):
        """Mock backend returns stats."""
        metadata = TorrentMetadata(
            info_hash=b"\x44" * 32,
            piece_length=262144,
            files=[],
            total_size=1000
        )
        backend.add_torrent(metadata, tmp_path)

        stats = backend.get_stats(metadata.info_hash)
        assert stats is not None

        # Nonexistent returns None
        assert backend.get_stats(b"\xff" * 32) is None


# =============================================================================
# DCPPTorrentManager Tests
# =============================================================================

class TestDCPPTorrentManager:
    """Tests for DCPPTorrentManager."""

    @pytest.fixture
    def manager(self, tmp_path):
        backend = MockBitTorrentBackend()
        return DCPPTorrentManager(backend, tmp_path)

    def test_add_collection(self, manager):
        """Manager adds collection from manifest."""
        manifest = {
            "collection_id": "test:collection",
            "torrent": {
                "magnet_uri": "magnet:?xt=urn:btih:" + "0" * 40
            }
        }

        info_hash = manager.add_collection(manifest)
        assert len(info_hash) == 32

    def test_get_collection_status(self, manager):
        """Manager returns collection status."""
        manifest = {
            "collection_id": "test:status",
            "torrent": {
                "magnet_uri": "magnet:?xt=urn:btih:" + "1" * 40
            }
        }

        manager.add_collection(manifest)

        status = manager.get_collection_status("test:status")
        assert status == TorrentStatus.METADATA

    def test_get_collection_stats(self, manager):
        """Manager returns collection stats."""
        manifest = {
            "collection_id": "test:stats",
            "torrent": {
                "magnet_uri": "magnet:?xt=urn:btih:" + "2" * 40
            }
        }

        manager.add_collection(manifest)

        stats = manager.get_collection_stats("test:stats")
        assert stats is not None

    def test_get_collection_coverage(self, manager):
        """Manager returns collection coverage."""
        manifest = {
            "collection_id": "test:coverage",
            "torrent": {
                "magnet_uri": "magnet:?xt=urn:btih:" + "3" * 40
            }
        }

        manager.add_collection(manifest)

        coverage = manager.get_collection_coverage("test:coverage")
        assert coverage == 0.0  # No pieces yet

    def test_unknown_collection_returns_none(self, manager):
        """Manager returns None for unknown collections."""
        assert manager.get_collection_status("unknown") is None
        assert manager.get_collection_stats("unknown") is None
        assert manager.get_collection_coverage("unknown") == 0.0


# =============================================================================
# recommended_piece_length Tests (non-RFC legacy function)
# =============================================================================

class TestRecommendedPieceLength:
    """Tests for legacy recommended_piece_length function."""

    def test_within_bounds(self):
        """Piece length should be within MIN/MAX bounds."""
        for size in [1000, 1_000_000, 1_000_000_000, 100_000_000_000]:
            pl = recommended_piece_length(size)
            assert MIN_PIECE_SIZE <= pl <= MAX_PIECE_SIZE

    def test_power_of_two(self):
        """Piece length should be a power of 2."""
        for size in [1_000_000, 10_000_000, 100_000_000]:
            pl = recommended_piece_length(size)
            # Check if power of 2
            assert (pl & (pl - 1)) == 0
