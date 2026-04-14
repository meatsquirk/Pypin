"""
Tests for Real BitTorrent Backend Implementation

Note: These tests require DCPP_BT_ALLOW_LOCAL=1 since torf library
may not be installed in all environments.
"""

import hashlib
import os
import tempfile
from pathlib import Path

import pytest

from dcpp_python.bittorrent import TorrentStatus, TorrentStats, MIN_PIECE_SIZE, MAX_PIECE_SIZE
from dcpp_python.bittorrent_real import (
    RealBitTorrentBackend,
    HybridTorrentMetadata,
    PieceMapping,
    recommended_piece_length_bep52,
    PIECE_SIZE_256KB,
    PIECE_SIZE_1MB,
    PIECE_SIZE_4MB,
    get_backend,
)


# Module-level fixture to enable local-only mode for all tests
@pytest.fixture(autouse=True, scope="module")
def enable_local_mode_for_module():
    """Enable local-only mode for all tests in this module."""
    original = os.environ.get("DCPP_BT_ALLOW_LOCAL")
    os.environ["DCPP_BT_ALLOW_LOCAL"] = "1"
    yield
    if original:
        os.environ["DCPP_BT_ALLOW_LOCAL"] = original
    elif "DCPP_BT_ALLOW_LOCAL" in os.environ:
        del os.environ["DCPP_BT_ALLOW_LOCAL"]


class TestRecommendedPieceLength:
    """Tests for piece length calculation."""

    def test_small_file_256kb(self):
        # <1GB should use 256KB pieces
        assert recommended_piece_length_bep52(500 * 1024 * 1024) == PIECE_SIZE_256KB

    def test_medium_file_1mb(self):
        # 1-10GB should use 1MB pieces
        assert recommended_piece_length_bep52(5 * 1024 * 1024 * 1024) == PIECE_SIZE_1MB

    def test_large_file_4mb(self):
        # >10GB should use 4MB pieces
        assert recommended_piece_length_bep52(20 * 1024 * 1024 * 1024) == PIECE_SIZE_4MB

    def test_boundary_1gb(self):
        one_gb = 1024 * 1024 * 1024
        # Just under 1GB -> 256KB
        assert recommended_piece_length_bep52(one_gb - 1) == PIECE_SIZE_256KB
        # At 1GB -> 1MB
        assert recommended_piece_length_bep52(one_gb) == PIECE_SIZE_1MB


class TestHybridTorrentMetadata:
    """Tests for hybrid torrent metadata."""

    def test_create_metadata(self):
        metadata = HybridTorrentMetadata(
            info_hash=b"\x00" * 32,
            info_hash_v1=b"\x11" * 20,
            piece_length=PIECE_SIZE_256KB,
            files=[],
            total_size=1000,
            magnet_uri="magnet:?...",
            piece_hashes_v1=[b"\x00" * 20],
            piece_hashes_v2=[b"\x00" * 32],
        )

        assert metadata.info_hash == b"\x00" * 32
        assert metadata.info_hash_v1 == b"\x11" * 20
        assert len(metadata.piece_hashes_v1) == 1
        assert len(metadata.piece_hashes_v2) == 1


class TestRealBitTorrentBackend:
    """Tests for the real BitTorrent backend."""

    @pytest.fixture
    def backend(self, tmp_path):
        return RealBitTorrentBackend(download_dir=tmp_path)

    @pytest.fixture
    def test_dir(self, tmp_path):
        """Create a test directory with some files."""
        test_dir = tmp_path / "test_content"
        test_dir.mkdir()

        # Create test files
        (test_dir / "file1.txt").write_text("Hello, World!")
        (test_dir / "file2.txt").write_text("This is test content.")
        (test_dir / "subdir").mkdir()
        (test_dir / "subdir" / "file3.txt").write_text("Nested file content.")

        return test_dir

    def test_create_torrent_basic(self, backend, test_dir):
        metadata = backend.create_torrent(
            source_dir=test_dir,
            piece_length=PIECE_SIZE_256KB,
            name="test_torrent"
        )

        assert isinstance(metadata, HybridTorrentMetadata)
        assert metadata.info_hash is not None
        assert len(metadata.info_hash) == 32  # SHA-256
        assert metadata.total_size > 0
        assert len(metadata.files) == 3
        assert metadata.magnet_uri.startswith("magnet:?")

    def test_create_torrent_hybrid_hashes(self, backend, test_dir):
        metadata = backend.create_torrent(
            source_dir=test_dir,
            piece_length=PIECE_SIZE_256KB,
            name="hybrid_test"
        )

        assert isinstance(metadata, HybridTorrentMetadata)
        # Should have both v1 and v2 info hashes
        assert len(metadata.info_hash) == 32  # v2: SHA-256
        assert len(metadata.info_hash_v1) == 20  # v1: SHA-1

        # Should have piece hashes
        num_pieces = (metadata.total_size + metadata.piece_length - 1) // metadata.piece_length
        assert len(metadata.piece_hashes_v1) == num_pieces
        assert len(metadata.piece_hashes_v2) == num_pieces

        # Each hash should be correct size
        for h in metadata.piece_hashes_v1:
            assert len(h) == 20  # SHA-1
        for h in metadata.piece_hashes_v2:
            assert len(h) == 32  # SHA-256

    def test_create_torrent_magnet_uri(self, backend, test_dir):
        metadata = backend.create_torrent(
            source_dir=test_dir,
            piece_length=PIECE_SIZE_256KB,
            name="magnet_test"
        )

        # Magnet URI should contain both v1 and v2 hashes
        assert "xt=urn:btih:" in metadata.magnet_uri  # v1
        assert "xt=urn:btmh:1220" in metadata.magnet_uri  # v2

    def test_create_torrent_empty_dir(self, backend, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        with pytest.raises(ValueError, match="No files found"):
            backend.create_torrent(empty_dir, PIECE_SIZE_256KB, "empty")

    def test_create_torrent_nonexistent_dir(self, backend):
        with pytest.raises(ValueError, match="does not exist"):
            backend.create_torrent(Path("/nonexistent"), PIECE_SIZE_256KB, "test")

    def test_add_magnet(self, backend, tmp_path):
        magnet = (
            "magnet:?"
            "xt=urn:btih:0123456789abcdef0123456789abcdef01234567"
            "&xt=urn:btmh:1220" + "0" * 64
            + "&dn=test"
        )

        info_hash = backend.add_magnet(magnet, tmp_path)

        assert info_hash is not None
        assert backend.get_status(info_hash) == TorrentStatus.METADATA

    def test_add_torrent(self, backend, tmp_path, test_dir):
        # First create a torrent
        metadata = backend.create_torrent(test_dir, PIECE_SIZE_256KB, "test")

        # Then add it again (simulating receiving metadata)
        new_hash = backend.add_torrent(metadata, tmp_path)

        assert new_hash == metadata.info_hash
        assert backend.get_status(new_hash) == TorrentStatus.DOWNLOADING

    def test_remove_torrent(self, backend, test_dir):
        metadata = backend.create_torrent(test_dir, PIECE_SIZE_256KB, "test")

        result = backend.remove_torrent(metadata.info_hash)
        assert result is True

        # Should no longer exist
        assert backend.get_status(metadata.info_hash) is None
        assert backend.remove_torrent(metadata.info_hash) is False

    def test_pause_resume(self, backend, tmp_path):
        magnet = "magnet:?xt=urn:btih:" + "0" * 40
        info_hash = backend.add_magnet(magnet, tmp_path)

        # Change to downloading first
        backend._torrent_status[info_hash] = TorrentStatus.DOWNLOADING

        # Pause
        backend.pause(info_hash)
        assert backend.get_status(info_hash) == TorrentStatus.PAUSED

        # Resume
        backend.resume(info_hash)
        assert backend.get_status(info_hash) == TorrentStatus.DOWNLOADING

    def test_get_stats(self, backend, test_dir):
        metadata = backend.create_torrent(test_dir, PIECE_SIZE_256KB, "test")

        stats = backend.get_stats(metadata.info_hash)

        assert stats is not None
        assert stats.total_size == metadata.total_size
        assert stats.total_pieces > 0


class TestPieceOperations:
    """Tests for piece reading and verification."""

    @pytest.fixture
    def backend_with_content(self, tmp_path):
        backend = RealBitTorrentBackend(download_dir=tmp_path)

        # Create test directory with known content
        content_dir = tmp_path / "content"
        content_dir.mkdir()

        # Create files with known data
        file1_data = b"A" * 1000
        file2_data = b"B" * 500

        (content_dir / "file1.bin").write_bytes(file1_data)
        (content_dir / "file2.bin").write_bytes(file2_data)

        # Use 0 for piece_length to auto-select per RFC Section 12
        # For small files (<1GB), this will be 256KB
        metadata = backend.create_torrent(
            source_dir=content_dir,
            piece_length=0,  # Auto-select per RFC 12
            name="test_pieces"
        )

        return backend, metadata, content_dir

    def test_get_piece_single_file(self, backend_with_content):
        backend, metadata, content_dir = backend_with_content

        # Get first piece
        piece_data = backend.get_piece(metadata.info_hash, 0)

        assert piece_data is not None
        # First piece should start with 'A's (from file1)
        assert piece_data[0:1] == b"A"

    def test_get_piece_nonexistent(self, backend_with_content):
        backend, metadata, _ = backend_with_content

        # Get piece that doesn't exist
        piece_data = backend.get_piece(metadata.info_hash, 9999)
        assert piece_data is None

    def test_verify_piece_v2(self, backend_with_content):
        backend, metadata, _ = backend_with_content

        # Get piece and verify
        piece_data = backend.get_piece(metadata.info_hash, 0)
        assert piece_data is not None

        result = backend.verify_piece(metadata.info_hash, 0, piece_data)
        assert result is True

    def test_verify_piece_corrupted(self, backend_with_content):
        backend, metadata, _ = backend_with_content

        # Get piece and corrupt it
        piece_data = backend.get_piece(metadata.info_hash, 0)
        assert piece_data is not None

        corrupted = bytes([b ^ 0xFF for b in piece_data])
        result = backend.verify_piece(metadata.info_hash, 0, corrupted)
        assert result is False

    def test_verify_piece_v1_fallback(self, backend_with_content):
        backend, metadata, _ = backend_with_content

        # Clear v2 hashes to force v1 fallback
        metadata.piece_hashes_v2 = []

        piece_data = backend.get_piece(metadata.info_hash, 0)
        assert piece_data is not None

        # Should still verify with v1 hashes
        result = backend.verify_piece(metadata.info_hash, 0, piece_data)
        assert result is True


class TestFilePieceMapping:
    """Tests for piece-to-file mapping."""

    @pytest.fixture
    def multi_file_backend(self, tmp_path):
        backend = RealBitTorrentBackend()

        # Create files that span multiple pieces
        content_dir = tmp_path / "multi"
        content_dir.mkdir()

        # RFC Section 12: <1GB uses 256KB pieces
        # Use piece_length=0 to auto-select per RFC 12
        piece_size = 256 * 1024  # 256KB per RFC 12 for <1GB

        # File 1: Exactly 1.5 pieces
        (content_dir / "a.bin").write_bytes(b"A" * int(piece_size * 1.5))

        # File 2: Exactly 0.5 pieces
        (content_dir / "b.bin").write_bytes(b"B" * int(piece_size * 0.5))

        # File 3: 2 pieces
        (content_dir / "c.bin").write_bytes(b"C" * (piece_size * 2))

        # Use 0 for piece_length to auto-select per RFC Section 12
        metadata = backend.create_torrent(
            source_dir=content_dir,
            piece_length=0,  # Auto-select per RFC 12
            name="multi_file"
        )

        return backend, metadata

    def test_mapping_returns_list(self, multi_file_backend):
        backend, metadata = multi_file_backend

        mappings = backend.get_file_piece_mapping(metadata.info_hash)

        assert isinstance(mappings, list)
        assert len(mappings) > 0

    def test_mapping_covers_all_pieces(self, multi_file_backend):
        backend, metadata = multi_file_backend

        mappings = backend.get_file_piece_mapping(metadata.info_hash)
        num_pieces = (metadata.total_size + metadata.piece_length - 1) // metadata.piece_length

        assert len(mappings) == num_pieces

    def test_piece_mapping_structure(self, multi_file_backend):
        backend, metadata = multi_file_backend

        mappings = backend.get_file_piece_mapping(metadata.info_hash)

        for piece_idx, piece_mappings in enumerate(mappings):
            for mapping in piece_mappings:
                assert isinstance(mapping, PieceMapping)
                assert mapping.piece_index == piece_idx
                assert mapping.length > 0


class TestGetBackend:
    """Tests for backend factory function."""

    def test_returns_backend(self, tmp_path):
        backend = get_backend(tmp_path)
        assert isinstance(backend, RealBitTorrentBackend)

    def test_creates_torrent(self, tmp_path):
        backend = get_backend(tmp_path)

        # Create a simple file
        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "test.txt").write_text("test content")

        # Use 0 for piece_length to auto-select per RFC Section 12
        metadata = backend.create_torrent(content_dir, 0, "test")
        assert metadata.info_hash is not None
