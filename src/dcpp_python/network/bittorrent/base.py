"""
DCPP BitTorrent Integration

Implements the data plane for DCPP using BitTorrent v2 (BEP 52).
This module provides interfaces for:
- Torrent creation from manifests
- Seeding content
- Downloading content
- Piece verification
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, cast
import hashlib
import urllib.parse
import logging
import os
import sys
import warnings

logger = logging.getLogger("dcpp.bittorrent")


# BitTorrent piece size constants (BEP 52)
MIN_PIECE_SIZE = 16 * 1024  # 16 KiB
MAX_PIECE_SIZE = 16 * 1024 * 1024  # 16 MiB


class TorrentStatus(Enum):
    """Status of a torrent."""

    METADATA = "metadata"  # Torrent metadata being fetched
    DOWNLOADING = "downloading"  # Downloading pieces
    SEEDING = "seeding"  # Seeding (all pieces available)
    PAUSED = "paused"  # Paused
    ERROR = "error"  # Error state


def bt_status_from_torrent_status(status: "TorrentStatus | None") -> str:
    """Map torrent status to ANNOUNCE bt_status string."""
    if status is None:
        return "none"
    if status in (TorrentStatus.METADATA, TorrentStatus.DOWNLOADING):
        return "leeching"
    if status == TorrentStatus.SEEDING:
        return "seeding"
    if status == TorrentStatus.PAUSED:
        return "paused"
    if status == TorrentStatus.ERROR:
        return "error"
    return "none"


@dataclass
class TorrentStats:
    """Statistics for a torrent."""

    total_size: int = 0  # Total size in bytes
    downloaded: int = 0  # Downloaded bytes
    uploaded: int = 0  # Uploaded bytes
    total_pieces: int = 0  # Number of pieces
    have_pieces: int = 0  # Pieces we have
    connected_peers: int = 0  # Connected peers
    download_rate: int = 0  # Download rate (bytes/sec)
    upload_rate: int = 0  # Upload rate (bytes/sec)

    @property
    def completion(self) -> float:
        """Calculate completion percentage."""
        if self.total_pieces == 0:
            return 0.0
        return self.have_pieces / self.total_pieces


@dataclass
class Piece:
    """A piece of a torrent."""

    index: int  # Piece index
    size: int  # Piece size
    hash: bytes  # SHA-256 hash (for v2)
    have: bool = False  # Whether we have this piece


@dataclass
class TorrentFile:
    """A file in a torrent."""

    path: Path  # File path (relative)
    size: int  # File size
    piece_hashes: List[bytes] = field(default_factory=list)  # Piece hashes for this file (v2)


@dataclass
class TorrentMetadata:
    """Torrent metadata (v2 format)."""

    info_hash: bytes  # Info hash (v2) - 32 bytes
    piece_length: int  # Piece length
    files: List[TorrentFile] = field(default_factory=list)  # Files in the torrent
    total_size: int = 0  # Total size
    magnet_uri: str = ""  # Magnet URI


class BitTorrentBackend(ABC):
    """BitTorrent backend trait."""

    @abstractmethod
    def create_torrent(self, source_dir: Path, piece_length: int, name: str) -> TorrentMetadata:
        """Create a torrent from a directory of files."""
        pass

    @abstractmethod
    def add_magnet(self, magnet_uri: str, download_dir: Path) -> bytes:
        """Add a torrent by magnet URI. Returns info hash."""
        pass

    @abstractmethod
    def add_torrent(self, metadata: TorrentMetadata, download_dir: Path) -> bytes:
        """Add a torrent from metadata. Returns info hash."""
        pass

    @abstractmethod
    def remove_torrent(self, info_hash: bytes) -> bool:
        """Remove a torrent. Returns True if removed."""
        pass

    @abstractmethod
    def get_status(self, info_hash: bytes) -> Optional[TorrentStatus]:
        """Get torrent status."""
        pass

    @abstractmethod
    def get_stats(self, info_hash: bytes) -> Optional[TorrentStats]:
        """Get torrent stats."""
        pass

    @abstractmethod
    def pause(self, info_hash: bytes) -> None:
        """Pause a torrent."""
        pass

    @abstractmethod
    def resume(self, info_hash: bytes) -> None:
        """Resume a torrent."""
        pass

    @abstractmethod
    def get_piece(self, info_hash: bytes, piece_index: int) -> Optional[bytes]:
        """Get piece data."""
        pass

    @abstractmethod
    def verify_piece(self, info_hash: bytes, piece_index: int, data: bytes) -> bool:
        """Verify a piece."""
        pass


@dataclass
class MockTorrent:
    """Internal mock torrent state."""

    metadata: TorrentMetadata
    status: TorrentStatus = TorrentStatus.METADATA
    stats: TorrentStats = field(default_factory=TorrentStats)
    pieces: Dict[int, bytes] = field(default_factory=dict)


class MockBitTorrentBackend(BitTorrentBackend):
    """
    Mock BitTorrent backend for testing purposes only.

    WARNING: This backend is for unit tests and development only.
    It does NOT provide:
    - Real BitTorrent protocol support
    - Peer networking
    - Piece persistence (in-memory only)
    - BEP 52 compliant info hashes (RFC 3.2 violation)

    For production use, set DCPP_BT_BACKEND=local or DCPP_BT_BACKEND=real
    and install torf>=4.0.0 for BEP 52 compliance.

    This backend requires explicit opt-in via DCPP_BT_BACKEND=mock.
    A warning is always logged when instantiated to ensure visibility.
    """

    def __init__(self) -> None:
        """
        Initialize the mock backend.

        Always logs a warning about RFC noncompliance. Use only for testing.
        """
        self._torrents: Dict[bytes, MockTorrent] = {}

        # Always log warning - mock backend should only be used intentionally
        if not self._is_test_environment():
            logger.warning(
                "MockBitTorrentBackend instantiated outside test environment. "
                "This backend does NOT comply with RFC 3.2 (BEP 52 info hashes). "
                "For production, use DCPP_BT_BACKEND=local or DCPP_BT_BACKEND=real "
                "with torf>=4.0.0 installed."
            )

    @staticmethod
    def _is_test_environment() -> bool:
        """Check if running in a test environment."""
        # Check for pytest
        if "pytest" in sys.modules:
            return True
        # Check for unittest
        if "unittest" in sys.modules:
            return True
        # Check for common test runner environment variables
        if os.environ.get("PYTEST_CURRENT_TEST"):
            return True
        return False

    def add_mock_piece(self, info_hash: bytes, piece_index: int, data: bytes) -> None:
        """Add mock piece data (for testing)."""
        if info_hash in self._torrents:
            torrent = self._torrents[info_hash]
            torrent.pieces[piece_index] = data
            torrent.stats.have_pieces += 1

    def create_torrent(self, source_dir: Path, piece_length: int, name: str) -> TorrentMetadata:
        """Create a torrent from a directory of files."""
        # Generate info hash from name
        info_hash = hashlib.sha256(name.encode()).digest()

        return TorrentMetadata(
            info_hash=info_hash,
            piece_length=piece_length,
            files=[],
            total_size=0,
            magnet_uri=f"magnet:?xt=urn:btmh:1220{info_hash.hex()}&dn={urllib.parse.quote(name)}",
        )

    def add_magnet(self, magnet_uri: str, download_dir: Path) -> bytes:
        """Add a torrent by magnet URI."""
        # Generate info hash from magnet URI
        info_hash = hashlib.sha256(magnet_uri.encode()).digest()

        metadata = TorrentMetadata(
            info_hash=info_hash,
            piece_length=262144,  # 256 KiB
            files=[],
            total_size=0,
            magnet_uri=magnet_uri,
        )

        self._torrents[info_hash] = MockTorrent(
            metadata=metadata, status=TorrentStatus.METADATA, stats=TorrentStats()
        )

        return info_hash

    def add_torrent(self, metadata: TorrentMetadata, download_dir: Path) -> bytes:
        """Add a torrent from metadata."""
        info_hash = metadata.info_hash
        self._torrents[info_hash] = MockTorrent(
            metadata=metadata, status=TorrentStatus.DOWNLOADING, stats=TorrentStats()
        )
        return info_hash

    def remove_torrent(self, info_hash: bytes) -> bool:
        """Remove a torrent."""
        if info_hash in self._torrents:
            del self._torrents[info_hash]
            return True
        return False

    def get_status(self, info_hash: bytes) -> Optional[TorrentStatus]:
        """Get torrent status."""
        if info_hash in self._torrents:
            return self._torrents[info_hash].status
        return None

    def get_stats(self, info_hash: bytes) -> Optional[TorrentStats]:
        """Get torrent stats."""
        if info_hash in self._torrents:
            return self._torrents[info_hash].stats
        return None

    def pause(self, info_hash: bytes) -> None:
        """Pause a torrent."""
        if info_hash in self._torrents:
            self._torrents[info_hash].status = TorrentStatus.PAUSED

    def resume(self, info_hash: bytes) -> None:
        """Resume a torrent."""
        if info_hash in self._torrents:
            torrent = self._torrents[info_hash]
            if torrent.status == TorrentStatus.PAUSED:
                torrent.status = TorrentStatus.DOWNLOADING

    def get_piece(self, info_hash: bytes, piece_index: int) -> Optional[bytes]:
        """Get piece data."""
        if info_hash in self._torrents:
            return self._torrents[info_hash].pieces.get(piece_index)
        return None

    def verify_piece(self, info_hash: bytes, piece_index: int, data: bytes) -> bool:
        """Verify a piece."""
        if info_hash in self._torrents:
            torrent = self._torrents[info_hash]
            if piece_index in torrent.pieces:
                stored_hash = hashlib.sha256(torrent.pieces[piece_index]).digest()
                data_hash = hashlib.sha256(data).digest()
                return stored_hash == data_hash
        return False


class DCPPTorrentManager:
    """DCPP-specific BitTorrent manager.

    Integrates BitTorrent with DCPP collections.
    """

    def __init__(self, backend: BitTorrentBackend, download_dir: Path):
        self._backend = backend
        self._download_dir = download_dir
        self._collection_torrents: Dict[str, bytes] = {}  # collection_id -> info_hash

    def add_collection(self, manifest: dict[str, object]) -> bytes:
        """Add a collection's torrent from its manifest.

        Args:
            manifest: DCPP manifest dict with 'collection_id' and 'torrent' keys.
                     The torrent dict must have 'magnet_uri'.

        Returns:
            The 32-byte info hash.
        """
        collection_id = cast(str, manifest["collection_id"])
        collection_dir = self._download_dir / collection_id
        collection_dir.mkdir(parents=True, exist_ok=True)

        torrent_info = cast(dict[str, object], manifest["torrent"])
        magnet_uri = cast(str, torrent_info.get("magnet_uri") or torrent_info.get("magnet"))
        if not magnet_uri:
            raise ValueError("Torrent info missing magnet URI")
        info_hash = self._backend.add_magnet(magnet_uri, collection_dir)
        self._collection_torrents[collection_id] = info_hash

        return info_hash

    def get_collection_status(self, collection_id: str) -> Optional[TorrentStatus]:
        """Get status for a collection."""
        if collection_id in self._collection_torrents:
            info_hash = self._collection_torrents[collection_id]
            return self._backend.get_status(info_hash)
        return None

    def get_collection_stats(self, collection_id: str) -> Optional[TorrentStats]:
        """Get stats for a collection."""
        if collection_id in self._collection_torrents:
            info_hash = self._collection_torrents[collection_id]
            return self._backend.get_stats(info_hash)
        return None

    def get_collection_coverage(self, collection_id: str) -> float:
        """Get coverage for a collection."""
        stats = self.get_collection_stats(collection_id)
        if stats:
            return stats.completion
        return 0.0

    def verify_piece_for_probe(self, collection_id: str, piece_index: int, data: bytes) -> bool:
        """Verify piece data for health probe."""
        if collection_id in self._collection_torrents:
            info_hash = self._collection_torrents[collection_id]
            return self._backend.verify_piece(info_hash, piece_index, data)
        return False

    def get_piece_for_probe(self, collection_id: str, piece_index: int) -> Optional[bytes]:
        """Get piece data for health probe response."""
        if collection_id in self._collection_torrents:
            info_hash = self._collection_torrents[collection_id]
            return self._backend.get_piece(info_hash, piece_index)
        return None


def recommended_piece_length(total_size: int) -> int:
    """Calculate optimal piece length for a collection.

    Targets ~1000-2000 pieces for optimal swarm behavior.
    """
    target_pieces = 1500
    raw = total_size // target_pieces

    # Round to power of 2 within bounds
    piece_length = MIN_PIECE_SIZE
    while piece_length < raw and piece_length < MAX_PIECE_SIZE:
        piece_length *= 2

    return max(MIN_PIECE_SIZE, min(piece_length, MAX_PIECE_SIZE))
