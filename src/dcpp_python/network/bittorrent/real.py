"""
BitTorrent Backend Implementation for Python

This module provides a BitTorrent backend for DCPP with hybrid v1+v2 (BEP 52)
support for local torrent operations.

IMPORTANT - Implementation Status:
    - Torrent creation: REQUIRES TORF for spec-compliant v2 info hash
    - Piece reading: FULLY FUNCTIONAL - Reads pieces from disk
    - Piece verification: FULLY FUNCTIONAL - SHA-1 and SHA-256 verification
    - Network operations: NOT IMPLEMENTED - No actual BitTorrent peer connections

What works (no external dependencies):
    - get_piece() - Reads piece data from local disk
    - verify_piece() - Verifies pieces with SHA-1 (v1) and SHA-256 (v2)
    - Piece-to-file mapping for multi-file torrents
    - Local-only torrent metadata (non-compliant info hashes)

What requires torf library:
    - create_torrent() - BEP 52 compliant v2 info hash (bencoded info dict)
    - Proper magnet URI generation with spec-compliant btih/btmh

What requires additional libraries (libtorrent):
    - Downloading torrents from peers
    - Seeding to peers
    - DHT/tracker announcements
    - Peer discovery and connection

Environment Variables:
    DCPP_BT_ALLOW_LOCAL: Set to "1" to allow non-compliant local-only
                        torrent creation without torf. Default is "0"
                        which requires torf for create_torrent().

To upgrade to full BitTorrent networking:
    1. Install torf for BEP 52 compliant torrent creation: pip install torf>=4.0.0
    2. Install python-libtorrent for peer networking
    3. Implement download/upload in subclass

Features:
- Hybrid v1+v2 torrent creation (BEP 52) - requires torf
- SHA-1 piece hashes for v1 compatibility
- SHA-256 piece hashes for v2 integrity
- Piece-to-file mapping for multi-file torrents
- Constant-time piece verification

RFC Section 12 Requirements:
- BitTorrent v2 protocol (BEP 52) for SHA-256 piece integrity
- Hybrid v1+v2 torrents for compatibility
- Piece sizes: <1GB -> 256KB, 1-10GB -> 1MB, >10GB -> 4MB

BEP 52 Compliance Note:
The v2 info hash MUST be the SHA-256 of the bencoded info dictionary,
NOT a hash of concatenated piece hashes. This is critical for interop
with the BitTorrent network. Without torf, created torrents will NOT
be compatible with other BitTorrent clients.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from dcpp_python.network.bittorrent.base import (
    BitTorrentBackend,
    TorrentMetadata,
    TorrentFile,
    TorrentStatus,
    TorrentStats,
    MIN_PIECE_SIZE,
    MAX_PIECE_SIZE,
)

logger = logging.getLogger("dcpp.bittorrent_real")


def _compute_piece_hashes_sha1_streaming(
    source_dir: Path,
    files: List[TorrentFile],
    piece_length: int,
) -> List[bytes]:
    """Compute SHA-1 piece hashes without buffering all data in memory."""
    if piece_length <= 0:
        return []

    piece_hashes: List[bytes] = []
    piece_buffer = bytearray()
    read_chunk_size = 1024 * 1024

    for file in files:
        file_path = source_dir / file.path
        if not file_path.exists():
            continue
        with open(file_path, "rb") as handle:
            while True:
                chunk = handle.read(read_chunk_size)
                if not chunk:
                    break
                piece_buffer.extend(chunk)
                while len(piece_buffer) >= piece_length:
                    piece_data = bytes(piece_buffer[:piece_length])
                    del piece_buffer[:piece_length]
                    piece_hashes.append(hashlib.sha1(piece_data).digest())

    if piece_buffer:
        piece_hashes.append(hashlib.sha1(bytes(piece_buffer)).digest())

    return piece_hashes


def is_local_only_allowed() -> bool:
    """
    Check if local-only (non-compliant) torrent creation is allowed.

    Returns True if DCPP_BT_ALLOW_LOCAL environment variable is set to "1".
    Default is False to require torf for spec-compliant torrents.
    """
    return os.environ.get("DCPP_BT_ALLOW_LOCAL", "0") == "1"


# BEP 52 constants
PIECE_SIZE_256KB = 256 * 1024
PIECE_SIZE_1MB = 1024 * 1024
PIECE_SIZE_4MB = 4 * 1024 * 1024


def recommended_piece_length_bep52(total_size: int) -> int:
    """
    Calculate optimal piece length per DCPP RFC Section 12.

    Piece sizes:
    - <1GB: 256 KB
    - 1-10GB: 1 MB
    - >10GB: 4 MB

    Args:
        total_size: Total content size in bytes

    Returns:
        Recommended piece length
    """
    one_gb = 1024 * 1024 * 1024
    ten_gb = 10 * one_gb

    if total_size < one_gb:
        return PIECE_SIZE_256KB
    elif total_size < ten_gb:
        return PIECE_SIZE_1MB
    else:
        return PIECE_SIZE_4MB


def validate_piece_length_rfc12(piece_length: int, total_size: int) -> None:
    """
    Validate that piece length matches RFC Section 12 requirements.

    Per RFC Section 12, piece sizes MUST be:
    - <1GB: 256 KB
    - 1-10GB: 1 MB
    - >10GB: 4 MB

    Args:
        piece_length: Requested piece length in bytes
        total_size: Total content size in bytes

    Raises:
        ValueError: If piece_length doesn't match RFC 12 requirements
    """
    required_length = recommended_piece_length_bep52(total_size)

    if piece_length != required_length:
        one_gb = 1024 * 1024 * 1024
        ten_gb = 10 * one_gb

        if total_size < one_gb:
            size_band = "<1GB"
        elif total_size < ten_gb:
            size_band = "1-10GB"
        else:
            size_band = ">10GB"

        raise ValueError(
            f"Piece length {piece_length} bytes does not match RFC Section 12 requirements. "
            f"For content size {total_size} bytes ({size_band}), "
            f"piece length MUST be {required_length} bytes ({required_length // 1024}KB). "
            f"RFC Section 12 mandates: <1GB->256KB, 1-10GB->1MB, >10GB->4MB."
        )


@dataclass
class HybridTorrentMetadata(TorrentMetadata):
    """
    Extended torrent metadata with hybrid v1+v2 support.

    Adds:
    - info_hash_v1: 20-byte SHA-1 info hash for v1 compatibility
    - piece_hashes_v1: SHA-1 piece hashes for v1
    - piece_hashes_v2: SHA-256 piece hashes for v2
    """

    info_hash_v1: bytes = b""  # 20-byte SHA-1 hash
    piece_hashes_v1: List[bytes] = field(default_factory=list)  # SHA-1 per piece
    piece_hashes_v2: List[bytes] = field(default_factory=list)  # SHA-256 per piece


@dataclass
class PieceMapping:
    """Mapping from piece index to file regions."""

    piece_index: int
    piece_offset: int  # Offset within piece
    file_path: Path
    file_offset: int  # Offset within file
    length: int  # Bytes from this file


class RealBitTorrentBackend(BitTorrentBackend):
    """
    Real BitTorrent backend with hybrid v1+v2 support.

    This implementation creates proper torrents with both SHA-1 (v1)
    and SHA-256 (v2) piece hashes for maximum compatibility.
    """

    def __init__(self, download_dir: Optional[Path] = None):
        """
        Initialize the BitTorrent backend.

        Args:
            download_dir: Default download directory
        """
        self._download_dir = download_dir or Path.cwd()
        self._torrents: Dict[bytes, HybridTorrentMetadata] = {}
        self._torrent_status: Dict[bytes, TorrentStatus] = {}
        self._torrent_stats: Dict[bytes, TorrentStats] = {}
        self._torrent_dirs: Dict[bytes, Path] = {}  # info_hash -> source dir
        self._piece_data: Dict[bytes, Dict[int, bytes]] = {}  # info_hash -> piece_index -> data

    def create_torrent(self, source_dir: Path, piece_length: int, name: str) -> TorrentMetadata:
        """
        Create a hybrid v1+v2 torrent from a directory.

        IMPORTANT: This method creates NON-COMPLIANT torrent metadata that will
        NOT work with the BitTorrent network. The info hashes are computed from
        hash(pieces+name) instead of the bencoded info dictionary per BEP 52.

        For spec-compliant torrents, use TorfBackend which requires torf>=4.0.0.

        Per RFC Section 12 and BEP 52:
        - v2 info hash MUST be SHA-256 of bencoded info dictionary
        - v1 info hash MUST be SHA-1 of bencoded info dictionary
        - This implementation does NOT produce compliant hashes

        Args:
            source_dir: Directory containing files
            piece_length: Piece length in bytes
            name: Torrent name

        Returns:
            HybridTorrentMetadata with both v1 and v2 info (LOCAL-ONLY)

        Raises:
            ImportError: If torf is not installed and DCPP_BT_ALLOW_LOCAL != "1"
        """
        # Check if we should fail without torf
        if not is_local_only_allowed():
            raise ImportError(
                "BEP 52 compliant torrent creation requires torf library. "
                "Install with: pip install torf>=4.0.0\n"
                "Or set DCPP_BT_ALLOW_LOCAL=1 for local-only testing (NON-COMPLIANT).\n"
                "See RFC Section 12 and BEP 52 for info hash requirements."
            )

        logger.warning(
            "Creating LOCAL-ONLY torrent with non-compliant info hashes. "
            "These torrents will NOT work with the BitTorrent network. "
            "Install torf>=4.0.0 for spec-compliant torrents."
        )

        source_dir = Path(source_dir).resolve()
        if not source_dir.exists():
            raise ValueError(f"Source directory does not exist: {source_dir}")

        # Collect files
        files: List[TorrentFile] = []
        total_size = 0

        for root, _, filenames in os.walk(source_dir):
            for filename in sorted(filenames):
                file_path = Path(root) / filename
                if file_path.is_file():
                    rel_path = file_path.relative_to(source_dir)
                    file_size = file_path.stat().st_size
                    files.append(
                        TorrentFile(
                            path=rel_path,
                            size=file_size,
                        )
                    )
                    total_size += file_size

        if not files:
            raise ValueError("No files found in source directory")

        # Determine piece length per RFC Section 12
        if piece_length < MIN_PIECE_SIZE or piece_length == 0:
            # Auto-select based on RFC Section 12 bands
            piece_length = recommended_piece_length_bep52(total_size)
        else:
            # Validate caller-specified piece_length matches RFC Section 12
            validate_piece_length_rfc12(piece_length, total_size)

        # Calculate pieces and hashes
        num_pieces = (total_size + piece_length - 1) // piece_length
        piece_hashes_v1: List[bytes] = []  # SHA-1
        piece_hashes_v2: List[bytes] = []  # SHA-256

        # Stream file data and compute piece hashes without buffering all data
        piece_buffer = bytearray()
        read_chunk_size = 1024 * 1024

        for file in files:
            file_path = source_dir / file.path
            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(read_chunk_size)
                    if not chunk:
                        break
                    piece_buffer.extend(chunk)

                    while len(piece_buffer) >= piece_length:
                        piece_data = bytes(piece_buffer[:piece_length])
                        del piece_buffer[:piece_length]

                        # SHA-1 for v1
                        sha1_hash = hashlib.sha1(piece_data).digest()
                        piece_hashes_v1.append(sha1_hash)

                        # SHA-256 for v2
                        sha256_hash = hashlib.sha256(piece_data).digest()
                        piece_hashes_v2.append(sha256_hash)

        if piece_buffer:
            piece_data = bytes(piece_buffer)

            # SHA-1 for v1
            sha1_hash = hashlib.sha1(piece_data).digest()
            piece_hashes_v1.append(sha1_hash)

            # SHA-256 for v2
            sha256_hash = hashlib.sha256(piece_data).digest()
            piece_hashes_v2.append(sha256_hash)

        # WARNING: These info hashes are NON-COMPLIANT with BEP 52!
        # BEP 52 requires: info_hash = sha256(bencode(info_dict))
        # We're using: info_hash = sha256(pieces + name) - WRONG!
        # This is for LOCAL TESTING ONLY

        # v1 info hash: SHA-1 (NON-COMPLIANT - should be bencoded info dict)
        v1_info_data = b"".join(piece_hashes_v1) + name.encode("utf-8")
        info_hash_v1 = hashlib.sha1(v1_info_data).digest()

        # v2 info hash: SHA-256 (NON-COMPLIANT - should be bencoded info dict)
        v2_info_data = b"".join(piece_hashes_v2) + name.encode("utf-8")
        info_hash_v2 = hashlib.sha256(v2_info_data).digest()

        # Generate hybrid magnet URI (NON-COMPLIANT hashes!)
        # Format: magnet:?xt=urn:btih:{v1}&xt=urn:btmh:1220{v2}&dn={name}
        magnet_parts = [
            f"xt=urn:btih:{info_hash_v1.hex()}",
            f"xt=urn:btmh:1220{info_hash_v2.hex()}",
            f"dn={urllib.parse.quote(name)}",
        ]
        magnet_uri = "magnet:?" + "&".join(magnet_parts)

        metadata = HybridTorrentMetadata(
            info_hash=info_hash_v2,  # Primary is v2
            info_hash_v1=info_hash_v1,
            piece_length=piece_length,
            files=files,
            total_size=total_size,
            magnet_uri=magnet_uri,
            piece_hashes_v1=piece_hashes_v1,
            piece_hashes_v2=piece_hashes_v2,
        )

        # Store torrent internally
        self._torrents[info_hash_v2] = metadata
        self._torrent_status[info_hash_v2] = TorrentStatus.SEEDING
        self._torrent_stats[info_hash_v2] = TorrentStats(
            total_size=total_size,
            downloaded=total_size,
            total_pieces=num_pieces,
            have_pieces=num_pieces,
        )
        self._torrent_dirs[info_hash_v2] = source_dir

        logger.info(
            f"Created LOCAL-ONLY torrent: {name} ({num_pieces} pieces, {total_size} bytes) "
            "[NON-COMPLIANT info hashes]"
        )
        return metadata

    def add_magnet(self, magnet_uri: str, download_dir: Path) -> bytes:
        """
        Add a torrent by magnet URI.

        Args:
            magnet_uri: Magnet URI
            download_dir: Download directory

        Returns:
            Info hash (v2 if available, else v1)
        """
        # Parse magnet URI to extract info hashes
        info_hash_v1 = None
        info_hash_v2 = None
        for part in magnet_uri.replace("magnet:?", "").split("&"):
            if "=" in part:
                key, value = part.split("=", 1)
                if key == "xt":
                    if value.startswith("urn:btih:"):
                        info_hash_v1 = bytes.fromhex(value[9:49])
                    elif value.startswith("urn:btmh:1220"):
                        info_hash_v2 = bytes.fromhex(value[13:])
                elif key == "dn":
                    pass

        # Prefer v2 hash
        info_hash = info_hash_v2 or info_hash_v1
        if not info_hash:
            raise ValueError("No valid info hash found in magnet URI")

        # Create placeholder metadata
        metadata = HybridTorrentMetadata(
            info_hash=info_hash,
            info_hash_v1=info_hash_v1 or b"",
            piece_length=PIECE_SIZE_256KB,
            files=[],
            total_size=0,
            magnet_uri=magnet_uri,
        )

        self._torrents[info_hash] = metadata
        self._torrent_status[info_hash] = TorrentStatus.METADATA
        self._torrent_stats[info_hash] = TorrentStats()
        self._torrent_dirs[info_hash] = download_dir

        return info_hash

    def add_torrent(self, metadata: TorrentMetadata, download_dir: Path) -> bytes:
        """Add a torrent from metadata."""
        info_hash = metadata.info_hash

        # Convert to hybrid if needed
        if isinstance(metadata, HybridTorrentMetadata):
            self._torrents[info_hash] = metadata
        else:
            self._torrents[info_hash] = HybridTorrentMetadata(
                info_hash=metadata.info_hash,
                piece_length=metadata.piece_length,
                files=metadata.files,
                total_size=metadata.total_size,
                magnet_uri=metadata.magnet_uri,
            )

        self._torrent_status[info_hash] = TorrentStatus.DOWNLOADING
        self._torrent_stats[info_hash] = TorrentStats(
            total_size=metadata.total_size,
            total_pieces=len(getattr(metadata, "piece_hashes_v2", []))
            or (metadata.total_size + metadata.piece_length - 1) // metadata.piece_length,
        )
        self._torrent_dirs[info_hash] = download_dir

        return info_hash

    def remove_torrent(self, info_hash: bytes) -> bool:
        """Remove a torrent."""
        if info_hash not in self._torrents:
            return False

        del self._torrents[info_hash]
        self._torrent_status.pop(info_hash, None)
        self._torrent_stats.pop(info_hash, None)
        self._torrent_dirs.pop(info_hash, None)
        self._piece_data.pop(info_hash, None)

        return True

    def get_status(self, info_hash: bytes) -> Optional[TorrentStatus]:
        """Get torrent status."""
        return self._torrent_status.get(info_hash)

    def get_stats(self, info_hash: bytes) -> Optional[TorrentStats]:
        """Get torrent stats."""
        return self._torrent_stats.get(info_hash)

    def pause(self, info_hash: bytes) -> None:
        """Pause a torrent."""
        if info_hash in self._torrent_status:
            self._torrent_status[info_hash] = TorrentStatus.PAUSED

    def resume(self, info_hash: bytes) -> None:
        """Resume a torrent."""
        if info_hash in self._torrent_status:
            status = self._torrent_status[info_hash]
            if status == TorrentStatus.PAUSED:
                self._torrent_status[info_hash] = TorrentStatus.DOWNLOADING

    def get_piece(self, info_hash: bytes, piece_index: int) -> Optional[bytes]:
        """
        Get piece data from disk.

        Maps the piece index to file(s) and reads the corresponding bytes.

        Args:
            info_hash: Torrent info hash
            piece_index: Piece index (0-based)

        Returns:
            Piece data bytes, or None if not available
        """
        if info_hash not in self._torrents:
            return None

        metadata = self._torrents[info_hash]
        source_dir = self._torrent_dirs.get(info_hash)

        if not source_dir or not source_dir.exists():
            return None

        # Calculate piece offset in the concatenated file stream
        piece_start = piece_index * metadata.piece_length
        piece_end = min(piece_start + metadata.piece_length, metadata.total_size)
        piece_size = piece_end - piece_start

        if piece_size <= 0:
            return None

        # Map piece to files and read data
        piece_data = bytearray()
        current_pos = 0  # Position in concatenated stream
        bytes_read = 0

        for file in metadata.files:
            file_start = current_pos
            file_end = current_pos + file.size
            current_pos = file_end

            # Skip files before piece
            if file_end <= piece_start:
                continue

            # Stop if we've passed the piece
            if file_start >= piece_end:
                break

            # Calculate overlap with this file
            read_start = max(0, piece_start - file_start)
            read_end = min(file.size, piece_end - file_start)
            read_length = read_end - read_start

            if read_length <= 0:
                continue

            # Read from file
            file_path = source_dir / file.path
            try:
                with open(file_path, "rb") as f:
                    f.seek(read_start)
                    data = f.read(read_length)
                    piece_data.extend(data)
                    bytes_read += len(data)
            except (OSError, IOError) as e:
                logger.error(f"Error reading piece {piece_index} from {file_path}: {e}")
                return None

        if bytes_read != piece_size:
            logger.warning(f"Piece {piece_index}: expected {piece_size} bytes, got {bytes_read}")

        return bytes(piece_data)

    def verify_piece(self, info_hash: bytes, piece_index: int, data: bytes) -> bool:
        """
        Verify piece data against stored hashes.

        Supports both v1 (SHA-1) and v2 (SHA-256) verification.

        Args:
            info_hash: Torrent info hash
            piece_index: Piece index
            data: Piece data to verify

        Returns:
            True if piece is valid
        """
        if info_hash not in self._torrents:
            return False

        metadata = self._torrents[info_hash]

        # Try v2 verification first (SHA-256)
        if metadata.piece_hashes_v2 and piece_index < len(metadata.piece_hashes_v2):
            expected_hash = metadata.piece_hashes_v2[piece_index]
            actual_hash = hashlib.sha256(data).digest()
            if self._constant_time_compare(expected_hash, actual_hash):
                return True

        # Fall back to v1 verification (SHA-1)
        if metadata.piece_hashes_v1 and piece_index < len(metadata.piece_hashes_v1):
            expected_hash = metadata.piece_hashes_v1[piece_index]
            actual_hash = hashlib.sha1(data).digest()
            if self._constant_time_compare(expected_hash, actual_hash):
                return True

        return False

    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

    def get_file_piece_mapping(self, info_hash: bytes) -> List[List[PieceMapping]]:
        """
        Get the mapping of pieces to file regions.

        Useful for understanding which files contribute to which pieces.

        Args:
            info_hash: Torrent info hash

        Returns:
            List of piece mappings (one list per piece)
        """
        if info_hash not in self._torrents:
            return []

        metadata = self._torrents[info_hash]
        num_pieces = (metadata.total_size + metadata.piece_length - 1) // metadata.piece_length

        mappings: List[List[PieceMapping]] = [[] for _ in range(num_pieces)]
        current_pos = 0

        for file in metadata.files:
            file_start = current_pos
            file_end = current_pos + file.size
            current_pos = file_end

            # Find all pieces this file contributes to
            first_piece = file_start // metadata.piece_length
            last_piece = (file_end - 1) // metadata.piece_length if file_end > 0 else first_piece

            for piece_idx in range(first_piece, min(last_piece + 1, num_pieces)):
                piece_start = piece_idx * metadata.piece_length
                piece_end = min(piece_start + metadata.piece_length, metadata.total_size)

                # Calculate overlap
                overlap_start = max(file_start, piece_start)
                overlap_end = min(file_end, piece_end)

                if overlap_start < overlap_end:
                    mappings[piece_idx].append(
                        PieceMapping(
                            piece_index=piece_idx,
                            piece_offset=overlap_start - piece_start,
                            file_path=Path(file.path),
                            file_offset=overlap_start - file_start,
                            length=overlap_end - overlap_start,
                        )
                    )

        return mappings


# Minimum torf version required for BEP 52 compliance
MIN_TORF_VERSION = (4, 0, 0)


def _parse_version(version_str: str) -> tuple[int, int, int]:
    """Parse version string into tuple for comparison."""
    parts = version_str.split(".")
    result = []
    for part in parts[:3]:  # Only compare major.minor.patch
        # Handle versions like "4.0.0a1" by stripping non-numeric suffixes
        numeric = "".join(c for c in part if c.isdigit())
        result.append(int(numeric) if numeric else 0)
    while len(result) < 3:
        result.append(0)
    return (result[0], result[1], result[2])


# Try to use torf for BEP 52 compliant torrent creation
try:
    import torf

    # Validate minimum version requirement
    _torf_version = _parse_version(torf.__version__)
    if _torf_version < MIN_TORF_VERSION:
        raise ImportError(
            f"torf {torf.__version__} is below minimum required version "
            f"{'.'.join(str(v) for v in MIN_TORF_VERSION)}. "
            f"BEP 52 compliance requires torf>=4.0.0."
        )

    class TorfBackend(RealBitTorrentBackend):
        """
        BitTorrent backend using the torf library for BEP 52 compliance.

        This provides proper torrent file creation with correct bencoding,
        producing spec-compliant info hashes that work with the BitTorrent network.

        Per RFC Section 12 and BEP 52:
        - v2 info hash = SHA-256 of bencoded info dictionary
        - v1 info hash = SHA-1 of bencoded info dictionary
        - torf handles the bencoding correctly
        """

        def create_torrent(self, source_dir: Path, piece_length: int, name: str) -> TorrentMetadata:
            """
            Create a BEP 52 compliant hybrid v1+v2 torrent using torf.

            This method produces spec-compliant torrents that work with the
            BitTorrent network. The info hashes are computed from properly
            bencoded info dictionaries per BEP 52.

            Per RFC Section 12:
            - Piece sizes: <1GB -> 256KB, 1-10GB -> 1MB, >10GB -> 4MB
            - BitTorrent v2 protocol (BEP 52) for SHA-256 piece integrity

            Args:
                source_dir: Directory containing files
                piece_length: Piece length in bytes
                name: Torrent name

            Returns:
                HybridTorrentMetadata with BEP 52 compliant info hashes
            """
            source_dir = Path(source_dir).resolve()
            if not source_dir.exists():
                raise ValueError(f"Source directory does not exist: {source_dir}")

            # Calculate total size for RFC Section 12 validation
            total_size = sum(f.stat().st_size for f in source_dir.rglob("*") if f.is_file())

            # Determine piece length per RFC Section 12
            if piece_length < MIN_PIECE_SIZE or piece_length == 0:
                # Auto-select based on RFC Section 12 bands
                piece_length = recommended_piece_length_bep52(total_size)
            else:
                # Validate caller-specified piece_length matches RFC Section 12
                validate_piece_length_rfc12(piece_length, total_size)

            # Use torf for proper BEP 52 compliant torrent creation
            t = torf.Torrent(path=source_dir, name=name)
            t.piece_size = piece_length

            # Generate the torrent (computes hashes with proper bencoding)
            t.generate()

            # Extract file info
            files = []
            for file_path in t.files:
                # torf returns relative paths
                rel_path = Path(file_path)
                full_path = source_dir / rel_path
                file_size = full_path.stat().st_size if full_path.exists() else 0
                files.append(
                    TorrentFile(
                        path=rel_path,
                        size=file_size,
                    )
                )

            # Get BEP 52 compliant info hashes
            # torf computes these from properly bencoded info dictionaries
            info_hash_v2 = bytes.fromhex(t.infohash) if t.infohash else b""

            # v1 info hash (SHA-1 of bencoded info dict)
            # torf may provide this via infohash property for hybrid torrents
            info_hash_v1 = b""
            if hasattr(t, "infohash_base32") and t.infohash_base32:
                # Some torf versions expose v1 hash differently
                try:
                    # Try to get v1 hash if available
                    if hasattr(t, "infohash_v1"):
                        info_hash_v1 = bytes.fromhex(t.infohash_v1)
                except (AttributeError, ValueError):
                    pass

            # Piece hashes (SHA-1 for v1, stored in t.hashes)
            # Note: torf 4.x returns t.pieces as int (count), t.hashes as tuple of bytes
            piece_hashes_v2 = list(t.hashes) if t.hashes else []

            # Compute SHA-1 piece hashes for v1 compatibility without buffering all data
            piece_hashes_v1 = _compute_piece_hashes_sha1_streaming(
                source_dir=source_dir,
                files=files,
                piece_length=t.piece_size,
            )

            metadata = HybridTorrentMetadata(
                info_hash=info_hash_v2,
                info_hash_v1=info_hash_v1,
                piece_length=t.piece_size,
                files=files,
                total_size=t.size,
                magnet_uri=str(t.magnet()),
                piece_hashes_v1=piece_hashes_v1,
                piece_hashes_v2=piece_hashes_v2,
            )

            # Store
            self._torrents[info_hash_v2] = metadata
            self._torrent_status[info_hash_v2] = TorrentStatus.SEEDING
            self._torrent_stats[info_hash_v2] = TorrentStats(
                total_size=t.size,
                downloaded=t.size,
                total_pieces=len(piece_hashes_v2),
                have_pieces=len(piece_hashes_v2),
            )
            self._torrent_dirs[info_hash_v2] = source_dir

            logger.info(
                f"Created BEP 52 compliant torrent: {name} "
                f"({len(piece_hashes_v2)} pieces, {t.size} bytes)"
            )
            return metadata

    TORF_AVAILABLE = True
    logger.info(f"torf {torf.__version__} available - BEP 52 compliant torrent creation enabled")

except ImportError as e:
    TORF_AVAILABLE = False
    logger.debug(
        f"torf not available ({e}) - torrent creation requires DCPP_BT_ALLOW_LOCAL=1 "
        "or install torf>=4.0.0"
    )


def get_backend(download_dir: Optional[Path] = None) -> BitTorrentBackend:
    """
    Get the best available BitTorrent backend.

    Returns TorfBackend if torf is installed, else RealBitTorrentBackend.
    """
    if TORF_AVAILABLE:
        return TorfBackend(download_dir)
    return RealBitTorrentBackend(download_dir)
