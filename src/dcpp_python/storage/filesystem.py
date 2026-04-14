"""File-system storage backend."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from pathlib import Path
from typing import Iterator, Tuple, cast

from .base import StorageBackend, StorageStats, logger
from .interfaces import CollectionMetadataPayload

class FileSystemStorage(StorageBackend):
    """
    File-system based storage backend.

    Directory structure:
        {base_path}/
            {collection_id}/
                items/
                    {cid_prefix}/{cid}
                metadata.json
                shards/
                    {shard_id}/
                        items.json
    """

    def __init__(self, base_path: Path | str):
        """
        Initialize file-system storage.

        Args:
            base_path: Base directory for storage
        """
        self.base_path = Path(base_path).expanduser().resolve()
        self.base_path.mkdir(parents=True, exist_ok=True)

    def _collection_path(self, collection_id: str) -> Path:
        """Get path for a collection."""
        safe_id = self._sanitize_collection_id(collection_id)
        return self.base_path / safe_id

    def _sanitize_collection_id(self, collection_id: str) -> str:
        """
        Sanitize collection_id for filesystem use.

        Prefer readable IDs when safe; fall back to a stable hash if unsafe.
        """
        if not collection_id:
            raise ValueError("collection_id must be non-empty")

        # Whitelist common characters and forbid traversal segments explicitly.
        if re.fullmatch(r"[A-Za-z0-9._:-]+", collection_id) and ".." not in collection_id:
            return collection_id.replace(":", "_")

        digest = hashlib.sha256(collection_id.encode("utf-8")).hexdigest()
        return f"collection_{digest}"

    def _item_path(self, collection_id: str, cid: str) -> Path:
        """Get path for an item."""
        collection_path = self._collection_path(collection_id)
        # Use first 2 chars of CID as prefix for sharding
        prefix = cid[:2] if len(cid) >= 2 else "00"
        return collection_path / "items" / prefix / cid

    def _shard_path(self, collection_id: str, shard_id: int) -> Path:
        """Get path for shard metadata."""
        return self._collection_path(collection_id) / "shards" / str(shard_id)

    def _verify_cid(self, cid: str, data: bytes) -> bool:
        """
        Verify content matches CID.

        Uses proper CIDv1 parsing and SHA-256 verification per RFC Section 3.3.

        Args:
            cid: Content identifier (CIDv1 base32)
            data: Content bytes

        Returns:
            True if content matches CID
        """
        return self.verify_content(cid, data)

    def store(self, collection_id: str, cid: str, data: bytes) -> bool:
        """Store content with CID verification."""
        if not self._verify_cid(cid, data):
            return False

        item_path = self._item_path(collection_id, cid)
        item_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            item_path.write_bytes(data)
            return True
        except OSError:
            return False

    def retrieve(self, collection_id: str, cid: str) -> bytes | None:
        """Retrieve content by CID."""
        item_path = self._item_path(collection_id, cid)
        if not item_path.exists():
            return None

        try:
            return item_path.read_bytes()
        except OSError:
            return None

    def retrieve_range(
        self, collection_id: str, cid: str, offset: int, length: int
    ) -> bytes | None:
        """
        Retrieve a range of content (for health probes).

        Args:
            collection_id: Collection ID
            cid: Content identifier
            offset: Start offset in bytes
            length: Number of bytes to read

        Returns:
            Requested bytes or None if not available
        """
        item_path = self._item_path(collection_id, cid)
        if not item_path.exists():
            return None

        try:
            with open(item_path, "rb") as f:
                f.seek(offset)
                return f.read(length)
        except OSError:
            return None

    def exists(self, collection_id: str, cid: str) -> bool:
        """Check if content exists."""
        return self._item_path(collection_id, cid).exists()

    def delete(self, collection_id: str, cid: str) -> bool:
        """Delete content."""
        item_path = self._item_path(collection_id, cid)
        if not item_path.exists():
            return False

        try:
            item_path.unlink()
            return True
        except OSError:
            return False

    def list_items(self, collection_id: str) -> list[str]:
        """List all CIDs in a collection."""
        items_path = self._collection_path(collection_id) / "items"
        if not items_path.exists():
            return []

        cids = []
        for prefix_dir in items_path.iterdir():
            if prefix_dir.is_dir():
                for item_file in prefix_dir.iterdir():
                    if item_file.is_file():
                        cids.append(item_file.name)
        return cids

    def get_item_size(self, collection_id: str, cid: str) -> int | None:
        """Get size of an item in bytes."""
        item_path = self._item_path(collection_id, cid)
        if not item_path.exists():
            return None
        return item_path.stat().st_size

    def get_stats(self) -> StorageStats:
        """Get storage statistics."""
        stats = StorageStats()

        if not self.base_path.exists():
            return stats

        for collection_dir in self.base_path.iterdir():
            if not collection_dir.is_dir():
                continue

            stats.collections += 1
            items_path = collection_dir / "items"

            if items_path.exists():
                for prefix_dir in items_path.iterdir():
                    if prefix_dir.is_dir():
                        for item_file in prefix_dir.iterdir():
                            if item_file.is_file():
                                stats.total_items += 1
                                stats.total_size_bytes += item_file.stat().st_size

        return stats

    def collection_exists(self, collection_id: str) -> bool:
        """Check if a collection exists."""
        return self._collection_path(collection_id).exists()

    def create_collection(
        self, collection_id: str, metadata: CollectionMetadataPayload | None = None
    ) -> bool:
        """
        Create a new collection directory structure.

        Args:
            collection_id: Collection ID
            metadata: Optional metadata to store

        Returns:
            True if created successfully
        """
        collection_path = self._collection_path(collection_id)
        if collection_path.exists():
            return False

        try:
            (collection_path / "items").mkdir(parents=True)
            (collection_path / "shards").mkdir(parents=True)

            if metadata:
                metadata_path = collection_path / "metadata.json"
                metadata_path.write_text(json.dumps(metadata, indent=2))

            return True
        except OSError:
            return False

    def delete_collection(self, collection_id: str) -> bool:
        """Delete an entire collection."""
        collection_path = self._collection_path(collection_id)
        if not collection_path.exists():
            return False

        try:
            shutil.rmtree(collection_path)
            return True
        except OSError:
            return False

    def get_collection_metadata(
        self, collection_id: str
    ) -> CollectionMetadataPayload | None:
        """Get collection metadata."""
        metadata_path = self._collection_path(collection_id) / "metadata.json"
        if not metadata_path.exists():
            return None

        try:
            return cast(CollectionMetadataPayload, json.loads(metadata_path.read_text()))
        except (OSError, json.JSONDecodeError):
            return None

    def set_collection_metadata(
        self, collection_id: str, metadata: CollectionMetadataPayload
    ) -> bool:
        """Set collection metadata."""
        collection_path = self._collection_path(collection_id)
        if not collection_path.exists():
            return False

        try:
            metadata_path = collection_path / "metadata.json"
            metadata_path.write_text(json.dumps(metadata, indent=2))
            return True
        except OSError:
            return False

    # Shard management

    def store_shard_manifest(self, collection_id: str, shard_id: int, items: list[str]) -> bool:
        """
        Store the manifest of items in a shard.

        Args:
            collection_id: Collection ID
            shard_id: Shard index
            items: List of CIDs in the shard

        Returns:
            True if stored successfully
        """
        shard_path = self._shard_path(collection_id, shard_id)
        shard_path.mkdir(parents=True, exist_ok=True)

        try:
            items_file = shard_path / "items.json"
            items_file.write_text(json.dumps(items, indent=2))
            return True
        except OSError:
            return False

    def get_shard_items(self, collection_id: str, shard_id: int) -> list[str] | None:
        """Get list of CIDs in a shard."""
        items_file = self._shard_path(collection_id, shard_id) / "items.json"
        if not items_file.exists():
            return None

        try:
            return cast(list[str], json.loads(items_file.read_text()))
        except (OSError, json.JSONDecodeError):
            return None

    def calculate_coverage(self, collection_id: str, total_items: int) -> float:
        """
        Calculate coverage ratio for a collection.

        Args:
            collection_id: Collection ID
            total_items: Total items expected in collection

        Returns:
            Coverage ratio (0.0 to 1.0)
        """
        if total_items == 0:
            return 0.0

        stored = len(self.list_items(collection_id))
        return min(1.0, stored / total_items)

    def iter_items(self, collection_id: str) -> Iterator[tuple[str, bytes]]:
        """
        Iterate over all items in a collection.

        Yields:
            Tuple of (cid, data)
        """
        for cid in self.list_items(collection_id):
            data = self.retrieve(collection_id, cid)
            if data is not None:
                yield cid, data
