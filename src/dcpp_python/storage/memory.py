"""In-memory storage backend."""

from __future__ import annotations

from .base import StorageBackend, StorageStats, logger

class MemoryStorage(StorageBackend):
    """
    In-memory storage backend for testing.

    Not persistent - data is lost when process exits.
    """

    def __init__(self) -> None:
        self._data: dict[str, dict[str, bytes]] = {}  # collection_id -> cid -> data

    def store(self, collection_id: str, cid: str, data: bytes) -> bool:
        if collection_id not in self._data:
            self._data[collection_id] = {}
        self._data[collection_id][cid] = data
        return True

    def retrieve(self, collection_id: str, cid: str) -> bytes | None:
        return self._data.get(collection_id, {}).get(cid)

    def exists(self, collection_id: str, cid: str) -> bool:
        return cid in self._data.get(collection_id, {})

    def delete(self, collection_id: str, cid: str) -> bool:
        if collection_id in self._data and cid in self._data[collection_id]:
            del self._data[collection_id][cid]
            return True
        return False

    def list_items(self, collection_id: str) -> list[str]:
        return list(self._data.get(collection_id, {}).keys())

    def get_stats(self) -> StorageStats:
        stats = StorageStats()
        stats.collections = len(self._data)
        for collection in self._data.values():
            stats.total_items += len(collection)
            stats.total_size_bytes += sum(len(data) for data in collection.values())
        return stats


# =============================================================================
# Genesis Storage (RFC Section 7.5)
# =============================================================================

from enum import Enum
import time
