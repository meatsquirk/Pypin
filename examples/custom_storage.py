"""Custom storage backend example using an in-memory dict."""

from __future__ import annotations

from typing import Dict

from dcpp_python.storage.base import StorageBackend, StorageStats


class DictStorage(StorageBackend):
    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, bytes]] = {}

    def store(self, collection_id: str, cid: str, data: bytes) -> bool:
        if not self.verify_content(cid, data):
            return False
        self._data.setdefault(collection_id, {})[cid] = data
        return True

    def retrieve(self, collection_id: str, cid: str) -> bytes | None:
        return self._data.get(collection_id, {}).get(cid)

    def delete(self, collection_id: str, cid: str) -> bool:
        if collection_id not in self._data:
            return False
        return self._data[collection_id].pop(cid, None) is not None

    def list_items(self, collection_id: str) -> list[str]:
        return sorted(self._data.get(collection_id, {}).keys())

    def get_stats(self) -> StorageStats:
        total_items = sum(len(items) for items in self._data.values())
        total_size = sum(len(value) for items in self._data.values() for value in items.values())
        return StorageStats(total_items=total_items, total_size_bytes=total_size, collections=len(self._data))


def main() -> None:
    storage = DictStorage()
    cid, stored = storage.store_verified("example:collection", b"custom storage payload")
    print(f"Stored: {stored} (cid={cid})")
    print(f"Items: {storage.list_items('example:collection')}")
    print(f"Stats: {storage.get_stats()}")


if __name__ == "__main__":
    main()
