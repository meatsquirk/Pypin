"""Storage interface protocols."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .base import StorageStats
from dcpp_python.manifest.manifest import ManifestPayload

CollectionMetadataPayload = ManifestPayload


@runtime_checkable
class StorageBackendProtocol(Protocol):
    """Structural interface for storage backends."""

    def store(self, collection_id: str, cid: str, data: bytes) -> bool:
        ...

    def retrieve(self, collection_id: str, cid: str) -> bytes | None:
        ...

    def exists(self, collection_id: str, cid: str) -> bool:
        ...

    def delete(self, collection_id: str, cid: str) -> bool:
        ...

    def list_items(self, collection_id: str) -> list[str]:
        ...

    def get_stats(self) -> StorageStats:
        ...

    def store_verified(self, collection_id: str, data: bytes) -> tuple[str, bool]:
        ...

    def retrieve_verified(self, collection_id: str, cid: str) -> bytes | None:
        ...

    def verify_content(self, cid: str, data: bytes) -> bool:
        ...


@runtime_checkable
class CollectionMetadataStorageProtocol(Protocol):
    """Interface for storage backends that persist collection metadata."""

    def collection_exists(self, collection_id: str) -> bool:
        ...

    def create_collection(
        self, collection_id: str, metadata: CollectionMetadataPayload | None = None
    ) -> bool:
        ...

    def get_collection_metadata(
        self, collection_id: str
    ) -> CollectionMetadataPayload | None:
        ...

    def set_collection_metadata(
        self, collection_id: str, metadata: CollectionMetadataPayload
    ) -> bool:
        ...
