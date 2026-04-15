"""Storage backend base classes and helpers."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Tuple

from dcpp_python.crypto.cid import compute_cid, verify_cid

logger = logging.getLogger("dcpp.storage")


@dataclass
class StorageStats:
    """Statistics for storage usage."""

    total_items: int = 0
    total_size_bytes: int = 0
    collections: int = 0
    shards: dict[str, int] = field(default_factory=dict)


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    def store(self, collection_id: str, cid: str, data: bytes) -> bool:
        """
        Store content.

        Args:
            collection_id: Collection ID
            cid: Content identifier (e.g., IPFS CID)
            data: Content bytes

        Returns:
            True if storage succeeded
        """
        pass

    @abstractmethod
    def retrieve(self, collection_id: str, cid: str) -> bytes | None:
        """
        Retrieve content.

        Args:
            collection_id: Collection ID
            cid: Content identifier

        Returns:
            Content bytes or None if not found
        """
        pass

    @abstractmethod
    def exists(self, collection_id: str, cid: str) -> bool:
        """Check if content exists."""
        pass

    @abstractmethod
    def delete(self, collection_id: str, cid: str) -> bool:
        """Delete content."""
        pass

    @abstractmethod
    def list_items(self, collection_id: str) -> list[str]:
        """List all CIDs in a collection."""
        pass

    @abstractmethod
    def get_stats(self) -> StorageStats:
        """Get storage statistics."""
        pass

    def verify_content(self, cid: str, data: bytes) -> bool:
        """
        Verify that content matches a CID.

        Uses proper CID parsing and SHA-256 verification per RFC Section 3.3.

        Args:
            cid: Content identifier (CIDv1 base32)
            data: Content bytes

        Returns:
            True if content matches CID
        """
        try:
            return verify_cid(cid, data)
        except ValueError as e:
            logger.warning(f"CID verification failed: {e}")
            return False

    def store_verified(self, collection_id: str, data: bytes) -> Tuple[str, bool]:
        """
        Store content with automatic CID computation and verification.

        Computes the CID for the data and stores it, verifying the round-trip.

        Args:
            collection_id: Collection ID
            data: Content bytes

        Returns:
            Tuple of (computed_cid, success)
        """
        cid = compute_cid(data)
        success = self.store(collection_id, cid, data)
        return cid, success

    def retrieve_verified(self, collection_id: str, cid: str) -> bytes | None:
        """
        Retrieve content and verify it matches the CID.

        Args:
            collection_id: Collection ID
            cid: Content identifier

        Returns:
            Content bytes if found and verified, None otherwise
        """
        data = self.retrieve(collection_id, cid)
        if data is None:
            return None

        if not self.verify_content(cid, data):
            logger.error(f"Content verification failed for {cid} in {collection_id}")
            return None

        return data
