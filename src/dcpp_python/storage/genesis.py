"""Genesis storage backends."""

from __future__ import annotations

import json
import os
import hashlib
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TypedDict
from typing_extensions import NotRequired
from enum import Enum
from pathlib import Path
from typing import Optional

from .base import logger

class GenesisState(Enum):
    """State of a genesis record."""

    TRUSTED = "trusted"  # Single authoritative source
    CONFLICTED = "conflicted"  # Multiple conflicting manifests
    RESOLVED = "resolved"  # Conflict resolved by admin/merge


class GenesisRecordPayload(TypedDict):
    collection_id: str
    manifest_cid: str
    manifest_version: int
    first_seen_at: int
    announcing_node_id: NotRequired[str | None]
    conflict_cids: list[str]
    state: str
    resolution_notes: NotRequired[str | None]
    resolved_at: NotRequired[int | None]
    resolved_by: NotRequired[str | None]


@dataclass
class GenesisRecord:
    """
    Genesis record for TOFU (Trust On First Use) verification.

    Tracks the first-seen manifest for UUID-scheme collections and
    handles conflict detection/resolution.
    """

    collection_id: str
    manifest_cid: str  # First-seen manifest CID
    manifest_version: int
    first_seen_at: int  # Unix timestamp
    announcing_node_id: bytes | None = None
    conflict_cids: list[str] = field(default_factory=list)
    state: GenesisState = GenesisState.TRUSTED
    resolution_notes: str | None = None
    resolved_at: int | None = None
    resolved_by: bytes | None = None

    def to_dict(self) -> GenesisRecordPayload:
        """Convert to dictionary for JSON serialization."""
        return {
            "collection_id": self.collection_id,
            "manifest_cid": self.manifest_cid,
            "manifest_version": self.manifest_version,
            "first_seen_at": self.first_seen_at,
            "announcing_node_id": (
                self.announcing_node_id.hex() if self.announcing_node_id else None
            ),
            "conflict_cids": self.conflict_cids,
            "state": self.state.value,
            "resolution_notes": self.resolution_notes,
            "resolved_at": self.resolved_at,
            "resolved_by": self.resolved_by.hex() if self.resolved_by else None,
        }

    @classmethod
    def from_dict(cls, data: GenesisRecordPayload) -> "GenesisRecord":
        """Create from dictionary."""
        announcing_node_id = data.get("announcing_node_id")
        resolved_by = data.get("resolved_by")
        return cls(
            collection_id=data["collection_id"],
            manifest_cid=data["manifest_cid"],
            manifest_version=data["manifest_version"],
            first_seen_at=data["first_seen_at"],
            announcing_node_id=(
                bytes.fromhex(announcing_node_id)
                if announcing_node_id is not None
                else None
            ),
            conflict_cids=data.get("conflict_cids", []),
            state=GenesisState(data.get("state", "trusted")),
            resolution_notes=data.get("resolution_notes"),
            resolved_at=data.get("resolved_at"),
            resolved_by=(bytes.fromhex(resolved_by) if resolved_by is not None else None),
        )


class GenesisStore(ABC):
    """Abstract base class for genesis record storage."""

    @abstractmethod
    async def get_genesis(self, collection_id: str) -> GenesisRecord | None:
        """
        Get genesis record for a collection.

        Args:
            collection_id: Collection ID

        Returns:
            Genesis record or None if not found
        """
        pass

    @abstractmethod
    async def record_genesis(
        self,
        collection_id: str,
        manifest_cid: str,
        version: int,
        node_id: bytes | None = None,
    ) -> GenesisRecord:
        """
        Record the first-seen manifest for a collection.

        Args:
            collection_id: Collection ID
            manifest_cid: CID of the first-seen manifest
            version: Manifest version number
            node_id: Node ID that announced this manifest

        Returns:
            Created genesis record
        """
        pass

    @abstractmethod
    async def record_conflict(self, collection_id: str, conflicting_cid: str) -> GenesisRecord:
        """
        Record a conflicting manifest for a collection.

        Args:
            collection_id: Collection ID
            conflicting_cid: CID of the conflicting manifest

        Returns:
            Updated genesis record with conflict info
        """
        pass

    @abstractmethod
    async def resolve_conflict(
        self,
        collection_id: str,
        accepted_cid: str,
        resolution_notes: str | None = None,
        resolved_by: bytes | None = None,
    ) -> GenesisRecord:
        """
        Resolve a conflict by accepting a specific manifest.

        Args:
            collection_id: Collection ID
            accepted_cid: CID of the accepted manifest
            resolution_notes: Optional notes about the resolution
            resolved_by: Node ID of the resolver

        Returns:
            Updated genesis record
        """
        pass

    @abstractmethod
    async def list_conflicts(self) -> list[GenesisRecord]:
        """
        List all collections with unresolved conflicts.

        Returns:
            List of genesis records in CONFLICTED state
        """
        pass

    @abstractmethod
    async def delete_genesis(self, collection_id: str) -> bool:
        """
        Delete genesis record for a collection.

        Args:
            collection_id: Collection ID

        Returns:
            True if deleted, False if not found
        """
        pass


class FileSystemGenesisStore(GenesisStore):
    """
    File-system based genesis record storage.

    Directory structure:
        {base_path}/genesis/{safe_collection_id}.json
    """

    def __init__(self, base_path: Path | str):
        """
        Initialize file-system genesis store.

        Args:
            base_path: Base directory for storage
        """
        self.base_path = Path(base_path).expanduser().resolve()
        self.genesis_path = self.base_path / "genesis"
        self.genesis_path.mkdir(parents=True, exist_ok=True)

    def _sanitize_collection_id(self, collection_id: str) -> str:
        """
        Sanitize collection_id for filesystem use.

        Prefer readable IDs when safe; fall back to a stable hash if unsafe.
        """
        if not collection_id:
            raise ValueError("collection_id must be non-empty")

        if re.fullmatch(r"[A-Za-z0-9._:-]+", collection_id) and ".." not in collection_id:
            return collection_id.replace(":", "_")

        digest = hashlib.sha256(collection_id.encode("utf-8")).hexdigest()
        return f"collection_{digest}"

    def _genesis_file(self, collection_id: str) -> Path:
        """Get path for genesis record file."""
        safe_id = self._sanitize_collection_id(collection_id)
        return self.genesis_path / f"{safe_id}.json"

    async def get_genesis(self, collection_id: str) -> GenesisRecord | None:
        """Get genesis record for a collection."""
        file_path = self._genesis_file(collection_id)
        if not file_path.exists():
            return None

        try:
            data = json.loads(file_path.read_text())
            return GenesisRecord.from_dict(data)
        except (OSError, json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to read genesis record for {collection_id}: {e}")
            return None

    async def _save_genesis(self, record: GenesisRecord) -> None:
        """Save genesis record to file."""
        file_path = self._genesis_file(record.collection_id)
        file_path.write_text(json.dumps(record.to_dict(), indent=2))

    async def record_genesis(
        self,
        collection_id: str,
        manifest_cid: str,
        version: int,
        node_id: bytes | None = None,
    ) -> GenesisRecord:
        """Record the first-seen manifest for a collection."""
        existing = await self.get_genesis(collection_id)
        if existing is not None:
            raise ValueError(
                f"Genesis record already exists for {collection_id}. "
                f"Use record_conflict() if this is a conflicting manifest."
            )

        record = GenesisRecord(
            collection_id=collection_id,
            manifest_cid=manifest_cid,
            manifest_version=version,
            first_seen_at=int(time.time()),
            announcing_node_id=node_id,
        )
        await self._save_genesis(record)
        logger.info(f"Recorded genesis for {collection_id}: {manifest_cid}")
        return record

    async def record_conflict(self, collection_id: str, conflicting_cid: str) -> GenesisRecord:
        """Record a conflicting manifest for a collection."""
        record = await self.get_genesis(collection_id)
        if record is None:
            raise ValueError(f"No genesis record for {collection_id}. Use record_genesis() first.")

        # Skip if this CID is already known
        if conflicting_cid == record.manifest_cid:
            return record
        if conflicting_cid in record.conflict_cids:
            return record

        record.conflict_cids.append(conflicting_cid)
        record.state = GenesisState.CONFLICTED
        await self._save_genesis(record)
        logger.warning(
            f"Conflict detected for {collection_id}: {conflicting_cid} vs {record.manifest_cid}"
        )
        return record

    async def resolve_conflict(
        self,
        collection_id: str,
        accepted_cid: str,
        resolution_notes: str | None = None,
        resolved_by: bytes | None = None,
    ) -> GenesisRecord:
        """Resolve a conflict by accepting a specific manifest."""
        record = await self.get_genesis(collection_id)
        if record is None:
            raise ValueError(f"No genesis record for {collection_id}")

        if record.state != GenesisState.CONFLICTED:
            raise ValueError(f"Collection {collection_id} is not in conflict state")

        # Verify the accepted CID is either the original or a conflict
        valid_cids = [record.manifest_cid] + record.conflict_cids
        if accepted_cid not in valid_cids:
            raise ValueError(f"CID {accepted_cid} is not a known manifest for {collection_id}")

        # Update record
        record.manifest_cid = accepted_cid
        record.state = GenesisState.RESOLVED
        record.resolution_notes = resolution_notes
        record.resolved_at = int(time.time())
        record.resolved_by = resolved_by

        # Keep conflict history for auditing but mark resolved
        await self._save_genesis(record)
        logger.info(f"Conflict resolved for {collection_id}: accepted {accepted_cid}")
        return record

    async def list_conflicts(self) -> list[GenesisRecord]:
        """List all collections with unresolved conflicts."""
        conflicts: list[GenesisRecord] = []
        if not self.genesis_path.exists():
            return conflicts

        for file_path in self.genesis_path.glob("*.json"):
            try:
                data = json.loads(file_path.read_text())
                record = GenesisRecord.from_dict(data)
                if record.state == GenesisState.CONFLICTED:
                    conflicts.append(record)
            except (OSError, json.JSONDecodeError, KeyError):
                continue

        return conflicts

    async def delete_genesis(self, collection_id: str) -> bool:
        """Delete genesis record for a collection."""
        file_path = self._genesis_file(collection_id)
        if not file_path.exists():
            return False

        try:
            file_path.unlink()
            logger.info(f"Deleted genesis record for {collection_id}")
            return True
        except OSError as e:
            logger.error(f"Failed to delete genesis record for {collection_id}: {e}")
            return False


class MemoryGenesisStore(GenesisStore):
    """In-memory genesis store for testing."""

    def __init__(self) -> None:
        self._records: dict[str, GenesisRecord] = {}

    async def get_genesis(self, collection_id: str) -> GenesisRecord | None:
        return self._records.get(collection_id)

    async def record_genesis(
        self,
        collection_id: str,
        manifest_cid: str,
        version: int,
        node_id: bytes | None = None,
    ) -> GenesisRecord:
        if collection_id in self._records:
            raise ValueError(f"Genesis record already exists for {collection_id}")

        record = GenesisRecord(
            collection_id=collection_id,
            manifest_cid=manifest_cid,
            manifest_version=version,
            first_seen_at=int(time.time()),
            announcing_node_id=node_id,
        )
        self._records[collection_id] = record
        return record

    async def record_conflict(self, collection_id: str, conflicting_cid: str) -> GenesisRecord:
        record = self._records.get(collection_id)
        if record is None:
            raise ValueError(f"No genesis record for {collection_id}")

        if conflicting_cid == record.manifest_cid:
            return record
        if conflicting_cid in record.conflict_cids:
            return record

        record.conflict_cids.append(conflicting_cid)
        record.state = GenesisState.CONFLICTED
        return record

    async def resolve_conflict(
        self,
        collection_id: str,
        accepted_cid: str,
        resolution_notes: str | None = None,
        resolved_by: bytes | None = None,
    ) -> GenesisRecord:
        record = self._records.get(collection_id)
        if record is None:
            raise ValueError(f"No genesis record for {collection_id}")

        if record.state != GenesisState.CONFLICTED:
            raise ValueError(f"Collection {collection_id} is not in conflict state")

        valid_cids = [record.manifest_cid] + record.conflict_cids
        if accepted_cid not in valid_cids:
            raise ValueError(f"CID {accepted_cid} is not a known manifest")

        record.manifest_cid = accepted_cid
        record.state = GenesisState.RESOLVED
        record.resolution_notes = resolution_notes
        record.resolved_at = int(time.time())
        record.resolved_by = resolved_by
        return record

    async def list_conflicts(self) -> list[GenesisRecord]:
        return [r for r in self._records.values() if r.state == GenesisState.CONFLICTED]

    async def delete_genesis(self, collection_id: str) -> bool:
        if collection_id in self._records:
            del self._records[collection_id]
            return True
        return False
