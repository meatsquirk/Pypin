"""
DCPP Collection Manifest Structures

Implements manifest and item structures defined in Section 8 of the DCPP/1.0 Wire Protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypedDict
from typing_extensions import NotRequired

import cbor2

from dcpp_python.core.constants import (
    AccessMode,
    CollectionType,
    ItemStatus,
    MediaType,
    SourceType,
    StorageType,
)


# =============================================================================
# TypedDict payloads
# =============================================================================


class TorrentInfoPayload(TypedDict):
    infohash: str
    magnet: str
    piece_length: int


class ShardingConfigPayload(TypedDict):
    enabled: bool
    shard_count: int
    shard_size_bytes: int


class SourceInfoPayload(TypedDict):
    type: str
    chain: NotRequired[str]
    contract: NotRequired[str]


class EncryptionConfigPayload(TypedDict):
    algorithm: str
    key_id: str


class SubCollectionPayload(TypedDict):
    id: str
    name: str
    item_count: int
    path: NotRequired[str]


class MediaFilePayload(TypedDict):
    type: str
    cid: str
    size_bytes: int
    mime_type: str


class FileMetadataPayload(TypedDict):
    created_at: int
    modified_at: int
    permissions: NotRequired[int]


class ItemPayload(TypedDict):
    item_id: str
    name: str
    cid: str
    size_bytes: int
    mime_type: str
    storage_type: str
    status: str
    token_id: NotRequired[str]
    path: NotRequired[str]
    metadata_cid: NotRequired[str]
    media: NotRequired[list[MediaFilePayload]]
    file_meta: NotRequired[FileMetadataPayload]


class ManifestPayload(TypedDict):
    protocol: str
    type: str
    access_mode: str
    collection_id: str
    name: str
    version: int
    created_at: int
    updated_at: int
    total_items: int
    total_size_bytes: int
    merkle_root: str
    torrent: TorrentInfoPayload
    encryption: NotRequired[EncryptionConfigPayload]
    description: NotRequired[str]
    source: NotRequired[SourceInfoPayload]
    parent_collection: NotRequired[str]
    sub_collections: NotRequired[list[SubCollectionPayload]]
    sharding: NotRequired[ShardingConfigPayload]
    probe_interval: NotRequired[int]
    items: NotRequired[list[ItemPayload]]
    items_index_cid: NotRequired[str]


class ShardManifestPayload(TypedDict):
    collection_id: str
    shard_id: int
    item_ids: list[str]
    item_count: int
    size_bytes: int
    merkle_root: str
    torrent: TorrentInfoPayload


class ItemsIndexPayload(TypedDict):
    collection_id: str
    items: list[ItemPayload]


@dataclass
class TorrentInfo:
    """BitTorrent info for a collection/shard (Section 8.1)."""

    infohash: str
    magnet: str
    piece_length: int

    def to_dict(self) -> TorrentInfoPayload:
        return {
            "infohash": self.infohash,
            "magnet": self.magnet,
            "piece_length": self.piece_length,
        }

    @classmethod
    def from_dict(cls, data: TorrentInfoPayload) -> "TorrentInfo":
        return cls(
            infohash=data["infohash"],
            magnet=data["magnet"],
            piece_length=data["piece_length"],
        )


@dataclass
class ShardingConfig:
    """Sharding configuration (Section 8.1)."""

    enabled: bool
    shard_count: int
    shard_size_bytes: int

    def to_dict(self) -> ShardingConfigPayload:
        return {
            "enabled": self.enabled,
            "shard_count": self.shard_count,
            "shard_size_bytes": self.shard_size_bytes,
        }

    @classmethod
    def from_dict(cls, data: ShardingConfigPayload) -> "ShardingConfig":
        return cls(
            enabled=data["enabled"],
            shard_count=data["shard_count"],
            shard_size_bytes=data["shard_size_bytes"],
        )


@dataclass
class SourceInfo:
    """Source information (Section 8.1)."""

    type: str
    chain: str | None = None
    contract: str | None = None

    def to_dict(self) -> SourceInfoPayload:
        result: SourceInfoPayload = {"type": self.type}
        if self.chain is not None:
            result["chain"] = self.chain
        if self.contract is not None:
            result["contract"] = self.contract
        return result

    @classmethod
    def from_dict(cls, data: SourceInfoPayload) -> "SourceInfo":
        return cls(
            type=data["type"],
            chain=data.get("chain"),
            contract=data.get("contract"),
        )


@dataclass
class EncryptionConfig:
    """Encryption configuration for private collections (Section 8.1)."""

    algorithm: str
    key_id: str

    def to_dict(self) -> EncryptionConfigPayload:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, data: EncryptionConfigPayload) -> "EncryptionConfig":
        return cls(
            algorithm=data["algorithm"],
            key_id=data["key_id"],
        )


@dataclass
class SubCollection:
    """Sub-collection within a collection (Section 8.1)."""

    id: str
    name: str
    item_count: int
    path: str | None = None

    def to_dict(self) -> SubCollectionPayload:
        result: SubCollectionPayload = {
            "id": self.id,
            "name": self.name,
            "item_count": self.item_count,
        }
        if self.path is not None:
            result["path"] = self.path
        return result

    @classmethod
    def from_dict(cls, data: SubCollectionPayload) -> "SubCollection":
        return cls(
            id=data["id"],
            name=data["name"],
            item_count=data["item_count"],
            path=data.get("path"),
        )


@dataclass
class MediaFile:
    """Additional media file for an item (Section 8.2)."""

    type: str
    cid: str
    size_bytes: int
    mime_type: str

    def to_dict(self) -> MediaFilePayload:
        return {
            "type": self.type,
            "cid": self.cid,
            "size_bytes": self.size_bytes,
            "mime_type": self.mime_type,
        }

    @classmethod
    def from_dict(cls, data: MediaFilePayload) -> "MediaFile":
        return cls(
            type=data["type"],
            cid=data["cid"],
            size_bytes=data["size_bytes"],
            mime_type=data["mime_type"],
        )


@dataclass
class FileMetadata:
    """File metadata for backups/folders (Section 8.2)."""

    created_at: int
    modified_at: int
    permissions: int | None = None

    def to_dict(self) -> FileMetadataPayload:
        result: FileMetadataPayload = {
            "created_at": self.created_at,
            "modified_at": self.modified_at,
        }
        if self.permissions is not None:
            result["permissions"] = self.permissions
        return result

    @classmethod
    def from_dict(cls, data: FileMetadataPayload) -> "FileMetadata":
        return cls(
            created_at=data["created_at"],
            modified_at=data["modified_at"],
            permissions=data.get("permissions"),
        )


@dataclass
class Item:
    """
    Item structure (Section 8.2)

    Items represent individual pieces of content within a collection.
    """

    item_id: str
    name: str
    cid: str
    size_bytes: int
    mime_type: str
    storage_type: str
    status: str
    token_id: str | None = None
    path: str | None = None
    metadata_cid: str | None = None
    media: list[MediaFile] | None = None
    file_meta: FileMetadata | None = None

    def to_dict(self) -> ItemPayload:
        result: ItemPayload = {
            "item_id": self.item_id,
            "name": self.name,
            "cid": self.cid,
            "size_bytes": self.size_bytes,
            "mime_type": self.mime_type,
            "storage_type": self.storage_type,
            "status": self.status,
        }
        if self.token_id is not None:
            result["token_id"] = self.token_id
        if self.path is not None:
            result["path"] = self.path
        if self.metadata_cid is not None:
            result["metadata_cid"] = self.metadata_cid
        if self.media is not None:
            result["media"] = [m.to_dict() for m in self.media]
        if self.file_meta is not None:
            result["file_meta"] = self.file_meta.to_dict()
        return result

    @classmethod
    def from_dict(cls, data: ItemPayload) -> "Item":
        media = None
        if "media" in data and data["media"] is not None:
            media = [MediaFile.from_dict(m) for m in data["media"]]

        file_meta = None
        if "file_meta" in data and data["file_meta"] is not None:
            file_meta = FileMetadata.from_dict(data["file_meta"])

        return cls(
            item_id=data["item_id"],
            name=data["name"],
            cid=data["cid"],
            size_bytes=data["size_bytes"],
            mime_type=data["mime_type"],
            storage_type=data["storage_type"],
            status=data["status"],
            token_id=data.get("token_id"),
            path=data.get("path"),
            metadata_cid=data.get("metadata_cid"),
            media=media,
            file_meta=file_meta,
        )


@dataclass
class Manifest:
    """
    Collection Manifest (Section 8.1)

    Canonical record of a collection's contents, structure, and metadata.
    """

    # Required fields
    protocol: str
    type: str
    access_mode: str
    collection_id: str
    name: str
    version: int
    created_at: int
    updated_at: int
    total_items: int
    total_size_bytes: int
    merkle_root: str
    torrent: TorrentInfo

    # Optional fields
    encryption: EncryptionConfig | None = None
    description: str | None = None
    source: SourceInfo | None = None
    parent_collection: str | None = None
    sub_collections: list[SubCollection] | None = None
    sharding: ShardingConfig | None = None
    probe_interval: int | None = None
    items: list[Item] | None = None
    items_index_cid: str | None = None

    def to_dict(self) -> ManifestPayload:
        result: ManifestPayload = {
            "protocol": self.protocol,
            "type": self.type,
            "access_mode": self.access_mode,
            "collection_id": self.collection_id,
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "total_items": self.total_items,
            "total_size_bytes": self.total_size_bytes,
            "merkle_root": self.merkle_root,
            "torrent": self.torrent.to_dict(),
        }

        if self.encryption is not None:
            result["encryption"] = self.encryption.to_dict()
        if self.description is not None:
            result["description"] = self.description
        if self.source is not None:
            result["source"] = self.source.to_dict()
        if self.parent_collection is not None:
            result["parent_collection"] = self.parent_collection
        if self.sub_collections is not None:
            result["sub_collections"] = [s.to_dict() for s in self.sub_collections]
        if self.sharding is not None:
            result["sharding"] = self.sharding.to_dict()
        if self.probe_interval is not None:
            result["probe_interval"] = self.probe_interval
        if self.items is not None:
            result["items"] = [i.to_dict() for i in self.items]
        if self.items_index_cid is not None:
            result["items_index_cid"] = self.items_index_cid

        return result

    def to_cbor(self) -> bytes:
        """Serialize manifest to CBOR."""
        return cbor2.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: ManifestPayload) -> "Manifest":
        encryption = None
        if "encryption" in data and data["encryption"] is not None:
            encryption = EncryptionConfig.from_dict(data["encryption"])

        source = None
        if "source" in data and data["source"] is not None:
            source = SourceInfo.from_dict(data["source"])

        sub_collections = None
        if "sub_collections" in data and data["sub_collections"] is not None:
            sub_collections = [SubCollection.from_dict(s) for s in data["sub_collections"]]

        sharding = None
        if "sharding" in data and data["sharding"] is not None:
            sharding = ShardingConfig.from_dict(data["sharding"])

        items = None
        if "items" in data and data["items"] is not None:
            items = [Item.from_dict(i) for i in data["items"]]

        return cls(
            protocol=data["protocol"],
            type=data["type"],
            access_mode=data["access_mode"],
            collection_id=data["collection_id"],
            name=data["name"],
            version=data["version"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            total_items=data["total_items"],
            total_size_bytes=data["total_size_bytes"],
            merkle_root=data["merkle_root"],
            torrent=TorrentInfo.from_dict(data["torrent"]),
            encryption=encryption,
            description=data.get("description"),
            source=source,
            parent_collection=data.get("parent_collection"),
            sub_collections=sub_collections,
            sharding=sharding,
            probe_interval=data.get("probe_interval"),
            items=items,
            items_index_cid=data.get("items_index_cid"),
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> "Manifest":
        """Deserialize manifest from CBOR."""
        return cls.from_dict(cbor2.loads(data))


@dataclass
class ShardManifest:
    """
    Shard Manifest (Section 11.8)

    Each shard has its own manifest and torrent.
    """

    collection_id: str
    shard_id: int
    item_ids: list[str]
    item_count: int
    size_bytes: int
    merkle_root: str
    torrent: TorrentInfo

    def to_dict(self) -> ShardManifestPayload:
        return {
            "collection_id": self.collection_id,
            "shard_id": self.shard_id,
            "item_ids": self.item_ids,
            "item_count": self.item_count,
            "size_bytes": self.size_bytes,
            "merkle_root": self.merkle_root,
            "torrent": self.torrent.to_dict(),
        }

    def to_cbor(self) -> bytes:
        """Serialize shard manifest to CBOR."""
        return cbor2.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: ShardManifestPayload) -> "ShardManifest":
        return cls(
            collection_id=data["collection_id"],
            shard_id=data["shard_id"],
            item_ids=data["item_ids"],
            item_count=data["item_count"],
            size_bytes=data["size_bytes"],
            merkle_root=data["merkle_root"],
            torrent=TorrentInfo.from_dict(data["torrent"]),
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> "ShardManifest":
        """Deserialize shard manifest from CBOR."""
        return cls.from_dict(cbor2.loads(data))


@dataclass
class ItemsIndex:
    """
    External Items Index (Section 8.3)

    For collections exceeding inline limits.
    """

    collection_id: str
    items: list[Item]

    def to_dict(self) -> ItemsIndexPayload:
        return {
            "collection_id": self.collection_id,
            "items": [i.to_dict() for i in self.items],
        }

    def to_cbor(self) -> bytes:
        """Serialize items index to CBOR."""
        return cbor2.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: ItemsIndexPayload) -> "ItemsIndex":
        return cls(
            collection_id=data["collection_id"],
            items=[Item.from_dict(i) for i in data["items"]],
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> "ItemsIndex":
        """Deserialize items index from CBOR."""
        return cls.from_dict(cbor2.loads(data))
