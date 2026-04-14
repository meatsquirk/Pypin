"""Tests for DCPP manifest structures."""

import time
import pytest

from dcpp_python.core.constants import (
    AccessMode,
    CollectionType,
    ItemStatus,
    MediaType,
    SourceType,
    StorageType,
)
from dcpp_python.manifest import (
    EncryptionConfig,
    FileMetadata,
    Item,
    ItemsIndex,
    Manifest,
    MediaFile,
    ShardingConfig,
    ShardManifest,
    SourceInfo,
    SubCollection,
    TorrentInfo,
)


class TestTorrentInfo:
    """Test TorrentInfo structure."""

    def test_create_torrent_info(self):
        """Create TorrentInfo."""
        info = TorrentInfo(
            infohash="abcd1234567890",
            magnet="magnet:?xt=urn:btih:abcd1234",
            piece_length=262144,  # 256 KB
        )
        assert info.piece_length == 262144

    def test_torrent_info_roundtrip(self):
        """Serialize and deserialize TorrentInfo."""
        info = TorrentInfo(
            infohash="hash123",
            magnet="magnet:?xt=urn:btih:hash123",
            piece_length=1048576,  # 1 MB
        )
        d = info.to_dict()
        restored = TorrentInfo.from_dict(d)
        assert restored.infohash == info.infohash
        assert restored.piece_length == info.piece_length


class TestShardingConfig:
    """Test ShardingConfig structure."""

    def test_create_sharding_config(self):
        """Create ShardingConfig."""
        config = ShardingConfig(
            enabled=True,
            shard_count=10,
            shard_size_bytes=1073741824,  # 1 GB
        )
        assert config.enabled
        assert config.shard_count == 10

    def test_sharding_config_roundtrip(self):
        """Serialize and deserialize ShardingConfig."""
        config = ShardingConfig(
            enabled=True, shard_count=25, shard_size_bytes=2 * 1024**3
        )
        d = config.to_dict()
        restored = ShardingConfig.from_dict(d)
        assert restored.shard_count == 25


class TestSourceInfo:
    """Test SourceInfo structure."""

    def test_blockchain_source(self):
        """Create blockchain source."""
        source = SourceInfo(
            type=SourceType.BLOCKCHAIN,
            chain="eth",
            contract="0x1234567890abcdef",
        )
        d = source.to_dict()
        assert d["type"] == "blockchain"
        assert d["chain"] == "eth"

    def test_user_generated_source(self):
        """Create user-generated source (no chain/contract)."""
        source = SourceInfo(type=SourceType.USER_GENERATED)
        d = source.to_dict()
        assert "chain" not in d
        assert "contract" not in d


class TestEncryptionConfig:
    """Test EncryptionConfig structure."""

    def test_create_encryption_config(self):
        """Create encryption config."""
        config = EncryptionConfig(algorithm="aes-256-gcm", key_id="key_v1")
        d = config.to_dict()
        assert d["algorithm"] == "aes-256-gcm"
        assert d["key_id"] == "key_v1"


class TestSubCollection:
    """Test SubCollection structure."""

    def test_create_sub_collection(self):
        """Create sub-collection."""
        sub = SubCollection(
            id="photos-2024",
            name="2024 Photos",
            item_count=150,
            path="/photos/2024",
        )
        d = sub.to_dict()
        assert d["path"] == "/photos/2024"

    def test_sub_collection_without_path(self):
        """Sub-collection without path."""
        sub = SubCollection(id="sub1", name="Sub One", item_count=10)
        d = sub.to_dict()
        assert "path" not in d


class TestMediaFile:
    """Test MediaFile structure."""

    def test_create_media_file(self):
        """Create media file."""
        media = MediaFile(
            type=MediaType.VIDEO,
            cid="QmVideoFile123",
            size_bytes=10 * 1024 * 1024,  # 10 MB
            mime_type="video/mp4",
        )
        d = media.to_dict()
        assert d["type"] == "video"
        assert d["mime_type"] == "video/mp4"


class TestFileMetadata:
    """Test FileMetadata structure."""

    def test_create_file_metadata(self):
        """Create file metadata."""
        meta = FileMetadata(
            created_at=int(time.time()) - 86400,
            modified_at=int(time.time()),
            permissions=0o644,
        )
        d = meta.to_dict()
        assert d["permissions"] == 0o644

    def test_file_metadata_without_permissions(self):
        """File metadata without permissions."""
        meta = FileMetadata(created_at=1000, modified_at=2000)
        d = meta.to_dict()
        assert "permissions" not in d


class TestItem:
    """Test Item structure."""

    def test_create_nft_item(self):
        """Create NFT item."""
        item = Item(
            item_id="123",
            name="CoolNFT #123",
            cid="QmNFTContent123",
            size_bytes=500 * 1024,  # 500 KB
            mime_type="image/png",
            storage_type=StorageType.IPFS,
            status=ItemStatus.AVAILABLE,
            token_id="123",
            metadata_cid="QmMetadata123",
        )
        d = item.to_dict()
        assert d["token_id"] == "123"
        assert d["storage_type"] == "ipfs"

    def test_create_file_item(self):
        """Create file item for backup."""
        item = Item(
            item_id="photo001",
            name="vacation.jpg",
            cid="QmPhoto123",
            size_bytes=2 * 1024 * 1024,
            mime_type="image/jpeg",
            storage_type=StorageType.LOCAL,
            status=ItemStatus.LOCAL_ONLY,
            path="/photos/2024/vacation.jpg",
            file_meta=FileMetadata(
                created_at=1000000, modified_at=1000100, permissions=0o644
            ),
        )
        d = item.to_dict()
        assert d["path"] == "/photos/2024/vacation.jpg"
        assert d["file_meta"]["permissions"] == 0o644

    def test_item_with_media_files(self):
        """Item with additional media files."""
        media = [
            MediaFile(
                type=MediaType.IMAGE,
                cid="QmThumb",
                size_bytes=50 * 1024,
                mime_type="image/webp",
            ),
            MediaFile(
                type=MediaType.VIDEO,
                cid="QmVideo",
                size_bytes=50 * 1024 * 1024,
                mime_type="video/mp4",
            ),
        ]
        item = Item(
            item_id="nft1",
            name="MultiMedia NFT",
            cid="QmPrimary",
            size_bytes=1024,
            mime_type="image/png",
            storage_type=StorageType.IPFS,
            status=ItemStatus.AVAILABLE,
            media=media,
        )
        d = item.to_dict()
        assert len(d["media"]) == 2
        assert d["media"][0]["type"] == "image"

    def test_item_roundtrip(self):
        """Serialize and deserialize Item."""
        item = Item(
            item_id="test1",
            name="Test Item",
            cid="QmTest",
            size_bytes=1000,
            mime_type="application/octet-stream",
            storage_type=StorageType.HTTP,
            status=ItemStatus.AT_RISK,
            metadata_cid="QmMeta",
        )
        d = item.to_dict()
        restored = Item.from_dict(d)
        assert restored.item_id == item.item_id
        assert restored.status == item.status


class TestManifest:
    """Test Manifest structure."""

    def test_create_public_manifest(self):
        """Create public NFT collection manifest."""
        torrent = TorrentInfo(
            infohash="abc123", magnet="magnet:?xt=urn:btih:abc123", piece_length=262144
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.NFT_COLLECTION,
            access_mode=AccessMode.PUBLIC,
            collection_id="eth:0x1234567890",
            name="Cool NFT Collection",
            version=1,
            created_at=int(time.time()),
            updated_at=int(time.time()),
            total_items=10000,
            total_size_bytes=5 * 1024**3,  # 5 GB
            merkle_root="QmMerkleRoot123",
            torrent=torrent,
            source=SourceInfo(
                type=SourceType.BLOCKCHAIN, chain="eth", contract="0x1234567890"
            ),
            description="An awesome NFT collection",
        )
        assert manifest.access_mode == AccessMode.PUBLIC
        assert manifest.encryption is None

    def test_create_private_manifest(self):
        """Create private collection manifest."""
        torrent = TorrentInfo(
            infohash="xyz789", magnet="magnet:?xt=urn:btih:xyz789", piece_length=1048576
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.PHOTO_LIBRARY,
            access_mode=AccessMode.PRIVATE,
            collection_id="private:abcdef123456",
            name="Family Photos",
            version=5,
            created_at=1000000,
            updated_at=1500000,
            total_items=500,
            total_size_bytes=10 * 1024**3,
            merkle_root="QmFamilyRoot",
            torrent=torrent,
            encryption=EncryptionConfig(algorithm="aes-256-gcm", key_id="key_v2"),
        )
        assert manifest.access_mode == AccessMode.PRIVATE
        assert manifest.encryption is not None
        assert manifest.encryption.algorithm == "aes-256-gcm"

    def test_manifest_with_sharding(self):
        """Manifest with sharding enabled."""
        torrent = TorrentInfo(
            infohash="hash", magnet="magnet:?xt=...", piece_length=4194304
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.DATASET,
            access_mode=AccessMode.PUBLIC,
            collection_id="eth:0xbigcollection",
            name="Large Dataset",
            version=1,
            created_at=1000,
            updated_at=1000,
            total_items=100000,
            total_size_bytes=100 * 1024**3,  # 100 GB
            merkle_root="QmBigRoot",
            torrent=torrent,
            sharding=ShardingConfig(
                enabled=True,
                shard_count=100,
                shard_size_bytes=1024**3,
            ),
        )
        assert manifest.sharding.enabled
        assert manifest.sharding.shard_count == 100

    def test_manifest_with_inline_items(self):
        """Manifest with inline items array."""
        items = [
            Item(
                item_id=str(i),
                name=f"Item {i}",
                cid=f"Qm{i}",
                size_bytes=1000,
                mime_type="image/png",
                storage_type=StorageType.IPFS,
                status=ItemStatus.AVAILABLE,
            )
            for i in range(100)
        ]
        torrent = TorrentInfo(
            infohash="hash", magnet="magnet:?xt=...", piece_length=262144
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.NFT_COLLECTION,
            access_mode=AccessMode.PUBLIC,
            collection_id="eth:0xsmall",
            name="Small Collection",
            version=1,
            created_at=1000,
            updated_at=1000,
            total_items=100,
            total_size_bytes=100000,
            merkle_root="QmRoot",
            torrent=torrent,
            items=items,
        )
        assert len(manifest.items) == 100

    def test_manifest_with_external_items_index(self):
        """Manifest with external items index CID."""
        torrent = TorrentInfo(
            infohash="hash", magnet="magnet:?xt=...", piece_length=1048576
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.NFT_COLLECTION,
            access_mode=AccessMode.PUBLIC,
            collection_id="eth:0xlarge",
            name="Large Collection",
            version=1,
            created_at=1000,
            updated_at=1000,
            total_items=50000,
            total_size_bytes=50 * 1024**3,
            merkle_root="QmLargeRoot",
            torrent=torrent,
            items_index_cid="QmItemsIndex123",
        )
        assert manifest.items is None
        assert manifest.items_index_cid == "QmItemsIndex123"

    def test_manifest_with_sub_collections(self):
        """Manifest with sub-collections."""
        torrent = TorrentInfo(
            infohash="hash", magnet="magnet:?xt=...", piece_length=262144
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.PHOTO_LIBRARY,
            access_mode=AccessMode.PRIVATE,
            collection_id="private:family",
            name="Family Archive",
            version=3,
            created_at=1000,
            updated_at=2000,
            total_items=1000,
            total_size_bytes=20 * 1024**3,
            merkle_root="QmFamilyRoot",
            torrent=torrent,
            sub_collections=[
                SubCollection(
                    id="photos-2023", name="2023 Photos", item_count=300, path="/2023"
                ),
                SubCollection(
                    id="photos-2024", name="2024 Photos", item_count=700, path="/2024"
                ),
            ],
        )
        assert len(manifest.sub_collections) == 2

    def test_manifest_roundtrip(self):
        """Full manifest serialization roundtrip."""
        torrent = TorrentInfo(
            infohash="abcdef",
            magnet="magnet:?xt=urn:btih:abcdef",
            piece_length=262144,
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.NFT_COLLECTION,
            access_mode=AccessMode.PUBLIC,
            collection_id="eth:0xtest",
            name="Test Collection",
            version=42,
            created_at=1000000,
            updated_at=1500000,
            total_items=5000,
            total_size_bytes=2 * 1024**3,
            merkle_root="QmTestRoot",
            torrent=torrent,
            description="A test collection",
            source=SourceInfo(type=SourceType.BLOCKCHAIN, chain="eth", contract="0x"),
            probe_interval=43200,  # 12 hours
        )

        cbor_data = manifest.to_cbor()
        restored = Manifest.from_cbor(cbor_data)

        assert restored.protocol == manifest.protocol
        assert restored.type == manifest.type
        assert restored.access_mode == manifest.access_mode
        assert restored.collection_id == manifest.collection_id
        assert restored.version == manifest.version
        assert restored.description == manifest.description
        assert restored.torrent.infohash == torrent.infohash


class TestShardManifest:
    """Test ShardManifest structure."""

    def test_create_shard_manifest(self):
        """Create shard manifest."""
        torrent = TorrentInfo(
            infohash="shard5hash",
            magnet="magnet:?xt=urn:btih:shard5hash",
            piece_length=1048576,
        )
        shard = ShardManifest(
            collection_id="eth:0xlarge",
            shard_id=5,
            item_ids=["100", "101", "102", "103"],
            item_count=4,
            size_bytes=500 * 1024 * 1024,  # 500 MB
            merkle_root="QmShard5Root",
            torrent=torrent,
        )
        assert shard.shard_id == 5
        assert len(shard.item_ids) == 4

    def test_shard_manifest_roundtrip(self):
        """Serialize and deserialize ShardManifest."""
        torrent = TorrentInfo(
            infohash="shardX", magnet="magnet:?xt=...", piece_length=262144
        )
        shard = ShardManifest(
            collection_id="eth:0x123",
            shard_id=10,
            item_ids=["1000", "1001", "1002"],
            item_count=3,
            size_bytes=100 * 1024 * 1024,
            merkle_root="QmShardRoot",
            torrent=torrent,
        )

        cbor_data = shard.to_cbor()
        restored = ShardManifest.from_cbor(cbor_data)

        assert restored.shard_id == 10
        assert restored.item_ids == ["1000", "1001", "1002"]
        assert restored.torrent.infohash == "shardX"


class TestItemsIndex:
    """Test ItemsIndex structure."""

    def test_create_items_index(self):
        """Create items index."""
        items = [
            Item(
                item_id=str(i),
                name=f"Item {i}",
                cid=f"Qm{i}",
                size_bytes=1000,
                mime_type="image/png",
                storage_type=StorageType.IPFS,
                status=ItemStatus.AVAILABLE,
            )
            for i in range(1000)
        ]
        index = ItemsIndex(collection_id="eth:0xlarge", items=items)
        assert len(index.items) == 1000

    def test_items_index_roundtrip(self):
        """Serialize and deserialize ItemsIndex."""
        items = [
            Item(
                item_id="1",
                name="Test",
                cid="QmTest",
                size_bytes=100,
                mime_type="text/plain",
                storage_type=StorageType.IPFS,
                status=ItemStatus.UNKNOWN,
            )
        ]
        index = ItemsIndex(collection_id="test:col", items=items)

        cbor_data = index.to_cbor()
        restored = ItemsIndex.from_cbor(cbor_data)

        assert restored.collection_id == "test:col"
        assert len(restored.items) == 1
        assert restored.items[0].cid == "QmTest"
