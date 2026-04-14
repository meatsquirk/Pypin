"""Additional tests to ensure coverage exceeds 95%."""

import io
import pytest

from dcpp_python.core.constants import MessageType
from dcpp_python.framing import (
    FramingError,
    Profile1Framer,
)
from dcpp_python.manifest import (
    Item,
    Manifest,
    SubCollection,
    TorrentInfo,
    ShardManifest,
    ItemsIndex,
    FileMetadata,
    MediaFile,
)
from dcpp_python.messages import (
    MessageBase,
    KeyRotate,
    InviteToken,
)
from dcpp_python.utils import decode_varint


class TestMessageBase:
    """Test MessageBase abstract methods."""

    def test_to_dict_not_implemented(self):
        """to_dict raises NotImplementedError on base class."""
        base = MessageBase()
        with pytest.raises(NotImplementedError):
            base.to_dict()

    def test_from_dict_not_implemented(self):
        """from_dict raises NotImplementedError on base class."""
        with pytest.raises(NotImplementedError):
            MessageBase.from_dict({})


class TestKeyRotate:
    """Test KEY_ROTATE message."""

    def test_key_rotate_roundtrip(self):
        """Serialize and deserialize KEY_ROTATE."""
        msg = KeyRotate(
            collection_id="private:old123",
            new_collection_id="private:new456",
            new_key=b"encrypted_new_key_here",
            reason="member_revoked",
            admin_signature=b"admin_sig",
        )
        d = msg.to_dict()
        restored = KeyRotate.from_dict(d)
        assert restored.collection_id == msg.collection_id
        assert restored.new_collection_id == msg.new_collection_id
        assert restored.reason == msg.reason


class TestInviteTokenExtra:
    """Additional InviteToken tests."""

    def test_invite_token_roundtrip(self):
        """Full roundtrip of InviteToken."""
        token = InviteToken(
            collection_id="private:abc",
            created_at=1000,
            expires_at=2000,
            permissions="member",
            signature=b"signature_bytes",
        )
        cbor_data = token.to_cbor()
        restored = InviteToken.from_cbor(cbor_data)
        assert restored.collection_id == token.collection_id
        assert restored.permissions == token.permissions


class TestStreamDecoding:
    """Test stream-based decoding edge cases."""

    def test_profile1_decode_stream_incomplete_header(self):
        """Profile 1 stream with incomplete header."""
        stream = io.BytesIO(b"DCPP\x00\x00\x00")  # Only 7 bytes, need 20
        with pytest.raises(FramingError, match="Incomplete header"):
            Profile1Framer.decode(stream)

    def test_profile1_decode_stream_incomplete_payload(self):
        """Profile 1 stream with incomplete payload."""
        import struct
        from dcpp_python.utils import crc32c

        # Build header claiming 100 bytes but provide only 10
        # Header: Magic(4) + Version(2) + Type(2) + RequestID(4) + Length(4) + CRC(4) = 20 bytes
        payload_len = 100
        fake_crc = 0x12345678
        header = (
            b"DCPP"
            + b"\x01\x00"  # version
            + struct.pack(">H", MessageType.HELLO)
            + struct.pack(">I", 0)  # request_id
            + struct.pack(">I", payload_len)
            + struct.pack(">I", fake_crc)
        )
        stream = io.BytesIO(header + b"x" * 10)  # Only 10 bytes of payload
        with pytest.raises(FramingError, match="Incomplete payload"):
            Profile1Framer.decode(stream)


class TestVarintStreamEdgeCases:
    """Test varint decoding from streams with edge cases."""

    def test_decode_varint_stream_empty(self):
        """Empty stream should raise."""
        stream = io.BytesIO(b"")
        with pytest.raises(ValueError, match="Incomplete varint"):
            decode_varint(stream)


class TestManifestEdgeCases:
    """Test manifest edge cases for coverage."""

    def test_sub_collection_from_dict(self):
        """SubCollection from_dict with all fields."""
        data = {
            "id": "sub1",
            "name": "Sub One",
            "item_count": 100,
            "path": "/path/to/sub",
        }
        sub = SubCollection.from_dict(data)
        assert sub.path == "/path/to/sub"

    def test_item_with_all_optional_fields(self):
        """Item with all optional fields populated."""
        data = {
            "item_id": "1",
            "name": "Full Item",
            "cid": "QmTest",
            "size_bytes": 1000,
            "mime_type": "image/png",
            "storage_type": "ipfs",
            "status": "available",
            "token_id": "123",
            "path": "/photos/img.png",
            "metadata_cid": "QmMeta",
            "media": [
                {
                    "type": "image",
                    "cid": "QmThumb",
                    "size_bytes": 100,
                    "mime_type": "image/webp",
                }
            ],
            "file_meta": {
                "created_at": 1000,
                "modified_at": 2000,
                "permissions": 644,
            },
        }
        item = Item.from_dict(data)
        assert item.token_id == "123"
        assert item.path == "/photos/img.png"
        assert len(item.media) == 1
        assert item.file_meta.permissions == 644

    def test_manifest_with_all_optional_fields(self):
        """Manifest with all optional fields for coverage."""
        from dcpp_python.manifest import SourceInfo, EncryptionConfig, ShardingConfig

        torrent = TorrentInfo(
            infohash="abc", magnet="magnet:?xt=...", piece_length=262144
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type="nft-collection",
            access_mode="private",
            collection_id="private:xyz",
            name="Full Test",
            version=1,
            created_at=1000,
            updated_at=2000,
            total_items=100,
            total_size_bytes=1000000,
            merkle_root="QmRoot",
            torrent=torrent,
            encryption=EncryptionConfig(algorithm="aes-256-gcm", key_id="v1"),
            description="A full manifest",
            source=SourceInfo(type="blockchain", chain="eth", contract="0x123"),
            parent_collection="parent:col",
            sub_collections=[
                SubCollection(id="sub1", name="Sub", item_count=10, path="/sub")
            ],
            sharding=ShardingConfig(
                enabled=True, shard_count=5, shard_size_bytes=1000000
            ),
            probe_interval=3600,
            items=[
                Item(
                    item_id="1",
                    name="Item",
                    cid="Qm1",
                    size_bytes=100,
                    mime_type="text/plain",
                    storage_type="ipfs",
                    status="available",
                )
            ],
            items_index_cid=None,  # Can't have both items and index
        )
        d = manifest.to_dict()
        restored = Manifest.from_dict(d)
        assert restored.encryption.algorithm == "aes-256-gcm"
        assert restored.source.chain == "eth"
        assert len(restored.sub_collections) == 1
        assert restored.sharding.enabled

    def test_shard_manifest_cbor_roundtrip(self):
        """ShardManifest CBOR roundtrip."""
        torrent = TorrentInfo(
            infohash="shardX", magnet="magnet:?...", piece_length=262144
        )
        shard = ShardManifest(
            collection_id="eth:0x123",
            shard_id=5,
            item_ids=["100", "101"],
            item_count=2,
            size_bytes=50000,
            merkle_root="QmShardRoot",
            torrent=torrent,
        )
        cbor_data = shard.to_cbor()
        restored = ShardManifest.from_cbor(cbor_data)
        assert restored.shard_id == 5

    def test_items_index_cbor_roundtrip(self):
        """ItemsIndex CBOR roundtrip."""
        items = [
            Item(
                item_id="1",
                name="Test",
                cid="Qm1",
                size_bytes=100,
                mime_type="text/plain",
                storage_type="ipfs",
                status="available",
            )
        ]
        index = ItemsIndex(collection_id="col:1", items=items)
        cbor_data = index.to_cbor()
        restored = ItemsIndex.from_cbor(cbor_data)
        assert len(restored.items) == 1


class TestFramingStreamMagicCheck:
    """Test Profile1 stream magic byte check."""

    def test_profile1_stream_bad_magic(self):
        """Profile 1 stream with wrong magic bytes."""
        # 20-byte header: Magic(4) + Version(2) + Type(2) + RequestID(4) + Length(4) + CRC(4)
        stream = io.BytesIO(b"XXXX" + b"\x00" * 16 + b"payload")
        from dcpp_python.framing import MagicBytesError

        with pytest.raises(MagicBytesError):
            Profile1Framer.decode(stream)

    def test_profile1_stream_checksum_failure(self):
        """Profile 1 stream with bad checksum."""
        import struct
        from dcpp_python.framing import ChecksumError
        import cbor2

        payload = cbor2.dumps({"test": "data"})
        wrong_crc = 0xDEADBEEF
        # Header: Magic(4) + Version(2) + Type(2) + RequestID(4) + Length(4) + CRC(4) = 20 bytes
        header = (
            b"DCPP"
            + b"\x01\x00"  # version
            + struct.pack(">H", MessageType.HELLO)
            + struct.pack(">I", 0)  # request_id
            + struct.pack(">I", len(payload))
            + struct.pack(">I", wrong_crc)
        )
        stream = io.BytesIO(header + payload)
        with pytest.raises(ChecksumError):
            Profile1Framer.decode(stream)


class TestProfile1StreamOversized:
    """Test Profile 1 stream with oversized length."""

    def test_profile1_stream_oversized(self):
        """Profile 1 stream claiming oversized payload."""
        import struct
        from dcpp_python.framing import MessageTooLargeError
        from dcpp_python.core.constants import MAX_MESSAGE_SIZE

        huge_len = MAX_MESSAGE_SIZE + 1000
        # Header: Magic(4) + Version(2) + Type(2) + RequestID(4) + Length(4) + CRC(4) = 20 bytes
        header = (
            b"DCPP"
            + b"\x01\x00"  # version
            + struct.pack(">H", MessageType.HELLO)
            + struct.pack(">I", 0)  # request_id
            + struct.pack(">I", huge_len)
            + struct.pack(">I", 0)  # fake CRC
        )
        stream = io.BytesIO(header)
        with pytest.raises(MessageTooLargeError):
            Profile1Framer.decode(stream)


class TestProfile1BytesOversized:
    """Test Profile 1 bytes with oversized length."""

    def test_profile1_bytes_oversized(self):
        """Profile 1 bytes claiming oversized payload."""
        import struct
        from dcpp_python.framing import MessageTooLargeError
        from dcpp_python.core.constants import MAX_MESSAGE_SIZE

        huge_len = MAX_MESSAGE_SIZE + 1000
        # Header: Magic(4) + Version(2) + Type(2) + RequestID(4) + Length(4) + CRC(4) = 20 bytes
        header = (
            b"DCPP"
            + b"\x01\x00"  # version
            + struct.pack(">H", MessageType.HELLO)
            + struct.pack(">I", 0)  # request_id
            + struct.pack(">I", huge_len)
            + struct.pack(">I", 0)  # fake CRC
        )
        # Provide enough bytes for header but not for claimed payload
        data = header + b"x" * 100
        with pytest.raises(MessageTooLargeError):
            Profile1Framer.decode(data)


class TestMessagesExtraFromCbor:
    """Test message from_cbor methods that weren't covered."""

    def test_announce_from_cbor(self):
        """Test Announce.from_cbor."""
        from dcpp_python.messages import Announce, CollectionAnnouncement

        announce = Announce(
            node_id=b"node",
            announce_seq=100,
            collections=[
                CollectionAnnouncement(id="test", manifest_cid="Qm", coverage=1.0)
            ],
            timestamp=1000,
            expires_at=2000,
            signature=b"sig",
        )
        restored = Announce.from_cbor(announce.to_cbor())
        assert restored.announce_seq == 100

    def test_get_manifest_from_cbor(self):
        """Test GetManifest.from_cbor."""
        from dcpp_python.messages import GetManifest

        msg = GetManifest(collection_id="test")
        restored = GetManifest.from_cbor(msg.to_cbor())
        assert restored.collection_id == "test"

    def test_manifest_response_from_cbor(self):
        """Test ManifestResponse.from_cbor."""
        from dcpp_python.messages import ManifestResponse

        msg = ManifestResponse(collection_id="test", manifest={"version": 1})
        restored = ManifestResponse.from_cbor(msg.to_cbor())
        assert restored.manifest["version"] == 1

    def test_get_peers_from_cbor(self):
        """Test GetPeers.from_cbor."""
        from dcpp_python.messages import GetPeers

        msg = GetPeers(collection_id="test", shard_id=5)
        restored = GetPeers.from_cbor(msg.to_cbor())
        assert restored.shard_id == 5

    def test_peers_response_from_cbor(self):
        """Test PeersResponse.from_cbor."""
        from dcpp_python.messages import PeersResponse, PeerInfo

        msg = PeersResponse(
            collection_id="test",
            peers=[
                PeerInfo(
                    node_id=b"peer",
                    multiaddrs=["/ip4/1.2.3.4/tcp/4001"],
                    coverage=1.0,
                    last_seen=1000,
                    response_quality=0.9,
                )
            ],
        )
        restored = PeersResponse.from_cbor(msg.to_cbor())
        assert len(restored.peers) == 1

    def test_health_probe_from_cbor(self):
        """Test HealthProbe.from_cbor."""
        from dcpp_python.messages import HealthProbe, Challenge

        msg = HealthProbe(
            collection_id="test",
            challenges=[Challenge(cid="Qm", offset=0, length=100)],
            nonce=b"nonce",
        )
        restored = HealthProbe.from_cbor(msg.to_cbor())
        assert len(restored.challenges) == 1

    def test_health_response_from_cbor(self):
        """Test HealthResponse.from_cbor."""
        from dcpp_python.messages import HealthResponse, ChallengeResponse

        msg = HealthResponse(
            nonce=b"nonce",
            responses=[ChallengeResponse(cid="Qm", data=b"data")],
        )
        restored = HealthResponse.from_cbor(msg.to_cbor())
        assert restored.responses[0].data == b"data"

    def test_goodbye_from_cbor(self):
        """Test Goodbye.from_cbor."""
        from dcpp_python.messages import Goodbye

        msg = Goodbye(reason="shutdown", collections=["col1"])
        restored = Goodbye.from_cbor(msg.to_cbor())
        assert restored.reason == "shutdown"

    def test_error_response_from_cbor(self):
        """Test ErrorResponse.from_cbor."""
        from dcpp_python.messages import ErrorResponse

        msg = ErrorResponse(code=1, message="error", request_type=3)
        restored = ErrorResponse.from_cbor(msg.to_cbor())
        assert restored.code == 1

    def test_invite_from_cbor(self):
        """Test Invite.from_cbor."""
        from dcpp_python.messages import Invite

        msg = Invite(
            collection_id="private:abc",
            invite_token=b"token",
            expires_at=2000,
            inviter_id=b"admin",
            permissions="member",
        )
        restored = Invite.from_cbor(msg.to_cbor())
        assert restored.permissions == "member"

    def test_join_from_cbor(self):
        """Test Join.from_cbor."""
        from dcpp_python.messages import Join

        msg = Join(
            collection_id="private:abc",
            invite_token=b"token",
            node_id=b"joiner",
            timestamp=1000,
        )
        restored = Join.from_cbor(msg.to_cbor())
        assert restored.node_id == b"joiner"

    def test_join_ack_from_cbor(self):
        """Test JoinAck.from_cbor."""
        from dcpp_python.messages import JoinAck

        msg = JoinAck(
            collection_id="private:abc",
            node_id=b"joiner",
            collection_key=b"key",
            member_since=1000,
            permissions="member",
        )
        restored = JoinAck.from_cbor(msg.to_cbor())
        assert restored.collection_key == b"key"

    def test_leave_from_cbor(self):
        """Test Leave.from_cbor."""
        from dcpp_python.messages import Leave

        msg = Leave(collection_id="private:abc", node_id=b"leaver", reason="bye")
        restored = Leave.from_cbor(msg.to_cbor())
        assert restored.reason == "bye"

    def test_revoke_from_cbor(self):
        """Test Revoke.from_cbor."""
        from dcpp_python.messages import Revoke

        msg = Revoke(
            collection_id="private:abc",
            revoked_node_id=b"bad",
            admin_id=b"admin",
            timestamp=1000,
            signature=b"sig",
            reason="violation",
        )
        restored = Revoke.from_cbor(msg.to_cbor())
        assert restored.reason == "violation"

    def test_get_members_from_cbor(self):
        """Test GetMembers.from_cbor."""
        from dcpp_python.messages import GetMembers

        msg = GetMembers(collection_id="private:abc", requester_id=b"admin")
        restored = GetMembers.from_cbor(msg.to_cbor())
        assert restored.requester_id == b"admin"

    def test_members_response_from_cbor(self):
        """Test MembersResponse.from_cbor."""
        from dcpp_python.messages import MembersResponse, MemberInfo

        msg = MembersResponse(
            collection_id="private:abc",
            members=[
                MemberInfo(
                    node_id=b"member",
                    permissions="member",
                    joined_at=1000,
                    last_seen=2000,
                    status="active",
                )
            ],
            total_count=1,
        )
        restored = MembersResponse.from_cbor(msg.to_cbor())
        assert restored.total_count == 1


class TestRemainingCoverage:
    """Tests for remaining uncovered lines."""

    def test_manifest_with_items_index_cid(self):
        """Manifest with items_index_cid set (not inline items)."""
        torrent = TorrentInfo(
            infohash="hash", magnet="magnet:?...", piece_length=262144
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type="nft-collection",
            access_mode="public",
            collection_id="eth:0xlarge",
            name="Large Collection",
            version=1,
            created_at=1000,
            updated_at=2000,
            total_items=50000,
            total_size_bytes=50 * 1024 ** 3,
            merkle_root="QmRoot",
            torrent=torrent,
            items=None,  # No inline items
            items_index_cid="QmItemsIndexCID123",  # External index
        )
        d = manifest.to_dict()
        assert d["items_index_cid"] == "QmItemsIndexCID123"
        assert "items" not in d

    def test_manifest_response_with_signature(self):
        """ManifestResponse with signature."""
        from dcpp_python.messages import ManifestResponse

        msg = ManifestResponse(
            collection_id="test",
            manifest={"version": 1},
            signature=b"curator_signature",  # With signature
        )
        d = msg.to_dict()
        assert d["signature"] == b"curator_signature"
        restored = ManifestResponse.from_cbor(msg.to_cbor())
        assert restored.signature == b"curator_signature"

    def test_revoke_to_signable_dict(self):
        """Test Revoke.to_signable_dict method."""
        from dcpp_python.messages import Revoke

        msg = Revoke(
            collection_id="private:abc",
            revoked_node_id=b"bad_peer",
            admin_id=b"admin",
            timestamp=1000,
            signature=b"sig",
            reason="policy violation",
        )
        signable = msg.to_signable_dict()
        assert "signature" not in signable
        assert signable["reason"] == "policy violation"
        assert signable["collection_id"] == "private:abc"

    def test_revoke_to_signable_dict_no_reason(self):
        """Test Revoke.to_signable_dict without reason."""
        from dcpp_python.messages import Revoke

        msg = Revoke(
            collection_id="private:xyz",
            revoked_node_id=b"peer",
            admin_id=b"admin",
            timestamp=2000,
            signature=b"sig",
            reason=None,  # No reason
        )
        signable = msg.to_signable_dict()
        assert "reason" not in signable

    def test_varint_stream_too_long(self):
        """Test varint decoding from stream that exceeds 64 bits."""
        # Create a stream with 10 continuation bytes (exceeds 64-bit varint)
        stream = io.BytesIO(b"\x80" * 10 + b"\x01")
        with pytest.raises(ValueError, match="too long"):
            decode_varint(stream)
