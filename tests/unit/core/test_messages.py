"""Tests for DCPP message types."""

import time
import pytest
import cbor2

from dcpp_python.core.constants import (
    Capability,
    ErrorCode,
    GoodbyeReason,
    MemberStatus,
    MessageType,
    Permission,
)
from dcpp_python.messages import (
    Announce,
    Challenge,
    ChallengeResponse,
    CollectionAnnouncement,
    ErrorResponse,
    GetManifest,
    GetMembers,
    GetPeers,
    Goodbye,
    HealthProbe,
    HealthResponse,
    Hello,
    Invite,
    InviteToken,
    Join,
    JoinAck,
    Leave,
    ManifestResponse,
    MemberInfo,
    MembersResponse,
    PeerInfo,
    PeersResponse,
    Revoke,
    decode_message,
)


class TestHello:
    """Test HELLO message (0x0001)."""

    def test_create_hello(self):
        """Create a HELLO message."""
        hello = Hello(
            version="1.0.0",
            node_id=b"test_peer_id",
            capabilities=[Capability.GUARDIAN, Capability.SEEDER],
            collections=["eth:0x1234", "polygon:0x5678"],
            timestamp=int(time.time()),
            user_agent="dcpp-py/0.1.0",
        )
        assert hello.MESSAGE_TYPE == MessageType.HELLO
        assert hello.node_id == b"test_peer_id"
        assert len(hello.capabilities) == 2
        assert hello.version == "1.0.0"

    def test_hello_to_dict(self):
        """Convert HELLO to dict."""
        hello = Hello(
            version="1.0.0",
            node_id=b"peer",
            capabilities=["guardian"],
            collections=["col1"],
            timestamp=1000,
            user_agent="test",
        )
        d = hello.to_dict()
        assert d["node_id"] == b"peer"
        assert d["capabilities"] == ["guardian"]
        assert d["user_agent"] == "test"
        assert d["version"] == "1.0.0"

    def test_hello_to_dict_no_user_agent(self):
        """HELLO without user_agent should not include it in dict."""
        hello = Hello(
            version="1.0.0",
            node_id=b"peer",
            capabilities=[],
            collections=[],
            timestamp=1000,
        )
        d = hello.to_dict()
        assert "user_agent" not in d
        assert d["version"] == "1.0.0"

    def test_hello_roundtrip(self):
        """Serialize and deserialize HELLO."""
        hello = Hello(
            version="1.0.0",
            node_id=b"peer_id_bytes",
            capabilities=[Capability.GUARDIAN],
            collections=["eth:0xabc"],
            timestamp=1234567890,
            user_agent="test/1.0",
        )
        cbor_data = hello.to_cbor()
        restored = Hello.from_cbor(cbor_data)

        assert restored.version == hello.version
        assert restored.node_id == hello.node_id
        assert restored.capabilities == hello.capabilities
        assert restored.collections == hello.collections
        assert restored.timestamp == hello.timestamp
        assert restored.user_agent == hello.user_agent

    def test_hello_missing_version_raises(self):
        """HELLO without version should raise ValueError during deserialization."""
        # Create a dict without version field
        data = {
            "node_id": b"peer",
            "capabilities": [],
            "collections": [],
            "timestamp": 1000,
        }
        cbor_data = cbor2.dumps(data)
        with pytest.raises(ValueError, match="missing required 'version' field"):
            Hello.from_cbor(cbor_data)


class TestAnnounce:
    """Test ANNOUNCE message (0x0002)."""

    def test_create_announce(self):
        """Create an ANNOUNCE message."""
        collections = [
            CollectionAnnouncement(
                id="eth:0x1234",
                manifest_cid="Qm...",
                coverage=1.0,
                shard_ids=[0, 1],
            )
        ]
        announce = Announce(
            node_id=b"peer",
            announce_seq=100,
            collections=collections,
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 3600,
            signature=b"sig",
        )
        assert announce.MESSAGE_TYPE == MessageType.ANNOUNCE

    def test_announce_signable_dict(self):
        """Get signable dict (without signature)."""
        announce = Announce(
            node_id=b"peer",
            announce_seq=1,
            collections=[],
            timestamp=1000,
            expires_at=2000,
            signature=b"signature",
        )
        signable = announce.to_signable_dict()
        assert "signature" not in signable
        assert signable["node_id"] == b"peer"

    def test_announce_roundtrip(self):
        """Serialize and deserialize ANNOUNCE."""
        collections = [
            CollectionAnnouncement(
                id="eth:0x1234",
                manifest_cid="QmTest123",
                coverage=0.75,
                shard_ids=[2, 3],
            )
        ]
        announce = Announce(
            node_id=b"test_node",
            announce_seq=42,
            collections=collections,
            timestamp=1000000,
            expires_at=1003600,
            signature=b"sig_bytes",
        )
        cbor_data = announce.to_cbor()
        restored = Announce.from_cbor(cbor_data)

        assert restored.node_id == announce.node_id
        assert restored.announce_seq == announce.announce_seq
        assert len(restored.collections) == 1
        assert restored.collections[0].id == "eth:0x1234"
        assert restored.collections[0].shard_ids == [2, 3]


class TestGetManifest:
    """Test GET_MANIFEST message (0x0003)."""

    def test_create_get_manifest(self):
        """Create GET_MANIFEST message."""
        msg = GetManifest(collection_id="eth:0xabc")
        assert msg.MESSAGE_TYPE == MessageType.GET_MANIFEST
        assert msg.version is None

    def test_get_manifest_with_version(self):
        """GET_MANIFEST with specific version."""
        msg = GetManifest(collection_id="eth:0xabc", version=5)
        d = msg.to_dict()
        assert d["version"] == 5

    def test_get_manifest_diff_mode(self):
        """GET_MANIFEST with since_version for diff."""
        msg = GetManifest(collection_id="eth:0xabc", since_version=3)
        d = msg.to_dict()
        assert d["since_version"] == 3

    def test_get_manifest_roundtrip(self):
        """Serialize and deserialize GET_MANIFEST."""
        msg = GetManifest(
            collection_id="polygon:0x123", version=10, since_version=5
        )
        restored = GetManifest.from_cbor(msg.to_cbor())
        assert restored.collection_id == msg.collection_id
        assert restored.version == msg.version
        assert restored.since_version == msg.since_version


class TestManifestResponse:
    """Test MANIFEST message (0x0004)."""

    def test_create_manifest_response(self):
        """Create MANIFEST response."""
        manifest = {
            "protocol": "dcpp/1.0",
            "type": "nft-collection",
            "name": "Test Collection",
        }
        msg = ManifestResponse(
            collection_id="eth:0x123", manifest=manifest, signature=b"curator_sig"
        )
        assert msg.MESSAGE_TYPE == MessageType.MANIFEST

    def test_manifest_response_roundtrip(self):
        """Serialize and deserialize MANIFEST."""
        manifest = {"version": 1, "items": []}
        msg = ManifestResponse(collection_id="test", manifest=manifest)
        restored = ManifestResponse.from_cbor(msg.to_cbor())
        assert restored.collection_id == msg.collection_id
        assert restored.manifest == manifest
        assert restored.signature is None


class TestGetPeers:
    """Test GET_PEERS message (0x0005)."""

    def test_create_get_peers(self):
        """Create GET_PEERS message."""
        msg = GetPeers(collection_id="eth:0xabc")
        assert msg.MESSAGE_TYPE == MessageType.GET_PEERS
        assert msg.max_peers == 20  # Default

    def test_get_peers_with_shard(self):
        """GET_PEERS for specific shard."""
        msg = GetPeers(collection_id="eth:0xabc", shard_id=5, max_peers=50)
        d = msg.to_dict()
        assert d["shard_id"] == 5
        assert d["max_peers"] == 50


class TestPeersResponse:
    """Test PEERS message (0x0006)."""

    def test_create_peers_response(self):
        """Create PEERS response."""
        peers = [
            PeerInfo(
                node_id=b"peer1",
                multiaddrs=["/ip4/192.168.1.1/tcp/4001"],
                coverage=1.0,
                last_seen=int(time.time()),
                response_quality=0.95,
            ),
            PeerInfo(
                node_id=b"peer2",
                multiaddrs=["/ip4/10.0.0.1/tcp/4001"],
                coverage=0.5,
                last_seen=int(time.time()) - 60,
                response_quality=0.8,
            ),
        ]
        msg = PeersResponse(collection_id="eth:0x123", peers=peers)
        assert msg.MESSAGE_TYPE == MessageType.PEERS
        assert len(msg.peers) == 2

    def test_peers_response_roundtrip(self):
        """Serialize and deserialize PEERS."""
        peers = [
            PeerInfo(
                node_id=b"test_peer",
                multiaddrs=["/dns/example.com/tcp/4001"],
                coverage=0.75,
                last_seen=1000000,
                response_quality=0.9,
            )
        ]
        msg = PeersResponse(collection_id="col", peers=peers)
        restored = PeersResponse.from_cbor(msg.to_cbor())
        assert len(restored.peers) == 1
        assert restored.peers[0].node_id == b"test_peer"
        assert restored.peers[0].response_quality == 0.9


class TestHealthProbe:
    """Test HEALTH_PROBE message (0x0007)."""

    def test_create_health_probe(self):
        """Create HEALTH_PROBE message."""
        challenges = [
            Challenge(cid="QmTest123", offset=1024, length=256),
            Challenge(cid="QmTest456", offset=0, length=512),
        ]
        msg = HealthProbe(
            collection_id="eth:0x123", challenges=challenges, nonce=b"random_nonce"
        )
        assert msg.MESSAGE_TYPE == MessageType.HEALTH_PROBE
        assert len(msg.challenges) == 2

    def test_health_probe_roundtrip(self):
        """Serialize and deserialize HEALTH_PROBE."""
        challenges = [Challenge(cid="Qm123", offset=100, length=50)]
        msg = HealthProbe(
            collection_id="test", challenges=challenges, nonce=b"nonce123"
        )
        restored = HealthProbe.from_cbor(msg.to_cbor())
        assert restored.nonce == b"nonce123"
        assert restored.challenges[0].cid == "Qm123"
        assert restored.challenges[0].offset == 100


class TestHealthResponse:
    """Test HEALTH_RESPONSE message (0x0008)."""

    def test_create_health_response(self):
        """Create HEALTH_RESPONSE message."""
        responses = [
            ChallengeResponse(cid="Qm123", data=b"chunk_data"),
            ChallengeResponse(cid="Qm456", error="Content not available"),
        ]
        msg = HealthResponse(nonce=b"nonce123", responses=responses)
        assert msg.MESSAGE_TYPE == MessageType.HEALTH_RESPONSE

    def test_health_response_roundtrip(self):
        """Serialize and deserialize HEALTH_RESPONSE."""
        responses = [
            ChallengeResponse(cid="Qm1", data=b"\x00\x01\x02"),
            ChallengeResponse(cid="Qm2", error="Not found"),
        ]
        msg = HealthResponse(nonce=b"test_nonce", responses=responses)
        restored = HealthResponse.from_cbor(msg.to_cbor())
        assert restored.nonce == b"test_nonce"
        assert restored.responses[0].data == b"\x00\x01\x02"
        assert restored.responses[1].error == "Not found"


class TestGoodbye:
    """Test GOODBYE message (0x0009)."""

    def test_create_goodbye(self):
        """Create GOODBYE message."""
        msg = Goodbye(
            reason=GoodbyeReason.SHUTDOWN,
            collections=["eth:0x123", "eth:0x456"],
        )
        assert msg.MESSAGE_TYPE == MessageType.GOODBYE

    def test_goodbye_without_collections(self):
        """GOODBYE without collections list."""
        msg = Goodbye(reason=GoodbyeReason.MAINTENANCE)
        d = msg.to_dict()
        assert "collections" not in d

    def test_goodbye_roundtrip(self):
        """Serialize and deserialize GOODBYE."""
        msg = Goodbye(reason="leaving_collection", collections=["col1"])
        restored = Goodbye.from_cbor(msg.to_cbor())
        assert restored.reason == "leaving_collection"
        assert restored.collections == ["col1"]


class TestErrorResponse:
    """Test ERROR message (0x00FF)."""

    def test_create_error(self):
        """Create ERROR message."""
        msg = ErrorResponse(
            code=ErrorCode.UNKNOWN_COLLECTION,
            message="Collection not found",
            request_type=MessageType.GET_MANIFEST,
        )
        assert msg.MESSAGE_TYPE == MessageType.ERROR

    def test_error_roundtrip(self):
        """Serialize and deserialize ERROR."""
        msg = ErrorResponse(
            code=ErrorCode.RATE_LIMITED,
            message="Too many requests",
            request_type=MessageType.GET_PEERS,
        )
        restored = ErrorResponse.from_cbor(msg.to_cbor())
        assert restored.code == ErrorCode.RATE_LIMITED
        assert restored.message == "Too many requests"


class TestMembershipMessages:
    """Test membership messages for private collections."""

    def test_invite(self):
        """Test INVITE message."""
        msg = Invite(
            collection_id="private:abc123",
            invite_token=b"token_bytes",
            expires_at=int(time.time()) + 86400,
            inviter_id=b"admin_peer",
            permissions=Permission.MEMBER,
        )
        assert msg.MESSAGE_TYPE == MessageType.INVITE

        restored = Invite.from_cbor(msg.to_cbor())
        assert restored.permissions == Permission.MEMBER

    def test_invite_token(self):
        """Test InviteToken structure."""
        token = InviteToken(
            collection_id="private:xyz",
            created_at=1000,
            expires_at=2000,
            permissions=Permission.ADMIN,
            signature=b"sig",
        )
        signable = token.to_signable_dict()
        assert "signature" not in signable
        assert signable["permissions"] == Permission.ADMIN

    def test_join(self):
        """Test JOIN message."""
        msg = Join(
            collection_id="private:abc",
            invite_token=b"token",
            node_id=b"joining_peer",
            timestamp=int(time.time()),
        )
        assert msg.MESSAGE_TYPE == MessageType.JOIN

    def test_join_ack(self):
        """Test JOIN_ACK message."""
        msg = JoinAck(
            collection_id="private:abc",
            node_id=b"joined_peer",
            collection_key=b"encrypted_key_here",
            member_since=int(time.time()),
            permissions=Permission.MEMBER,
        )
        assert msg.MESSAGE_TYPE == MessageType.JOIN_ACK

    def test_leave(self):
        """Test LEAVE message."""
        msg = Leave(
            collection_id="private:abc",
            node_id=b"leaving_peer",
            reason="Moving to new device",
        )
        assert msg.MESSAGE_TYPE == MessageType.LEAVE

        # Without reason
        msg2 = Leave(collection_id="private:xyz", node_id=b"peer")
        d = msg2.to_dict()
        assert "reason" not in d

    def test_revoke(self):
        """Test REVOKE message."""
        msg = Revoke(
            collection_id="private:abc",
            revoked_node_id=b"bad_peer",
            admin_id=b"admin_peer",
            timestamp=int(time.time()),
            signature=b"admin_signature",
            reason="Policy violation",
        )
        assert msg.MESSAGE_TYPE == MessageType.REVOKE

    def test_get_members(self):
        """Test GET_MEMBERS message."""
        msg = GetMembers(collection_id="private:abc", requester_id=b"admin")
        assert msg.MESSAGE_TYPE == MessageType.GET_MEMBERS

    def test_members_response(self):
        """Test MEMBERS response."""
        members = [
            MemberInfo(
                node_id=b"peer1",
                permissions=Permission.ADMIN,
                joined_at=1000,
                last_seen=2000,
                status=MemberStatus.ACTIVE,
            ),
            MemberInfo(
                node_id=b"peer2",
                permissions=Permission.MEMBER,
                joined_at=1500,
                last_seen=1800,
                status=MemberStatus.OFFLINE,
            ),
        ]
        msg = MembersResponse(
            collection_id="private:abc", members=members, total_count=2
        )
        assert msg.MESSAGE_TYPE == MessageType.MEMBERS

        restored = MembersResponse.from_cbor(msg.to_cbor())
        assert len(restored.members) == 2
        assert restored.members[0].status == MemberStatus.ACTIVE


class TestDecodeMessage:
    """Test generic message decoding."""

    def test_decode_known_message_types(self):
        """Decode various message types using generic function."""
        # HELLO
        hello = Hello(
            version="1.0.0",
            node_id=b"peer", capabilities=[], collections=[], timestamp=1000
        )
        decoded = decode_message(MessageType.HELLO, hello.to_cbor())
        assert isinstance(decoded, Hello)

        # ERROR
        error = ErrorResponse(code=1, message="test", request_type=1)
        decoded = decode_message(MessageType.ERROR, error.to_cbor())
        assert isinstance(decoded, ErrorResponse)

    def test_decode_unknown_type_raises(self):
        """Decoding unknown message type should raise."""
        with pytest.raises(KeyError):
            decode_message(0x9999, b"\xa0")  # Invalid type


class TestMessageFieldLimits:
    """Test message field limits from spec."""

    def test_hello_many_collections(self):
        """HELLO can have up to 100 collections (Section 13.2.2)."""
        collections = [f"eth:0x{i:04x}" for i in range(100)]
        hello = Hello(
            version="1.0.0",
            node_id=b"peer",
            capabilities=[],
            collections=collections,
            timestamp=1000,
        )
        # Should successfully create and serialize
        cbor_data = hello.to_cbor()
        restored = Hello.from_cbor(cbor_data)
        assert len(restored.collections) == 100

    def test_announce_many_collections(self):
        """ANNOUNCE can have up to 50 collections (Section 13.2.2)."""
        collections = [
            CollectionAnnouncement(
                id=f"eth:0x{i:04x}", manifest_cid=f"Qm{i}", coverage=1.0
            )
            for i in range(50)
        ]
        announce = Announce(
            node_id=b"peer",
            announce_seq=1,
            collections=collections,
            timestamp=1000,
            expires_at=2000,
            signature=b"sig",
        )
        cbor_data = announce.to_cbor()
        restored = Announce.from_cbor(cbor_data)
        assert len(restored.collections) == 50


class TestChallengeValidation:
    """Test Challenge validation for offset/length edge cases."""

    def test_challenge_length_clamped_to_max(self):
        """Challenge length should be clamped to MAX_LENGTH (1024)."""
        challenge = Challenge(cid="QmTest", offset=0, length=2048)
        assert challenge.length == 1024

    def test_challenge_negative_offset_flagged(self):
        """Negative offset should be flagged and normalized to 0."""
        challenge = Challenge(cid="QmTest", offset=-100, length=256)
        assert challenge.offset == 0
        assert challenge._invalid_offset is True
        assert challenge._invalid_length is False

    def test_challenge_negative_length_flagged(self):
        """Negative length should be flagged and normalized to 0."""
        challenge = Challenge(cid="QmTest", offset=0, length=-50)
        assert challenge.length == 0
        assert challenge._invalid_length is True
        assert challenge._invalid_offset is False

    def test_challenge_both_negative(self):
        """Both negative offset and length should be flagged."""
        challenge = Challenge(cid="QmTest", offset=-10, length=-20)
        assert challenge.offset == 0
        assert challenge.length == 0
        assert challenge._invalid_offset is True
        assert challenge._invalid_length is True

    def test_challenge_valid_values_not_flagged(self):
        """Valid positive values should not be flagged."""
        challenge = Challenge(cid="QmTest", offset=100, length=256)
        assert challenge.offset == 100
        assert challenge.length == 256
        assert challenge._invalid_offset is False
        assert challenge._invalid_length is False

    def test_challenge_zero_offset_valid(self):
        """Zero offset should be valid."""
        challenge = Challenge(cid="QmTest", offset=0, length=256)
        assert challenge.offset == 0
        assert challenge._invalid_offset is False

    def test_challenge_from_dict_negative_offset(self):
        """from_dict with negative offset should flag it."""
        data = {"cid": "QmTest", "offset": -50, "length": 256}
        challenge = Challenge.from_dict(data)
        assert challenge.offset == 0
        assert challenge._invalid_offset is True

    def test_challenge_from_dict_negative_length(self):
        """from_dict with negative length should flag it."""
        data = {"cid": "QmTest", "offset": 100, "length": -100}
        challenge = Challenge.from_dict(data)
        assert challenge.length == 0
        assert challenge._invalid_length is True

    def test_new_validated_rejects_negative_offset(self):
        """new_validated should raise ValueError for negative offset."""
        with pytest.raises(ValueError, match="Invalid offset.*must be non-negative"):
            Challenge.new_validated(cid="QmTest", offset=-10, length=100, item_size=1000)

    def test_new_validated_rejects_negative_length(self):
        """new_validated should raise ValueError for negative length."""
        with pytest.raises(ValueError, match="Invalid length.*must be positive"):
            Challenge.new_validated(cid="QmTest", offset=0, length=-50, item_size=1000)

    def test_new_validated_rejects_zero_length(self):
        """new_validated should raise ValueError for zero length."""
        with pytest.raises(ValueError, match="Invalid length.*must be positive"):
            Challenge.new_validated(cid="QmTest", offset=0, length=0, item_size=1000)

    def test_new_validated_accepts_valid_values(self):
        """new_validated should accept valid positive values."""
        challenge = Challenge.new_validated(cid="QmTest", offset=100, length=256, item_size=1000)
        assert challenge.offset == 100
        assert challenge.length == 256
        assert challenge._invalid_offset is False
        assert challenge._invalid_length is False
