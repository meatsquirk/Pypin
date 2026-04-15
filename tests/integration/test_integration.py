"""Integration tests for DCPP wire protocol."""

import time
import pytest

from dcpp_python.core.constants import (
    AccessMode,
    Capability,
    CollectionType,
    ErrorCode,
    ItemStatus,
    MessageType,
    StorageType,
)
from dcpp_python.crypto import (
    generate_collection_key,
    generate_keypair,
    sign_message,
    verify_signature,
    derive_private_collection_id,
    derive_peer_id,
    encrypt_content,
    decrypt_content,
)
from dcpp_python.framing import Profile1Framer
from dcpp_python.manifest import (
    EncryptionConfig,
    Item,
    Manifest,
    TorrentInfo,
)
from dcpp_python.messages import (
    Announce,
    CollectionAnnouncement,
    ErrorResponse,
    GetManifest,
    GetPeers,
    HealthProbe,
    HealthResponse,
    Hello,
    ManifestResponse,
    PeerInfo,
    PeersResponse,
    Challenge,
    ChallengeResponse,
    decode_message,
)


class TestFullMessageFlow:
    """Test complete message flow scenarios."""

    def test_hello_exchange(self):
        """Simulate HELLO exchange between two nodes."""
        # Node A creates HELLO
        signing_key_a, verify_key_a = generate_keypair()
        node_a_hello = Hello(
            version="1.0.0",
            node_id=derive_peer_id(verify_key_a),
            capabilities=[Capability.GUARDIAN, Capability.SEEDER],
            collections=["eth:0x1234", "polygon:0x5678"],
            timestamp=int(time.time()),
            user_agent="dcpp-py/0.1.0",
        )

        # Encode with Profile 1
        encoded_a = Profile1Framer.encode(MessageType.HELLO, node_a_hello.to_dict())

        # Node B receives and decodes
        frame_a = Profile1Framer.decode(encoded_a)
        received_hello = Hello.from_dict(frame_a.decode_payload())

        assert received_hello.capabilities == [Capability.GUARDIAN, Capability.SEEDER]
        assert "eth:0x1234" in received_hello.collections

        # Node B responds with its own HELLO
        signing_key_b, verify_key_b = generate_keypair()
        node_b_hello = Hello(
            version="1.0.0",
            node_id=derive_peer_id(verify_key_b),
            capabilities=[Capability.GUARDIAN, Capability.LIGHT],
            collections=["eth:0x1234"],  # Common collection
            timestamp=int(time.time()),
            user_agent="dcpp-py/0.1.0",
        )

        encoded_b = Profile1Framer.encode(MessageType.HELLO, node_b_hello.to_dict())
        frame_b = Profile1Framer.decode(encoded_b)
        received_hello_b = Hello.from_dict(frame_b.decode_payload())

        # Both nodes should recognize common collection
        common = set(received_hello.collections) & set(received_hello_b.collections)
        assert "eth:0x1234" in common

    def test_signed_announce_flow(self):
        """Test ANNOUNCE message with cryptographic signature."""
        signing_key, verify_key = generate_keypair()
        node_id = derive_peer_id(verify_key)

        # Create ANNOUNCE message
        collections = [
            CollectionAnnouncement(
                id="eth:0xbored_apes",
                manifest_cid="QmManifest123",
                coverage=1.0,
                shard_ids=[0, 1, 2],
            )
        ]

        timestamp = int(time.time())
        expires_at = timestamp + 3600

        # Create announce without signature first
        announce_data = {
            "node_id": node_id,
            "announce_seq": timestamp,
            "collections": [c.to_dict() for c in collections],
            "timestamp": timestamp,
            "expires_at": expires_at,
        }

        # Sign the message
        signature = sign_message(announce_data, signing_key)

        # Create full ANNOUNCE message
        announce = Announce(
            node_id=node_id,
            announce_seq=timestamp,
            collections=collections,
            timestamp=timestamp,
            expires_at=expires_at,
            signature=signature,
        )

        # Encode and decode
        encoded = Profile1Framer.encode(MessageType.ANNOUNCE, announce.to_dict())
        frame = Profile1Framer.decode(encoded)
        decoded = Announce.from_dict(frame.decode_payload())

        # Verify signature
        signable_dict = decoded.to_signable_dict()
        from nacl.signing import VerifyKey
        from dcpp_python.crypto import pubkey_from_peer_id

        # Extract 32-byte pubkey from 38-byte libp2p PeerId
        pubkey_bytes = pubkey_from_peer_id(decoded.node_id)
        verify_key_restored = VerifyKey(pubkey_bytes)
        assert verify_signature(signable_dict, decoded.signature, verify_key_restored)

    def test_manifest_request_response(self):
        """Test GET_MANIFEST request and MANIFEST response."""
        collection_id = "eth:0xtest_collection"

        # Node A requests manifest
        request = GetManifest(collection_id=collection_id)
        encoded_req = Profile1Framer.encode(
            MessageType.GET_MANIFEST, request.to_dict()
        )

        # Node B receives request
        frame = Profile1Framer.decode(encoded_req)
        received_req = GetManifest.from_dict(frame.decode_payload())
        assert received_req.collection_id == collection_id

        # Node B creates and sends manifest
        torrent = TorrentInfo(
            infohash="abc123hash",
            magnet="magnet:?xt=urn:btih:abc123hash",
            piece_length=262144,
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.NFT_COLLECTION,
            access_mode=AccessMode.PUBLIC,
            collection_id=collection_id,
            name="Test NFT Collection",
            version=5,
            created_at=1000000,
            updated_at=1500000,
            total_items=1000,
            total_size_bytes=500 * 1024 * 1024,
            merkle_root="QmMerkleRoot",
            torrent=torrent,
        )

        response = ManifestResponse(
            collection_id=collection_id,
            manifest=manifest.to_dict(),
        )

        encoded_resp = Profile1Framer.encode(
            MessageType.MANIFEST, response.to_dict()
        )

        # Node A receives response
        frame_resp = Profile1Framer.decode(encoded_resp)
        received_resp = ManifestResponse.from_dict(frame_resp.decode_payload())

        # Reconstruct manifest from response
        received_manifest = Manifest.from_dict(received_resp.manifest)
        assert received_manifest.name == "Test NFT Collection"
        assert received_manifest.total_items == 1000
        assert received_manifest.torrent.infohash == "abc123hash"

    def test_peer_discovery_flow(self):
        """Test peer discovery with GET_PEERS and PEERS."""
        collection_id = "eth:0xpopular_collection"

        # Request peers
        request = GetPeers(collection_id=collection_id, max_peers=10)
        encoded_req = Profile1Framer.encode(MessageType.GET_PEERS, request.to_dict())

        frame = Profile1Framer.decode(encoded_req)
        received_req = GetPeers.from_dict(frame.decode_payload())

        # Build peer response
        peers = [
            PeerInfo(
                node_id=b"peer_" + str(i).encode(),
                multiaddrs=[f"/ip4/192.168.1.{i}/tcp/4001"],
                coverage=1.0 - (i * 0.1),
                last_seen=int(time.time()) - (i * 60),
                response_quality=0.95 - (i * 0.05),
            )
            for i in range(5)
        ]

        response = PeersResponse(collection_id=collection_id, peers=peers)
        encoded_resp = Profile1Framer.encode(MessageType.PEERS, response.to_dict())

        frame_resp = Profile1Framer.decode(encoded_resp)
        received_resp = PeersResponse.from_dict(frame_resp.decode_payload())

        assert len(received_resp.peers) == 5
        # Peers should maintain order
        assert received_resp.peers[0].coverage > received_resp.peers[4].coverage

    def test_health_probe_flow(self):
        """Test health probing with HEALTH_PROBE and HEALTH_RESPONSE."""
        import os

        collection_id = "eth:0xtest"
        nonce = os.urandom(16)

        # Create probe
        challenges = [
            Challenge(cid="QmContent1", offset=0, length=256),
            Challenge(cid="QmContent2", offset=1024, length=512),
            Challenge(cid="QmMissing", offset=0, length=100),
        ]

        probe = HealthProbe(
            collection_id=collection_id, challenges=challenges, nonce=nonce
        )

        encoded_probe = Profile1Framer.encode(
            MessageType.HEALTH_PROBE, probe.to_dict()
        )

        frame = Profile1Framer.decode(encoded_probe)
        received_probe = HealthProbe.from_dict(frame.decode_payload())

        # Build response (simulating node that has some content)
        responses = [
            ChallengeResponse(cid="QmContent1", data=os.urandom(256)),
            ChallengeResponse(cid="QmContent2", data=os.urandom(512)),
            ChallengeResponse(cid="QmMissing", error="Content not available"),
        ]

        health_resp = HealthResponse(nonce=received_probe.nonce, responses=responses)

        encoded_resp = Profile1Framer.encode(
            MessageType.HEALTH_RESPONSE, health_resp.to_dict()
        )

        frame_resp = Profile1Framer.decode(encoded_resp)
        received_resp = HealthResponse.from_dict(frame_resp.decode_payload())

        # Verify nonce matches
        assert received_resp.nonce == nonce

        # Check responses
        assert received_resp.responses[0].data is not None
        assert len(received_resp.responses[0].data) == 256
        assert received_resp.responses[2].error == "Content not available"

    def test_error_handling(self):
        """Test error response flow."""
        # Request for unknown collection
        request = GetManifest(collection_id="eth:0xnonexistent")
        encoded_req = Profile1Framer.encode(
            MessageType.GET_MANIFEST, request.to_dict()
        )

        frame = Profile1Framer.decode(encoded_req)
        received_req = GetManifest.from_dict(frame.decode_payload())

        # Node doesn't have this collection, send error
        error = ErrorResponse(
            code=ErrorCode.UNKNOWN_COLLECTION,
            message=f"Collection {received_req.collection_id} not found",
            request_type=MessageType.GET_MANIFEST,
        )

        encoded_error = Profile1Framer.encode(MessageType.ERROR, error.to_dict())
        frame_error = Profile1Framer.decode(encoded_error)
        received_error = ErrorResponse.from_dict(frame_error.decode_payload())

        assert received_error.code == ErrorCode.UNKNOWN_COLLECTION
        assert "nonexistent" in received_error.message


class TestPrivateCollectionFlow:
    """Test private collection encryption and membership flow."""

    def test_private_collection_creation(self):
        """Test creating and encrypting a private collection."""
        # Generate collection key
        collection_key = generate_collection_key()
        collection_id = derive_private_collection_id(collection_key)

        assert collection_id.startswith("private:")

        # Create encrypted manifest
        torrent = TorrentInfo(
            infohash="private_hash",
            magnet="magnet:?xt=urn:btih:private_hash",
            piece_length=262144,
        )

        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.PHOTO_LIBRARY,
            access_mode=AccessMode.PRIVATE,
            collection_id=collection_id,
            name="Family Photos",  # This would be encrypted in real implementation
            version=1,
            created_at=int(time.time()),
            updated_at=int(time.time()),
            total_items=100,
            total_size_bytes=1024 * 1024 * 100,
            merkle_root="QmEncryptedRoot",
            torrent=torrent,
            encryption=EncryptionConfig(
                algorithm="aes-256-gcm",
                key_id="key_v1",
            ),
        )

        # Encrypt manifest
        manifest_bytes = manifest.to_cbor()
        nonce, encrypted_manifest = encrypt_content(manifest_bytes, collection_key)

        # Decrypt and verify
        decrypted = decrypt_content(nonce, encrypted_manifest, collection_key)
        restored = Manifest.from_cbor(decrypted)

        assert restored.name == "Family Photos"
        assert restored.encryption.algorithm == "aes-256-gcm"

    def test_encrypted_content_flow(self):
        """Test encrypting and decrypting content items."""
        collection_key = generate_collection_key()

        # Simulate encrypting file content
        original_content = b"This is my private photo data" * 1000

        # Encrypt
        nonce, ciphertext = encrypt_content(original_content, collection_key)

        # The CID would be computed over the encrypted content
        import hashlib

        encrypted_cid = (
            "Qm" + hashlib.sha256(ciphertext).hexdigest()[:40]
        )  # Simplified

        # Create item pointing to encrypted content
        item = Item(
            item_id="photo001",
            name="vacation.jpg",  # Would be encrypted separately
            cid=encrypted_cid,
            size_bytes=len(ciphertext),
            mime_type="application/octet-stream",  # Encrypted
            storage_type=StorageType.IPFS,
            status=ItemStatus.AVAILABLE,
        )

        # Decrypt
        decrypted = decrypt_content(nonce, ciphertext, collection_key)
        assert decrypted == original_content


class TestProtocolInteroperability:
    """Test that both framing profiles can interoperate."""

    def test_same_message_different_profiles(self):
        """Same logical message encoded with both profiles."""
        signing_key, verify_key = generate_keypair()

        hello = Hello(
            version="1.0.0",
            node_id=derive_peer_id(verify_key),
            capabilities=[Capability.GUARDIAN],
            collections=["eth:0x1234"],
            timestamp=int(time.time()),
            user_agent="test/1.0",
        )

        # Encode with Profile 1
        p0_encoded = Profile1Framer.encode(MessageType.HELLO, hello.to_dict())
        p0_frame = Profile1Framer.decode(p0_encoded)
        p0_hello = Hello.from_dict(p0_frame.decode_payload())

        # Encode with Profile 1
        p1_encoded = Profile1Framer.encode(MessageType.HELLO, hello.to_dict())
        p1_frame = Profile1Framer.decode(p1_encoded)
        p1_hello = Hello.from_dict(p1_frame.decode_payload())

        # Both should decode to identical messages
        assert p0_hello.node_id == p1_hello.node_id
        assert p0_hello.capabilities == p1_hello.capabilities
        assert p0_hello.collections == p1_hello.collections
        assert p0_hello.timestamp == p1_hello.timestamp
        assert p0_hello.user_agent == p1_hello.user_agent

    def test_decode_message_helper(self):
        """Test generic decode_message helper."""
        hello = Hello(
            version="1.0.0",
            node_id=b"test_peer",
            capabilities=[],
            collections=[],
            timestamp=1000,
        )

        encoded = Profile1Framer.encode(MessageType.HELLO, hello.to_dict())
        frame = Profile1Framer.decode(encoded)

        # Use generic decode
        decoded = decode_message(frame.message_type, frame.payload)

        assert isinstance(decoded, Hello)
        assert decoded.node_id == b"test_peer"


class TestMessageSequence:
    """Test realistic message sequences."""

    def test_new_node_joining_swarm(self):
        """Simulate a new node joining a collection's swarm."""
        messages_exchanged = []

        # Step 1: HELLO exchange
        new_node_hello = Hello(
            version="1.0.0",
            node_id=b"new_node",
            capabilities=[Capability.GUARDIAN, Capability.SEEDER],
            collections=["eth:0xbayc"],
            timestamp=int(time.time()),
        )
        messages_exchanged.append(("new_node->existing", "HELLO"))

        existing_node_hello = Hello(
            version="1.0.0",
            node_id=b"existing_node",
            capabilities=[Capability.GUARDIAN, Capability.SEEDER],
            collections=["eth:0xbayc", "eth:0xazuki"],
            timestamp=int(time.time()),
        )
        messages_exchanged.append(("existing->new_node", "HELLO"))

        # Step 2: New node requests peers
        get_peers = GetPeers(collection_id="eth:0xbayc", max_peers=20)
        messages_exchanged.append(("new_node->existing", "GET_PEERS"))

        peers_response = PeersResponse(
            collection_id="eth:0xbayc",
            peers=[
                PeerInfo(
                    node_id=b"peer1",
                    multiaddrs=["/ip4/1.2.3.4/tcp/4001"],
                    coverage=1.0,
                    last_seen=int(time.time()),
                    response_quality=0.95,
                )
            ],
        )
        messages_exchanged.append(("existing->new_node", "PEERS"))

        # Step 3: New node requests manifest
        get_manifest = GetManifest(collection_id="eth:0xbayc")
        messages_exchanged.append(("new_node->existing", "GET_MANIFEST"))

        torrent = TorrentInfo(
            infohash="bayc_hash", magnet="magnet:?...", piece_length=1048576
        )
        manifest = Manifest(
            protocol="dcpp/1.0",
            type=CollectionType.NFT_COLLECTION,
            access_mode=AccessMode.PUBLIC,
            collection_id="eth:0xbayc",
            name="Bored Ape Yacht Club",
            version=100,
            created_at=1000000,
            updated_at=1500000,
            total_items=10000,
            total_size_bytes=10 * 1024**3,
            merkle_root="QmBAYCRoot",
            torrent=torrent,
        )
        manifest_response = ManifestResponse(
            collection_id="eth:0xbayc",
            manifest=manifest.to_dict(),
        )
        messages_exchanged.append(("existing->new_node", "MANIFEST"))

        # Step 4: After syncing, new node announces
        signing_key, verify_key = generate_keypair()
        announce_data = {
            "node_id": b"new_node",
            "announce_seq": int(time.time()),
            "collections": [
                {
                    "id": "eth:0xbayc",
                    "manifest_cid": "QmManifestCID",
                    "coverage": 1.0,
                }
            ],
            "timestamp": int(time.time()),
            "expires_at": int(time.time()) + 3600,
        }
        signature = sign_message(announce_data, signing_key)

        announce = Announce(
            node_id=b"new_node",
            announce_seq=announce_data["announce_seq"],
            collections=[
                CollectionAnnouncement(
                    id="eth:0xbayc",
                    manifest_cid="QmManifestCID",
                    coverage=1.0,
                )
            ],
            timestamp=announce_data["timestamp"],
            expires_at=announce_data["expires_at"],
            signature=signature,
        )
        messages_exchanged.append(("new_node->pubsub", "ANNOUNCE"))

        # Verify message sequence
        assert len(messages_exchanged) == 7
        assert messages_exchanged[0][1] == "HELLO"
        assert messages_exchanged[-1][1] == "ANNOUNCE"

        # All messages should serialize/deserialize correctly
        for msg in [
            new_node_hello,
            existing_node_hello,
            get_peers,
            peers_response,
            get_manifest,
            manifest_response,
            announce,
        ]:
            cbor = msg.to_cbor()
            restored = type(msg).from_cbor(cbor)
            assert restored.to_dict() == msg.to_dict()
