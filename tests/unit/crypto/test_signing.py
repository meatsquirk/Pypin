"""Tests for DCPP signature verification."""

import time

import pytest
from nacl.signing import SigningKey

from dcpp_python.crypto import (
    derive_peer_id,
    ed25519_pubkey_to_peer_id,
    generate_keypair,
    pubkey_from_peer_id,
    sign_announce,
    verify_announce,
    verify_announce_from_peer_id,
)
from dcpp_python.messages import Announce, CollectionAnnouncement


class TestPeerIdConversion:
    """Test peer ID to public key conversions."""

    def test_pubkey_to_peer_id_roundtrip(self):
        """Public key to peer_id and back should roundtrip."""
        signing_key, verify_key = generate_keypair()
        pubkey = bytes(verify_key)

        peer_id = ed25519_pubkey_to_peer_id(pubkey)
        assert len(peer_id) == 38

        extracted = pubkey_from_peer_id(peer_id)
        assert extracted is not None
        assert extracted == pubkey

    def test_peer_id_format(self):
        """Peer ID should have correct libp2p format."""
        signing_key, verify_key = generate_keypair()
        pubkey = bytes(verify_key)

        peer_id = ed25519_pubkey_to_peer_id(pubkey)

        # Identity multihash prefix
        assert peer_id[0] == 0x00  # identity hash
        assert peer_id[1] == 0x24  # length 36

        # Protobuf Ed25519 key type
        assert peer_id[2] == 0x08
        assert peer_id[3] == 0x01

        # Data field
        assert peer_id[4] == 0x12
        assert peer_id[5] == 0x20  # 32 bytes

        # Public key
        assert peer_id[6:] == pubkey

    def test_pubkey_from_invalid_peer_id(self):
        """Should return None for invalid peer_id formats."""
        # Wrong length
        assert pubkey_from_peer_id(b"\x00" * 32) is None
        assert pubkey_from_peer_id(b"\x00" * 40) is None

        # Wrong prefix
        invalid = b"\x01\x24" + b"\x08\x01\x12\x20" + b"\x00" * 32
        assert pubkey_from_peer_id(invalid) is None

    def test_derive_peer_id_from_verify_key(self):
        """derive_peer_id should work with VerifyKey."""
        signing_key, verify_key = generate_keypair()
        peer_id = derive_peer_id(verify_key)

        assert len(peer_id) == 38
        extracted = pubkey_from_peer_id(peer_id)
        assert extracted == bytes(verify_key)


class TestAnnounceSignature:
    """Test ANNOUNCE message signing and verification."""

    def create_test_announce(self, node_id: bytes) -> Announce:
        """Create a test ANNOUNCE message."""
        collections = [
            CollectionAnnouncement(
                id="eth:0xBC4CA0",
                manifest_cid="QmTest123",
                coverage=0.85,
                shard_ids=[0, 1, 2],
            )
        ]
        return Announce(
            node_id=node_id,
            announce_seq=1,
            collections=collections,
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 3600,
            signature=None,
        )

    def test_sign_and_verify_announce(self):
        """Sign and verify an ANNOUNCE message."""
        signing_key, verify_key = generate_keypair()
        peer_id = derive_peer_id(verify_key)
        pubkey = bytes(verify_key)

        announce = self.create_test_announce(peer_id)

        # Sign
        signature = sign_announce(announce, signing_key)
        assert len(signature) == 64

        # Add signature to announce
        announce.signature = signature

        # Verify
        assert verify_announce(announce, pubkey) is True

    def test_verify_with_wrong_key_fails(self):
        """Verification should fail with wrong public key."""
        signing_key, verify_key = generate_keypair()
        _, wrong_verify_key = generate_keypair()

        peer_id = derive_peer_id(verify_key)
        announce = self.create_test_announce(peer_id)

        signature = sign_announce(announce, signing_key)
        announce.signature = signature

        # Verify with wrong key should fail
        assert verify_announce(announce, bytes(wrong_verify_key)) is False

    def test_verify_tampered_message_fails(self):
        """Verification should fail if message was tampered."""
        signing_key, verify_key = generate_keypair()
        peer_id = derive_peer_id(verify_key)
        pubkey = bytes(verify_key)

        announce = self.create_test_announce(peer_id)

        signature = sign_announce(announce, signing_key)
        announce.signature = signature

        # Tamper with the message
        announce.announce_seq = 999

        # Should fail verification
        assert verify_announce(announce, pubkey) is False

    def test_verify_announce_from_peer_id(self):
        """Verify using embedded public key in peer_id."""
        signing_key, verify_key = generate_keypair()
        peer_id = derive_peer_id(verify_key)

        announce = self.create_test_announce(peer_id)
        signature = sign_announce(announce, signing_key)
        announce.signature = signature

        # Verify using the convenience function
        assert verify_announce_from_peer_id(announce) is True

    def test_verify_no_signature_raises(self):
        """Should raise if no signature present."""
        signing_key, verify_key = generate_keypair()
        peer_id = derive_peer_id(verify_key)
        pubkey = bytes(verify_key)

        announce = self.create_test_announce(peer_id)
        # No signature set

        with pytest.raises(ValueError, match="No signature"):
            verify_announce(announce, pubkey)

    def test_verify_invalid_peer_id_raises(self):
        """Should raise if peer_id format is invalid."""
        announce = self.create_test_announce(b"\x00" * 32)  # Invalid peer_id
        announce.signature = b"\x00" * 64

        with pytest.raises(ValueError, match="invalid peer_id format"):
            verify_announce_from_peer_id(announce)

    def test_sign_multiple_collections(self):
        """Sign and verify with multiple collections."""
        signing_key, verify_key = generate_keypair()
        peer_id = derive_peer_id(verify_key)
        pubkey = bytes(verify_key)

        collections = [
            CollectionAnnouncement(
                id="eth:0xBC4CA0",
                manifest_cid="QmTest1",
                coverage=1.0,
                shard_ids=[0, 1],
            ),
            CollectionAnnouncement(
                id="polygon:0x123456",
                manifest_cid="QmTest2",
                coverage=0.5,
                shard_ids=None,
            ),
            CollectionAnnouncement(
                id="private:abc123",
                manifest_cid="QmTest3",
                coverage=0.75,
                shard_ids=[0, 1, 2, 3, 4],
            ),
        ]

        announce = Announce(
            node_id=peer_id,
            announce_seq=42,
            collections=collections,
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 7200,
            signature=None,
        )

        signature = sign_announce(announce, signing_key)
        announce.signature = signature

        assert verify_announce(announce, pubkey) is True


class TestSignatureInterop:
    """Test that Python signatures are compatible with expected formats."""

    def test_signature_is_64_bytes(self):
        """Ed25519 signature should always be 64 bytes."""
        signing_key, verify_key = generate_keypair()
        peer_id = derive_peer_id(verify_key)

        announce = Announce(
            node_id=peer_id,
            announce_seq=1,
            collections=[
                CollectionAnnouncement(
                    id="test:collection",
                    manifest_cid="QmTest",
                    coverage=1.0,
                    shard_ids=None,
                )
            ],
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 3600,
            signature=None,
        )

        signature = sign_announce(announce, signing_key)
        assert len(signature) == 64
        assert isinstance(signature, bytes)

    def test_peer_id_is_38_bytes(self):
        """libp2p peer ID for Ed25519 should always be 38 bytes."""
        signing_key, verify_key = generate_keypair()
        peer_id = derive_peer_id(verify_key)

        assert len(peer_id) == 38
        assert isinstance(peer_id, bytes)
