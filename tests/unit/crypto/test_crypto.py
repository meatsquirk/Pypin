"""Tests for DCPP cryptographic utilities."""

import os
import pytest
from cryptography.exceptions import InvalidTag

from dcpp_python.crypto import (
    AES256GCM,
    canonical_cbor_dumps,
    compute_shard_index_hash,
    compute_shard_index_numeric,
    decrypt_content,
    derive_dht_key,
    derive_peer_id,
    derive_private_collection_id,
    derive_private_dht_key,
    encrypt_content,
    generate_collection_key,
    generate_keypair,
    generate_nonce,
    sign_message,
    verify_signature,
)


class TestCanonicalCBOR:
    """Test Canonical CBOR serialization."""

    def test_deterministic_output(self):
        """Same data should always produce same output."""
        data = {"z": 1, "a": 2, "m": 3}
        result1 = canonical_cbor_dumps(data)
        result2 = canonical_cbor_dumps(data)
        assert result1 == result2

    def test_sorted_keys(self):
        """Map keys should be sorted."""
        import cbor2

        data = {"zebra": 1, "apple": 2, "mango": 3}
        result = canonical_cbor_dumps(data)
        # Decode and verify order is maintained
        decoded = cbor2.loads(result)
        # Keys should be accessible in sorted order when iterating
        keys = list(decoded.keys())
        assert keys == sorted(keys)

    def test_nested_structures(self):
        """Nested structures should be canonical."""
        data = {
            "outer": {"z": 1, "a": 2},
            "list": [{"b": 1, "a": 2}],
        }
        result = canonical_cbor_dumps(data)
        # Should not raise
        assert len(result) > 0


class TestEd25519Signatures:
    """Test Ed25519 signing and verification."""

    def test_generate_keypair(self):
        """Generate Ed25519 keypair."""
        signing_key, verify_key = generate_keypair()
        assert signing_key is not None
        assert verify_key is not None
        # Keys should be 32 bytes
        assert len(bytes(verify_key)) == 32

    def test_sign_and_verify(self):
        """Sign message and verify signature."""
        signing_key, verify_key = generate_keypair()
        data = {"message": "hello", "timestamp": 12345}

        signature = sign_message(data, signing_key)
        assert len(signature) == 64  # Ed25519 signatures are 64 bytes

        # Verification should succeed
        assert verify_signature(data, signature, verify_key)

    def test_verify_wrong_key_fails(self):
        """Verification with wrong key should fail."""
        signing_key1, verify_key1 = generate_keypair()
        _, verify_key2 = generate_keypair()

        data = {"test": "data"}
        signature = sign_message(data, signing_key1)

        # Wrong key should fail
        assert not verify_signature(data, signature, verify_key2)

    def test_verify_modified_data_fails(self):
        """Verification with modified data should fail."""
        signing_key, verify_key = generate_keypair()
        data = {"value": 100}
        signature = sign_message(data, signing_key)

        # Modified data should fail
        modified_data = {"value": 101}
        assert not verify_signature(modified_data, signature, verify_key)

    def test_signature_deterministic(self):
        """Same data with same key produces same signature."""
        signing_key, _ = generate_keypair()
        data = {"constant": "data"}

        sig1 = sign_message(data, signing_key)
        sig2 = sign_message(data, signing_key)
        assert sig1 == sig2


class TestPeerId:
    """Test Peer ID derivation."""

    def test_derive_peer_id(self):
        """Derive peer ID from public key."""
        _, verify_key = generate_keypair()
        peer_id = derive_peer_id(verify_key)

        # libp2p PeerId for Ed25519 is 38 bytes
        assert len(peer_id) == 38
        assert isinstance(peer_id, bytes)
        # Verify libp2p format: identity multihash + protobuf
        assert peer_id[0] == 0x00  # identity hash
        assert peer_id[1] == 0x24  # length 36
        assert peer_id[2:4] == b"\x08\x01"  # Ed25519 key type
        assert peer_id[4:6] == b"\x12\x20"  # 32-byte data field

    def test_peer_id_deterministic(self):
        """Same public key produces same peer ID."""
        _, verify_key = generate_keypair()
        id1 = derive_peer_id(verify_key)
        id2 = derive_peer_id(verify_key)
        assert id1 == id2

    def test_different_keys_different_ids(self):
        """Different keys produce different peer IDs."""
        _, verify_key1 = generate_keypair()
        _, verify_key2 = generate_keypair()
        id1 = derive_peer_id(verify_key1)
        id2 = derive_peer_id(verify_key2)
        assert id1 != id2

    def test_pubkey_from_peer_id_roundtrip(self):
        """Public key can be extracted from peer ID."""
        from dcpp_python.crypto import pubkey_from_peer_id

        _, verify_key = generate_keypair()
        pubkey_bytes = bytes(verify_key)
        peer_id = derive_peer_id(verify_key)

        extracted = pubkey_from_peer_id(peer_id)
        assert extracted == pubkey_bytes

    def test_pubkey_from_peer_id_invalid_length(self):
        """Invalid peer ID length returns None."""
        from dcpp_python.crypto import pubkey_from_peer_id

        assert pubkey_from_peer_id(b"short") is None
        assert pubkey_from_peer_id(b"x" * 40) is None

    def test_pubkey_from_peer_id_invalid_format(self):
        """Invalid peer ID format returns None."""
        from dcpp_python.crypto import pubkey_from_peer_id

        # Wrong identity hash
        bad_id = bytes([0x01, 0x24]) + b"\x08\x01\x12\x20" + b"\x00" * 32
        assert pubkey_from_peer_id(bad_id) is None

        # Wrong protobuf key type
        bad_id = bytes([0x00, 0x24]) + b"\x08\x02\x12\x20" + b"\x00" * 32
        assert pubkey_from_peer_id(bad_id) is None


class TestPrivateCollectionId:
    """Test private collection ID derivation."""

    def test_derive_private_collection_id(self):
        """Derive private collection ID from key."""
        key = generate_collection_key()
        collection_id = derive_private_collection_id(key)

        assert collection_id.startswith("private:")
        # Should have base32 encoded content after prefix
        assert len(collection_id) > len("private:")

    def test_deterministic(self):
        """Same key produces same collection ID."""
        key = b"x" * 32
        id1 = derive_private_collection_id(key)
        id2 = derive_private_collection_id(key)
        assert id1 == id2

    def test_different_keys_different_ids(self):
        """Different keys produce different collection IDs."""
        key1 = generate_collection_key()
        key2 = generate_collection_key()
        id1 = derive_private_collection_id(key1)
        id2 = derive_private_collection_id(key2)
        assert id1 != id2


class TestDHTKeys:
    """Test DHT key derivation."""

    def test_derive_dht_key(self):
        """Derive DHT key for public collection."""
        collection_id = "eth:0x1234567890abcdef"
        dht_key = derive_dht_key(collection_id)

        assert len(dht_key) == 32  # SHA-256 output
        assert isinstance(dht_key, bytes)

    def test_dht_key_deterministic(self):
        """Same collection ID produces same DHT key."""
        collection_id = "polygon:0xabc"
        key1 = derive_dht_key(collection_id)
        key2 = derive_dht_key(collection_id)
        assert key1 == key2

    def test_derive_private_dht_key(self):
        """Derive DHT key for private collection."""
        collection_key = generate_collection_key()
        dht_key = derive_private_dht_key(collection_key)

        assert len(dht_key) == 32
        assert isinstance(dht_key, bytes)

    def test_private_dht_key_deterministic(self):
        """Same collection key produces same DHT key."""
        key = b"secret_key_here_32_bytes_long!!!"
        dht1 = derive_private_dht_key(key)
        dht2 = derive_private_dht_key(key)
        assert dht1 == dht2


class TestCollectionKey:
    """Test collection key generation."""

    def test_generate_collection_key(self):
        """Generate collection key."""
        key = generate_collection_key()
        assert len(key) == 32  # 256 bits
        assert isinstance(key, bytes)

    def test_keys_are_random(self):
        """Generated keys should be unique."""
        keys = [generate_collection_key() for _ in range(100)]
        unique_keys = set(keys)
        assert len(unique_keys) == 100


class TestNonce:
    """Test nonce generation."""

    def test_generate_nonce(self):
        """Generate 96-bit nonce."""
        nonce = generate_nonce()
        assert len(nonce) == 12  # 96 bits
        assert isinstance(nonce, bytes)

    def test_nonces_are_random(self):
        """Generated nonces should be unique."""
        nonces = [generate_nonce() for _ in range(100)]
        unique_nonces = set(nonces)
        assert len(unique_nonces) == 100


class TestAES256GCM:
    """Test AES-256-GCM encryption."""

    def test_encrypt_decrypt_basic(self):
        """Basic encryption and decryption."""
        key = generate_collection_key()
        cipher = AES256GCM(key)

        plaintext = b"Hello, World!"
        nonce, ciphertext = cipher.encrypt(plaintext)

        assert len(nonce) == 12
        assert ciphertext != plaintext

        decrypted = cipher.decrypt(nonce, ciphertext)
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty(self):
        """Encrypt and decrypt empty data."""
        key = generate_collection_key()
        cipher = AES256GCM(key)

        nonce, ciphertext = cipher.encrypt(b"")
        decrypted = cipher.decrypt(nonce, ciphertext)
        assert decrypted == b""

    def test_encrypt_decrypt_large(self):
        """Encrypt and decrypt large data."""
        key = generate_collection_key()
        cipher = AES256GCM(key)

        plaintext = os.urandom(1024 * 1024)  # 1 MB
        nonce, ciphertext = cipher.encrypt(plaintext)
        decrypted = cipher.decrypt(nonce, ciphertext)
        assert decrypted == plaintext

    def test_different_nonces_different_ciphertext(self):
        """Same plaintext with different nonces produces different ciphertext."""
        key = generate_collection_key()
        cipher = AES256GCM(key)

        plaintext = b"Same message"
        nonce1, ct1 = cipher.encrypt(plaintext)
        nonce2, ct2 = cipher.encrypt(plaintext)

        # Nonces should be different
        assert nonce1 != nonce2
        # Ciphertexts should be different
        assert ct1 != ct2

    def test_wrong_key_fails(self):
        """Decryption with wrong key should fail."""
        key1 = generate_collection_key()
        key2 = generate_collection_key()

        cipher1 = AES256GCM(key1)
        cipher2 = AES256GCM(key2)

        nonce, ciphertext = cipher1.encrypt(b"Secret")

        with pytest.raises(InvalidTag):
            cipher2.decrypt(nonce, ciphertext)

    def test_modified_ciphertext_fails(self):
        """Decryption with modified ciphertext should fail."""
        key = generate_collection_key()
        cipher = AES256GCM(key)

        nonce, ciphertext = cipher.encrypt(b"Original")

        # Modify ciphertext
        modified = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

        with pytest.raises(InvalidTag):
            cipher.decrypt(nonce, modified)

    def test_modified_nonce_fails(self):
        """Decryption with wrong nonce should fail."""
        key = generate_collection_key()
        cipher = AES256GCM(key)

        nonce, ciphertext = cipher.encrypt(b"Data")

        # Use different nonce
        wrong_nonce = generate_nonce()

        with pytest.raises(InvalidTag):
            cipher.decrypt(wrong_nonce, ciphertext)

    def test_associated_data(self):
        """Encryption with associated data."""
        key = generate_collection_key()
        cipher = AES256GCM(key)

        plaintext = b"Secret message"
        aad = b"collection:private:abc123"

        nonce, ciphertext = cipher.encrypt(plaintext, aad)
        decrypted = cipher.decrypt(nonce, ciphertext, aad)
        assert decrypted == plaintext

        # Wrong AAD should fail
        with pytest.raises(InvalidTag):
            cipher.decrypt(nonce, ciphertext, b"wrong_aad")

    def test_invalid_key_length(self):
        """Invalid key length should raise."""
        with pytest.raises(ValueError):
            AES256GCM(b"too_short")

        with pytest.raises(ValueError):
            AES256GCM(b"this_key_is_too_long_for_aes_256!")


class TestEncryptContentHelpers:
    """Test encrypt_content and decrypt_content helpers."""

    def test_encrypt_decrypt_content(self):
        """Test helper functions."""
        key = generate_collection_key()
        plaintext = b"Content to encrypt"

        nonce, ciphertext = encrypt_content(plaintext, key)
        decrypted = decrypt_content(nonce, ciphertext, key)

        assert decrypted == plaintext


class TestShardIndexComputation:
    """Test shard index computation."""

    def test_numeric_shard_index(self):
        """Test numeric (NFT token ID) shard assignment."""
        items_per_shard = 1000

        assert compute_shard_index_numeric("0", items_per_shard) == 0
        assert compute_shard_index_numeric("999", items_per_shard) == 0
        assert compute_shard_index_numeric("1000", items_per_shard) == 1
        assert compute_shard_index_numeric("5432", items_per_shard) == 5

    def test_numeric_strip_leading_zeros(self):
        """Leading zeros should be stripped."""
        assert compute_shard_index_numeric("007", 10) == 0
        assert compute_shard_index_numeric("0100", 10) == 10
        assert compute_shard_index_numeric("000", 10) == 0

    def test_hash_shard_index(self):
        """Test hash-based shard assignment."""
        shard_count = 10

        # Should be deterministic
        idx1 = compute_shard_index_hash("path/to/file.jpg", shard_count)
        idx2 = compute_shard_index_hash("path/to/file.jpg", shard_count)
        assert idx1 == idx2
        assert 0 <= idx1 < shard_count

    def test_hash_distribution(self):
        """Hash-based assignment should distribute items across shards."""
        shard_count = 10
        shard_counts = [0] * shard_count

        # Generate many random paths
        for i in range(10000):
            path = f"/photos/img_{i:05d}.jpg"
            idx = compute_shard_index_hash(path, shard_count)
            shard_counts[idx] += 1

        # Each shard should have roughly 1000 items (with some variance)
        for count in shard_counts:
            assert 800 < count < 1200  # Allow 20% variance
