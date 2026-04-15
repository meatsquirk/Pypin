"""
DCPP Cryptographic Utilities

Implements Ed25519 signatures (Section 5.4.2) and AES-256-GCM encryption (Section 3.4.1).
"""

from __future__ import annotations

import hashlib
import os
from typing import TYPE_CHECKING

import cbor2
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

if TYPE_CHECKING:
    from dcpp_python.core.messages import Announce


def canonical_cbor_dumps(data: dict[str, object]) -> bytes:
    """
    Serialize data to Canonical CBOR (RFC 8949 Section 4.2.1).

    Requirements:
    - Map keys sorted by encoded key bytes (length-first, then lexicographic)
    - Integer encoding: smallest valid encoding
    - No duplicate keys
    - No indefinite lengths

    Args:
        data: Dictionary to serialize

    Returns:
        Canonical CBOR bytes
    """
    # cbor2 with canonical=True handles the sorting and encoding requirements
    return cbor2.dumps(data, canonical=True)


def sign_message(data: dict[str, object], private_key: SigningKey) -> bytes:
    """
    Sign a message using Ed25519.

    Args:
        data: Message data (will be serialized to Canonical CBOR)
        private_key: Ed25519 signing key

    Returns:
        64-byte Ed25519 signature
    """
    canonical_bytes = canonical_cbor_dumps(data)
    signed = private_key.sign(canonical_bytes)
    return signed.signature


def verify_signature(data: dict[str, object], signature: bytes, public_key: VerifyKey) -> bool:
    """
    Verify an Ed25519 signature.

    Args:
        data: Original message data
        signature: 64-byte Ed25519 signature
        public_key: Ed25519 verify key

    Returns:
        True if signature is valid

    Raises:
        BadSignatureError: If signature is invalid
    """
    canonical_bytes = canonical_cbor_dumps(data)
    try:
        public_key.verify(canonical_bytes, signature)
        return True
    except BadSignatureError:
        return False


def generate_keypair() -> tuple[SigningKey, VerifyKey]:
    """
    Generate a new Ed25519 keypair.

    Returns:
        Tuple of (signing_key, verify_key)
    """
    signing_key = SigningKey.generate()
    return signing_key, signing_key.verify_key


def derive_peer_id(public_key: VerifyKey) -> bytes:
    """
    Derive libp2p Peer ID from Ed25519 public key.

    libp2p PeerId format for Ed25519 keys (38 bytes total):
    - Identity multihash prefix: 0x00 (identity hash) + 0x24 (length 36)
    - Protobuf-encoded public key (36 bytes):
      - 0x08 0x01 (field 1: key type = Ed25519)
      - 0x12 0x20 (field 2: data, 32 bytes)
      - <32 bytes of Ed25519 public key>

    Args:
        public_key: Ed25519 verify key

    Returns:
        38-byte libp2p Peer ID
    """
    pubkey_bytes = bytes(public_key)
    return ed25519_pubkey_to_peer_id(pubkey_bytes)


# libp2p Peer ID constants
PEER_ID_SIZE = 38  # Ed25519 peer ID size


def ed25519_pubkey_to_peer_id(public_key: bytes) -> bytes:
    """
    Convert Ed25519 public key to libp2p PeerId format.

    libp2p PeerId for Ed25519 keys uses identity multihash over protobuf-encoded key:
    - Multihash: 0x00 (identity) + 0x24 (length 36)
    - Protobuf: 0x08 0x01 (type=Ed25519) + 0x12 0x20 (data field, 32 bytes) + pubkey

    Args:
        public_key: 32-byte Ed25519 public key

    Returns:
        38-byte libp2p Peer ID
    """
    if len(public_key) != 32:
        raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(public_key)}")

    peer_id = bytearray(PEER_ID_SIZE)
    # Identity multihash prefix
    peer_id[0] = 0x00  # identity hash function code
    peer_id[1] = 0x24  # length: 36 bytes (protobuf-encoded key)
    # Protobuf-encoded public key
    peer_id[2] = 0x08  # field 1, wire type 0 (varint)
    peer_id[3] = 0x01  # value: 1 (Ed25519 key type)
    peer_id[4] = 0x12  # field 2, wire type 2 (length-delimited)
    peer_id[5] = 0x20  # length: 32 bytes
    peer_id[6:] = public_key
    return bytes(peer_id)


def pubkey_from_peer_id(peer_id: bytes) -> bytes | None:
    """
    Extract Ed25519 public key from libp2p PeerId.

    Args:
        peer_id: 38-byte libp2p Peer ID

    Returns:
        32-byte Ed25519 public key, or None if format is invalid
    """
    if len(peer_id) != PEER_ID_SIZE:
        return None

    # Validate identity multihash prefix
    if peer_id[0] != 0x00 or peer_id[1] != 0x24:
        return None

    # Validate protobuf structure
    if peer_id[2] != 0x08 or peer_id[3] != 0x01:  # Ed25519 key type
        return None
    if peer_id[4] != 0x12 or peer_id[5] != 0x20:  # 32-byte data field
        return None

    return peer_id[6:]


def derive_private_collection_id(collection_key: bytes) -> str:
    """
    Derive collection ID for private collections (Section 3.4.4).

    Format: "private:" + base32(sha256(collection_key)[0:16])

    Args:
        collection_key: 256-bit collection key

    Returns:
        Private collection ID string
    """
    import base64

    key_hash = hashlib.sha256(collection_key).digest()[:16]
    # Use base32 lowercase (RFC 4648)
    encoded = base64.b32encode(key_hash).decode("ascii").lower().rstrip("=")
    return f"private:{encoded}"


def derive_dht_key(collection_id: str) -> bytes:
    """
    Derive DHT key for collection discovery (Section 9.1.1).

    Formula: sha256("dcpp/1.0:" + collection_id)

    Args:
        collection_id: Collection ID string

    Returns:
        32-byte DHT key
    """
    prefix = "dcpp/1.0:"
    return hashlib.sha256((prefix + collection_id).encode("utf-8")).digest()


def derive_private_dht_key(collection_key: bytes) -> bytes:
    """
    Derive DHT key for private collection discovery (Section 9.2.2).

    Formula: sha256("dcpp/1.0/private:" + collection_key)

    Args:
        collection_key: 256-bit collection key

    Returns:
        32-byte DHT key
    """
    prefix = b"dcpp/1.0/private:"
    return hashlib.sha256(prefix + collection_key).digest()


def generate_collection_key() -> bytes:
    """
    Generate a new 256-bit Collection Key for private collections.

    Returns:
        32-byte random key
    """
    return os.urandom(32)


def generate_nonce() -> bytes:
    """
    Generate a 96-bit nonce for AES-256-GCM.

    Returns:
        12-byte random nonce
    """
    return os.urandom(12)


class AES256GCM:
    """
    AES-256-GCM encryption for private collections (Section 3.4.1).

    Parameters:
    - Algorithm: AES-256-GCM (AEAD)
    - Key size: 256 bits
    - Nonce: 96 bits, randomly generated per encryption operation
    - Authentication tag: 128 bits
    """

    def __init__(self, key: bytes):
        """
        Initialize AES-256-GCM cipher.

        Args:
            key: 256-bit (32 bytes) encryption key
        """
        if len(key) != 32:
            raise ValueError(f"Key must be 32 bytes, got {len(key)}")

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._cipher = AESGCM(key)

    def encrypt(
        self, plaintext: bytes, associated_data: bytes | None = None
    ) -> tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.

        Args:
            plaintext: Data to encrypt
            associated_data: Optional authenticated data (not encrypted)

        Returns:
            Tuple of (nonce, ciphertext_with_tag)
        """
        nonce = generate_nonce()
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext

    def decrypt(
        self, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None
    ) -> bytes:
        """
        Decrypt data using AES-256-GCM.

        Args:
            nonce: 96-bit nonce used for encryption
            ciphertext: Ciphertext with authentication tag
            associated_data: Optional authenticated data

        Returns:
            Decrypted plaintext

        Raises:
            InvalidTag: If authentication fails
        """
        return self._cipher.decrypt(nonce, ciphertext, associated_data)


def encrypt_content(plaintext: bytes, collection_key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt content for a private collection.

    Args:
        plaintext: Content to encrypt
        collection_key: 256-bit collection key

    Returns:
        Tuple of (nonce, ciphertext)
    """
    cipher = AES256GCM(collection_key)
    return cipher.encrypt(plaintext)


def decrypt_content(nonce: bytes, ciphertext: bytes, collection_key: bytes) -> bytes:
    """
    Decrypt content from a private collection.

    Args:
        nonce: 96-bit nonce
        ciphertext: Encrypted content
        collection_key: 256-bit collection key

    Returns:
        Decrypted plaintext
    """
    cipher = AES256GCM(collection_key)
    return cipher.decrypt(nonce, ciphertext)


def compute_shard_index_numeric(item_id: str, items_per_shard: int) -> int:
    """
    Compute shard index for numeric item IDs (Section 11.1.1).

    For NFT collections where item_id represents a token ID.

    Args:
        item_id: Token ID as string (base-10 unsigned integer)
        items_per_shard: Number of items per shard

    Returns:
        Shard index
    """
    # Strip leading zeros and parse as integer
    token_id = int(item_id.lstrip("0") or "0")
    return token_id // items_per_shard


def compute_shard_index_hash(item_id: str, shard_count: int) -> int:
    """
    Compute shard index for non-numeric item IDs (Section 11.1.2).

    For non-NFT content where item_id is a path or UUID.

    Args:
        item_id: Item identifier string
        shard_count: Total number of shards

    Returns:
        Shard index
    """
    hash_bytes = hashlib.sha256(item_id.encode("utf-8")).digest()
    # Take first 8 bytes as uint64
    hash_value = int.from_bytes(hash_bytes[:8], "big")
    return hash_value % shard_count


def sign_announce(announce: Announce, private_key: SigningKey) -> bytes:
    """
    Sign an ANNOUNCE message (RFC Section 6.3).

    Creates a canonical CBOR representation excluding the signature field,
    then signs it with Ed25519.

    Args:
        announce: Announce message to sign
        private_key: Ed25519 signing key

    Returns:
        64-byte Ed25519 signature
    """
    # Create the data to sign (excluding signature field)
    data_for_signing = {
        "node_id": announce.node_id,
        "announce_seq": announce.announce_seq,
        "collections": [
            {
                "id": c.id,
                "manifest_cid": c.manifest_cid,
                "coverage": c.coverage,
                **({"bt_status": c.bt_status} if c.bt_status is not None else {}),
                **({"shard_ids": c.shard_ids} if c.shard_ids else {}),
            }
            for c in announce.collections
        ],
        "timestamp": announce.timestamp,
        "expires_at": announce.expires_at,
    }
    return sign_message(data_for_signing, private_key)


def verify_announce(announce: Announce, public_key: bytes) -> bool:
    """
    Verify an ANNOUNCE message signature (RFC Section 6.3).

    Args:
        announce: Announce message with signature
        public_key: 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise

    Raises:
        ValueError: If no signature present or public key is wrong size
    """
    if announce.signature is None:
        raise ValueError("No signature present in ANNOUNCE message")

    if len(public_key) != 32:
        raise ValueError(f"Public key must be 32 bytes, got {len(public_key)}")

    # Create the data that was signed (excluding signature field)
    data_for_signing = {
        "node_id": announce.node_id,
        "announce_seq": announce.announce_seq,
        "collections": [
            {
                "id": c.id,
                "manifest_cid": c.manifest_cid,
                "coverage": c.coverage,
                **({"bt_status": c.bt_status} if c.bt_status is not None else {}),
                **({"shard_ids": c.shard_ids} if c.shard_ids else {}),
            }
            for c in announce.collections
        ],
        "timestamp": announce.timestamp,
        "expires_at": announce.expires_at,
    }

    try:
        verify_key = VerifyKey(public_key)
        return verify_signature(data_for_signing, announce.signature, verify_key)
    except Exception:
        return False


def verify_announce_from_peer_id(announce: Announce) -> bool:
    """
    Verify an ANNOUNCE message using the public key embedded in node_id.

    This is a convenience function that extracts the public key from the
    peer_id format node_id and verifies the signature.

    Args:
        announce: Announce message with signature

    Returns:
        True if signature is valid, False otherwise

    Raises:
        ValueError: If node_id format is invalid or no signature present
    """
    public_key = pubkey_from_peer_id(announce.node_id)
    if public_key is None:
        raise ValueError("Cannot extract public key from node_id - invalid peer_id format")

    return verify_announce(announce, public_key)
