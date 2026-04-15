"""
DCPP CID Verification Module

Implements CIDv1 parsing, verification, and generation per RFC Section 3.3.

CIDv1 Structure:
- Version: 0x01 (varint)
- Codec: multicodec varint (raw=0x55, dag-pb=0x70)
- Multihash: hash function code + length + digest

RFC Section 3.3 Strict Requirements (DCPP Compliance):
- Multibase: base32 lowercase (RFC 4648) - prefix 'b' ONLY
- Multihash: sha2-256 (0x12) ONLY
- Multicodec: raw (0x55) for files, dag-pb (0x70) for directories
- CID version: 1 ONLY

Lenient Mode (for migration/debugging):
- Accepts base16 (prefix 'f')
- Accepts base32 without prefix
- Accepts sha2-512, sha3-256, identity hashes

The default is strict mode for spec compliance. Use strict=False only
for migration from legacy systems or debugging.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from enum import IntEnum
from typing import Tuple


class Multicodec(IntEnum):
    """Common multicodec values for DCPP."""

    RAW = 0x55  # Raw binary data
    DAG_PB = 0x70  # DAG-protobuf (IPFS directories)


class Multihash(IntEnum):
    """Common multihash function codes."""

    IDENTITY = 0x00
    SHA2_256 = 0x12
    SHA2_512 = 0x13
    SHA3_256 = 0x16
    BLAKE2B_256 = 0xB220


# Hash function output sizes
HASH_SIZES = {
    Multihash.IDENTITY: None,  # Variable
    Multihash.SHA2_256: 32,
    Multihash.SHA2_512: 64,
    Multihash.SHA3_256: 32,
}


@dataclass
class CidInfo:
    """Parsed CID information."""

    version: int
    codec: int
    hash_func: int
    digest: bytes

    @property
    def codec_name(self) -> str:
        """Human-readable codec name."""
        names: dict[int, str] = {
            int(Multicodec.RAW): "raw",
            int(Multicodec.DAG_PB): "dag-pb",
        }
        return names.get(self.codec, f"unknown({self.codec:#x})")

    @property
    def hash_func_name(self) -> str:
        """Human-readable hash function name."""
        names: dict[int, str] = {
            int(Multihash.IDENTITY): "identity",
            int(Multihash.SHA2_256): "sha2-256",
            int(Multihash.SHA2_512): "sha2-512",
            int(Multihash.SHA3_256): "sha3-256",
        }
        return names.get(self.hash_func, f"unknown({self.hash_func:#x})")


def _decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Decode an unsigned varint from bytes.

    Args:
        data: Byte sequence
        offset: Starting offset

    Returns:
        Tuple of (value, bytes_consumed)

    Raises:
        ValueError: If varint is invalid or truncated
    """
    result = 0
    shift = 0
    consumed = 0

    while offset + consumed < len(data):
        byte = data[offset + consumed]
        consumed += 1
        result |= (byte & 0x7F) << shift

        if (byte & 0x80) == 0:
            return result, consumed

        shift += 7
        if shift >= 64:
            raise ValueError("Varint too large")

    raise ValueError("Truncated varint")


def _encode_varint(value: int) -> bytes:
    """
    Encode an unsigned integer as a varint.

    Args:
        value: Non-negative integer

    Returns:
        Varint-encoded bytes
    """
    if value < 0:
        raise ValueError("Varint cannot be negative")

    if value == 0:
        return b"\x00"

    result = bytearray()
    while value > 0:
        byte = value & 0x7F
        value >>= 7
        if value > 0:
            byte |= 0x80
        result.append(byte)

    return bytes(result)


# RFC 4648 base32 lowercase alphabet (a-z, 2-7)
_BASE32_LOWERCASE_ALPHABET = set("abcdefghijklmnopqrstuvwxyz234567")


def _validate_base32_lowercase(encoded: str) -> None:
    """
    Validate that a base32 string uses only lowercase characters per RFC 4648.

    Per RFC Section 3.3, DCPP requires base32 lowercase (RFC 4648).
    This function rejects any characters outside a-z and 2-7.

    Args:
        encoded: Base32 encoded string to validate

    Raises:
        ValueError: If string contains non-lowercase base32 characters
    """
    invalid_chars = set(encoded) - _BASE32_LOWERCASE_ALPHABET
    if invalid_chars:
        # Check if it's an uppercase issue specifically
        uppercase_chars = [c for c in invalid_chars if c.isupper()]
        if uppercase_chars:
            raise ValueError(
                f"Base32 contains uppercase characters {uppercase_chars} - "
                f"RFC Section 3.3 requires lowercase base32 (a-z, 2-7). "
                f"Convert to lowercase or use strict=False for legacy support."
            )
        raise ValueError(
            f"Base32 contains invalid characters {list(invalid_chars)} - "
            f"RFC 4648 base32 lowercase allows only a-z and 2-7."
        )


def _base32_decode(encoded: str, strict: bool = False) -> bytes:
    """
    Decode base32 (RFC 4648 lowercase, no padding).

    Args:
        encoded: Base32 encoded string (lowercase)
        strict: If True, reject non-lowercase characters per RFC Section 3.3

    Returns:
        Decoded bytes

    Raises:
        ValueError: If strict=True and string contains non-lowercase chars
    """
    if strict:
        _validate_base32_lowercase(encoded)

    # Normalize to uppercase for Python's base64 module
    upper = encoded.upper()
    # Add padding if needed
    padding = (8 - len(upper) % 8) % 8
    padded = upper + "=" * padding
    return base64.b32decode(padded)


def _base32_encode(data: bytes) -> str:
    """
    Encode bytes as base32 (RFC 4648 lowercase, no padding).

    Args:
        data: Bytes to encode

    Returns:
        Base32 encoded string (lowercase, no padding)
    """
    return base64.b32encode(data).decode("ascii").lower().rstrip("=")


def parse_cid(cid_str: str, strict: bool = True) -> CidInfo:
    """
    Parse a CID string into its components.

    Per RFC Section 3.3, DCPP requires strict CID format:
    - Multibase: base32 lowercase (RFC 4648) with 'b' prefix
    - Multihash: sha2-256 (0x12) only
    - Multicodec: raw (0x55) or dag-pb (0x70)
    - CID version: 1

    Args:
        cid_str: CID string
        strict: If True (default), enforce RFC Section 3.3 requirements.
               If False, accept legacy formats for migration/debugging.

    Returns:
        CidInfo with parsed components

    Raises:
        ValueError: If CID format is invalid or non-compliant in strict mode
    """
    if not cid_str:
        raise ValueError("Empty CID string")

    # Handle multibase prefix
    if cid_str.startswith("b"):
        # base32 lowercase (RFC 4648) - SPEC COMPLIANT
        # In strict mode, validate lowercase characters per RFC Section 3.3
        raw_bytes = _base32_decode(cid_str[1:], strict=strict)
    elif cid_str.startswith("Qm"):
        # CIDv0 (base58btc) - NOT COMPLIANT per RFC Section 3.3
        raise ValueError(
            "CIDv0 (Qm prefix) not supported per RFC Section 3.3. "
            "DCPP requires CIDv1 with base32 encoding."
        )
    elif cid_str.startswith("f"):
        # base16 (hex) - NOT COMPLIANT per RFC Section 3.3
        if strict:
            raise ValueError(
                "Base16 (hex) CID encoding not allowed per RFC Section 3.3. "
                "DCPP requires base32 lowercase with 'b' prefix. "
                "Use strict=False for legacy format support."
            )
        raw_bytes = bytes.fromhex(cid_str[1:])
    else:
        # Missing multibase prefix - NOT COMPLIANT per RFC Section 3.3
        if strict:
            raise ValueError(
                "CID missing multibase prefix per RFC Section 3.3. "
                "DCPP requires base32 lowercase with 'b' prefix. "
                "Use strict=False for legacy format support."
            )
        # Lenient: assume base32 without prefix
        try:
            raw_bytes = _base32_decode(cid_str, strict=False)
        except Exception:
            raise ValueError(f"Unknown CID format: {cid_str[:10]}...")

    cid_info = _parse_cid_bytes(raw_bytes)

    # Validate hash function in strict mode per RFC Section 3.3
    if strict and cid_info.hash_func != Multihash.SHA2_256:
        raise ValueError(
            f"Hash function {cid_info.hash_func_name} ({cid_info.hash_func:#x}) "
            f"not allowed per RFC Section 3.3. "
            f"DCPP requires sha2-256 (0x12). "
            f"Use strict=False for legacy format support."
        )

    # Validate codec in strict mode per RFC Section 3.3
    if strict and cid_info.codec not in (Multicodec.RAW, Multicodec.DAG_PB):
        raise ValueError(
            f"Codec {cid_info.codec_name} ({cid_info.codec:#x}) "
            f"not allowed per RFC Section 3.3. "
            f"DCPP requires raw (0x55) or dag-pb (0x70). "
            f"Use strict=False for legacy format support."
        )

    return cid_info


def _parse_cid_bytes(data: bytes) -> CidInfo:
    """
    Parse raw CID bytes.

    Args:
        data: Raw CID bytes (after multibase decoding)

    Returns:
        CidInfo with parsed components

    Raises:
        ValueError: If CID structure is invalid
    """
    if len(data) < 4:
        raise ValueError("CID too short")

    offset = 0

    # Parse version
    version, consumed = _decode_varint(data, offset)
    offset += consumed

    if version != 1:
        raise ValueError(f"Unsupported CID version: {version}")

    # Parse codec
    codec, consumed = _decode_varint(data, offset)
    offset += consumed

    # Parse multihash
    # Hash function code
    hash_func, consumed = _decode_varint(data, offset)
    offset += consumed

    # Digest length
    digest_len, consumed = _decode_varint(data, offset)
    offset += consumed

    # Verify digest length
    if offset + digest_len > len(data):
        raise ValueError("Truncated digest")

    digest = data[offset : offset + digest_len]

    if len(digest) != digest_len:
        raise ValueError(f"Digest length mismatch: expected {digest_len}, got {len(digest)}")

    return CidInfo(
        version=version,
        codec=codec,
        hash_func=hash_func,
        digest=digest,
    )


def verify_cid(cid_str: str, data: bytes, strict: bool = True) -> bool:
    """
    Verify that content matches a CID.

    Parses the CID, extracts the hash algorithm, computes the hash of the
    provided data, and compares with the CID's digest.

    Per RFC Section 3.3:
    - All content is addressed using IPFS CIDv1
    - Implementations MUST verify content against CID before accepting
    - strict=True (default) enforces RFC Section 3.3 format requirements

    Args:
        cid_str: CID string
        data: Content bytes
        strict: If True (default), enforce RFC Section 3.3 requirements.
               If False, accept legacy CID formats.

    Returns:
        True if content matches CID, False otherwise

    Raises:
        ValueError: If CID format is invalid or hash algorithm unsupported
    """
    cid_info = parse_cid(cid_str, strict=strict)

    # Compute hash based on the CID's hash function
    # In strict mode, only SHA2-256 is allowed (validated in parse_cid)
    if cid_info.hash_func == Multihash.SHA2_256:
        computed_hash = hashlib.sha256(data).digest()
    elif cid_info.hash_func == Multihash.SHA2_512:
        # Only reachable in lenient mode
        computed_hash = hashlib.sha512(data).digest()
    elif cid_info.hash_func == Multihash.SHA3_256:
        # Only reachable in lenient mode
        computed_hash = hashlib.sha3_256(data).digest()
    elif cid_info.hash_func == Multihash.IDENTITY:
        # Only reachable in lenient mode
        # Identity hash - the digest IS the data
        computed_hash = data
    else:
        raise ValueError(f"Unsupported hash function: {cid_info.hash_func:#x}")

    # Compare digests (constant-time for security)
    if len(computed_hash) != len(cid_info.digest):
        return False

    result = 0
    for a, b in zip(computed_hash, cid_info.digest):
        result |= a ^ b
    return result == 0


def compute_cid(data: bytes, codec: int = Multicodec.RAW) -> str:
    """
    Compute a CIDv1 for content.

    Uses SHA-256 hash and base32 encoding per DCPP RFC Section 3.3.

    Args:
        data: Content bytes
        codec: Multicodec value (default: raw=0x55)

    Returns:
        CIDv1 string with 'b' multibase prefix (base32 lowercase)
    """
    # Compute SHA-256 hash
    digest = hashlib.sha256(data).digest()

    # Build CID bytes
    cid_bytes = bytearray()

    # Version (1)
    cid_bytes.extend(_encode_varint(1))

    # Codec
    cid_bytes.extend(_encode_varint(codec))

    # Multihash: hash function code (sha2-256 = 0x12)
    cid_bytes.extend(_encode_varint(Multihash.SHA2_256))

    # Multihash: digest length (32 bytes)
    cid_bytes.extend(_encode_varint(32))

    # Multihash: digest
    cid_bytes.extend(digest)

    # Encode as base32 with 'b' prefix
    return "b" + _base32_encode(bytes(cid_bytes))


def compute_multihash(data: bytes, hash_func: int = Multihash.SHA2_256) -> bytes:
    """
    Compute a multihash for content.

    Args:
        data: Content bytes
        hash_func: Hash function code (default: sha2-256)

    Returns:
        Multihash bytes (function code + length + digest)
    """
    if hash_func == Multihash.SHA2_256:
        digest = hashlib.sha256(data).digest()
    elif hash_func == Multihash.SHA2_512:
        digest = hashlib.sha512(data).digest()
    elif hash_func == Multihash.SHA3_256:
        digest = hashlib.sha3_256(data).digest()
    elif hash_func == Multihash.IDENTITY:
        digest = data
    else:
        raise ValueError(f"Unsupported hash function: {hash_func:#x}")

    # Build multihash
    result = bytearray()
    result.extend(_encode_varint(hash_func))
    result.extend(_encode_varint(len(digest)))
    result.extend(digest)

    return bytes(result)


def cid_to_bytes(cid_str: str, strict: bool = True) -> bytes:
    """
    Convert a CID string to its raw bytes (without multibase prefix).

    Per RFC Section 3.3, DCPP requires base32 lowercase with 'b' prefix.

    Args:
        cid_str: CID string
        strict: If True (default), enforce RFC Section 3.3 requirements.
               If False, accept legacy formats.

    Returns:
        Raw CID bytes

    Raises:
        ValueError: If CID format is invalid or non-compliant in strict mode
    """
    if cid_str.startswith("b"):
        # Base32 lowercase - SPEC COMPLIANT
        # In strict mode, validate lowercase characters per RFC Section 3.3
        return _base32_decode(cid_str[1:], strict=strict)
    elif cid_str.startswith("f"):
        # Base16 - NOT COMPLIANT per RFC Section 3.3
        if strict:
            raise ValueError(
                "Base16 (hex) CID encoding not allowed per RFC Section 3.3. "
                "DCPP requires base32 lowercase with 'b' prefix."
            )
        return bytes.fromhex(cid_str[1:])
    else:
        # Missing prefix - NOT COMPLIANT per RFC Section 3.3
        if strict:
            raise ValueError(
                "CID missing multibase prefix per RFC Section 3.3. "
                "DCPP requires base32 lowercase with 'b' prefix."
            )
        return _base32_decode(cid_str, strict=False)


def bytes_to_cid(data: bytes, base: str = "base32") -> str:
    """
    Convert raw CID bytes to a CID string.

    Args:
        data: Raw CID bytes
        base: Encoding base ("base32" or "base16")

    Returns:
        CID string with multibase prefix
    """
    if base == "base32":
        return "b" + _base32_encode(data)
    elif base == "base16":
        return "f" + data.hex()
    else:
        raise ValueError(f"Unsupported base: {base}")
