"""
DCPP Utility Functions

Includes varint encoding/decoding and CRC32C checksum.
"""

from __future__ import annotations

import struct
from typing import BinaryIO


def encode_varint(value: int) -> bytes:
    """
    Encode an unsigned integer as an unsigned LEB128 varint.

    Used for varint-encoded fields in protocol utilities.

    Args:
        value: Non-negative integer to encode

    Returns:
        Varint-encoded bytes

    Raises:
        ValueError: If value is negative
    """
    if value < 0:
        raise ValueError("Cannot encode negative value as unsigned varint")

    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            break
    return bytes(result)


def decode_varint(data: bytes | BinaryIO, offset: int = 0) -> tuple[int, int]:
    """
    Decode an unsigned LEB128 varint from bytes or file-like object.

    Args:
        data: Bytes or file-like object to read from
        offset: Starting offset (only used for bytes input)

    Returns:
        Tuple of (decoded value, number of bytes consumed)

    Raises:
        ValueError: If varint is malformed or incomplete
    """
    if isinstance(data, (bytes, bytearray)):
        return _decode_varint_bytes(bytes(data), offset)
    return _decode_varint_stream(data)


def _decode_varint_bytes(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode varint from bytes."""
    result = 0
    shift = 0
    bytes_read = 0

    while True:
        if offset + bytes_read >= len(data):
            raise ValueError("Incomplete varint: unexpected end of data")

        byte = data[offset + bytes_read]
        bytes_read += 1

        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break

        shift += 7
        if shift > 63:
            raise ValueError("Varint too long (exceeds 64 bits)")

    return result, bytes_read


def _decode_varint_stream(stream: BinaryIO) -> tuple[int, int]:
    """Decode varint from a stream."""
    result = 0
    shift = 0
    bytes_read = 0

    while True:
        byte_data = stream.read(1)
        if not byte_data:
            raise ValueError("Incomplete varint: unexpected end of stream")

        byte = byte_data[0]
        bytes_read += 1

        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            break

        shift += 7
        if shift > 63:
            raise ValueError("Varint too long (exceeds 64 bits)")

    return result, bytes_read


# CRC32C lookup table (precomputed)
_CRC32C_TABLE: list[int] | None = None


def _make_crc32c_table() -> list[int]:
    """
    Generate CRC32C lookup table using Castagnoli polynomial.

    CRC32C parameters (Section 5.2.1):
    - Polynomial: 0x1EDC6F41 (Castagnoli)
    - Initial value: 0xFFFFFFFF
    - Input reflected: Yes
    - Output reflected: Yes
    - Final XOR: 0xFFFFFFFF
    """
    poly = 0x82F63B78  # Reflected Castagnoli polynomial
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        table.append(crc)
    return table


def crc32c(data: bytes) -> int:
    """
    Calculate CRC32C checksum (Castagnoli polynomial, iSCSI).

    This is used for Profile 1 framing (Section 5.2.1).

    Args:
        data: Bytes to checksum

    Returns:
        32-bit CRC32C checksum
    """
    global _CRC32C_TABLE
    if _CRC32C_TABLE is None:
        _CRC32C_TABLE = _make_crc32c_table()

    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def verify_crc32c(data: bytes, expected: int) -> bool:
    """
    Verify CRC32C checksum.

    Args:
        data: Data to verify
        expected: Expected checksum

    Returns:
        True if checksum matches
    """
    return crc32c(data) == expected


def encode_uint16_be(value: int) -> bytes:
    """Encode 16-bit unsigned integer as big-endian bytes."""
    return struct.pack(">H", value)


def decode_uint16_be(data: bytes, offset: int = 0) -> int:
    """Decode big-endian 16-bit unsigned integer."""
    return int(struct.unpack(">H", data[offset : offset + 2])[0])


def encode_uint32_be(value: int) -> bytes:
    """Encode 32-bit unsigned integer as big-endian bytes."""
    return struct.pack(">I", value)


def decode_uint32_be(data: bytes, offset: int = 0) -> int:
    """Decode big-endian 32-bit unsigned integer."""
    return int(struct.unpack(">I", data[offset : offset + 4])[0])


def encode_uint64_be(value: int) -> bytes:
    """Encode 64-bit unsigned integer as big-endian bytes."""
    return struct.pack(">Q", value)


def decode_uint64_be(data: bytes, offset: int = 0) -> int:
    """Decode big-endian 64-bit unsigned integer."""
    return int(struct.unpack(">Q", data[offset : offset + 8])[0])
