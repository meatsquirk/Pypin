"""Tests for DCPP utility functions."""

import io
import pytest

from dcpp_python.utils import (
    crc32c,
    decode_uint16_be,
    decode_uint32_be,
    decode_uint64_be,
    decode_varint,
    encode_uint16_be,
    encode_uint32_be,
    encode_uint64_be,
    encode_varint,
    verify_crc32c,
)


class TestVarint:
    """Test varint encoding/decoding (LEB128)."""

    def test_encode_zero(self):
        """Encode 0."""
        assert encode_varint(0) == b"\x00"

    def test_encode_small_values(self):
        """Encode values < 128 (single byte)."""
        assert encode_varint(1) == b"\x01"
        assert encode_varint(127) == b"\x7f"

    def test_encode_two_byte_values(self):
        """Encode values requiring two bytes."""
        assert encode_varint(128) == b"\x80\x01"
        assert encode_varint(255) == b"\xff\x01"
        assert encode_varint(16383) == b"\xff\x7f"

    def test_encode_larger_values(self):
        """Encode larger values."""
        assert encode_varint(16384) == b"\x80\x80\x01"
        assert encode_varint(2097151) == b"\xff\xff\x7f"

    def test_encode_negative_raises(self):
        """Negative values should raise ValueError."""
        with pytest.raises(ValueError):
            encode_varint(-1)

    def test_decode_zero(self):
        """Decode 0."""
        value, size = decode_varint(b"\x00")
        assert value == 0
        assert size == 1

    def test_decode_small_values(self):
        """Decode values < 128."""
        value, size = decode_varint(b"\x01")
        assert value == 1
        assert size == 1

        value, size = decode_varint(b"\x7f")
        assert value == 127
        assert size == 1

    def test_decode_two_byte_values(self):
        """Decode values requiring two bytes."""
        value, size = decode_varint(b"\x80\x01")
        assert value == 128
        assert size == 2

        value, size = decode_varint(b"\xff\x01")
        assert value == 255
        assert size == 2

    def test_decode_larger_values(self):
        """Decode larger values."""
        value, size = decode_varint(b"\x80\x80\x01")
        assert value == 16384
        assert size == 3

    def test_decode_with_offset(self):
        """Decode with offset."""
        data = b"\x00\x00\x80\x01\x00"
        value, size = decode_varint(data, 2)
        assert value == 128
        assert size == 2

    def test_decode_from_stream(self):
        """Decode from file-like object."""
        stream = io.BytesIO(b"\x80\x01extra")
        value, size = decode_varint(stream)
        assert value == 128
        assert size == 2
        assert stream.read() == b"extra"

    def test_decode_incomplete_raises(self):
        """Incomplete varint should raise ValueError."""
        with pytest.raises(ValueError, match="Incomplete varint"):
            decode_varint(b"\x80")

    def test_decode_too_long_raises(self):
        """Varint exceeding 64 bits should raise ValueError."""
        # 10 bytes of continuation bits
        with pytest.raises(ValueError, match="too long"):
            decode_varint(b"\x80" * 10 + b"\x01")

    def test_roundtrip(self):
        """Encode then decode should produce original value."""
        test_values = [0, 1, 127, 128, 255, 256, 16383, 16384, 2**20, 2**32, 2**62]
        for value in test_values:
            encoded = encode_varint(value)
            decoded, _ = decode_varint(encoded)
            assert decoded == value, f"Roundtrip failed for {value}"


class TestCRC32C:
    """Test CRC32C checksum (Castagnoli polynomial)."""

    def test_empty_data(self):
        """CRC of empty data."""
        assert crc32c(b"") == 0x00000000

    def test_known_vectors(self):
        """Test against known CRC32C test vectors."""
        # Test vectors from iSCSI spec
        assert crc32c(b"\x00" * 32) == 0x8A9136AA
        assert crc32c(b"\xff" * 32) == 0x62A8AB43

    def test_hello_world(self):
        """Test with ASCII string."""
        # Known CRC32C value for "hello world"
        result = crc32c(b"hello world")
        assert isinstance(result, int)
        assert 0 <= result <= 0xFFFFFFFF

    def test_verify_crc32c(self):
        """Test verification helper."""
        data = b"test data for crc"
        checksum = crc32c(data)
        assert verify_crc32c(data, checksum)
        assert not verify_crc32c(data, checksum ^ 1)

    def test_incremental_different_results(self):
        """Different data produces different checksums."""
        assert crc32c(b"abc") != crc32c(b"abd")


class TestIntegerEncoding:
    """Test big-endian integer encoding/decoding."""

    def test_uint16_encode_decode(self):
        """Test 16-bit encoding/decoding."""
        assert encode_uint16_be(0) == b"\x00\x00"
        assert encode_uint16_be(1) == b"\x00\x01"
        assert encode_uint16_be(256) == b"\x01\x00"
        assert encode_uint16_be(0xFFFF) == b"\xff\xff"

        assert decode_uint16_be(b"\x00\x00") == 0
        assert decode_uint16_be(b"\x00\x01") == 1
        assert decode_uint16_be(b"\x01\x00") == 256
        assert decode_uint16_be(b"\xff\xff") == 0xFFFF

    def test_uint32_encode_decode(self):
        """Test 32-bit encoding/decoding."""
        assert encode_uint32_be(0) == b"\x00\x00\x00\x00"
        assert encode_uint32_be(1) == b"\x00\x00\x00\x01"
        assert encode_uint32_be(0x44435050) == b"DCPP"  # Magic bytes
        assert encode_uint32_be(0xFFFFFFFF) == b"\xff\xff\xff\xff"

        assert decode_uint32_be(b"\x00\x00\x00\x00") == 0
        assert decode_uint32_be(b"DCPP") == 0x44435050
        assert decode_uint32_be(b"\xff\xff\xff\xff") == 0xFFFFFFFF

    def test_uint64_encode_decode(self):
        """Test 64-bit encoding/decoding."""
        assert encode_uint64_be(0) == b"\x00" * 8
        assert encode_uint64_be(1) == b"\x00" * 7 + b"\x01"
        assert decode_uint64_be(b"\x00" * 8) == 0
        assert decode_uint64_be(b"\x00" * 7 + b"\x01") == 1

    def test_decode_with_offset(self):
        """Test decoding with offset."""
        data = b"\xff\xff\x00\x01\x00\x02"
        assert decode_uint16_be(data, 0) == 0xFFFF
        assert decode_uint16_be(data, 2) == 1
        assert decode_uint16_be(data, 4) == 2

    def test_roundtrip(self):
        """Encode then decode should produce original value."""
        for value in [0, 1, 255, 256, 0xFFFF, 0x10000, 0xFFFFFFFF]:
            if value <= 0xFFFF:
                assert decode_uint16_be(encode_uint16_be(value)) == value
            if value <= 0xFFFFFFFF:
                assert decode_uint32_be(encode_uint32_be(value)) == value
            assert decode_uint64_be(encode_uint64_be(value)) == value
