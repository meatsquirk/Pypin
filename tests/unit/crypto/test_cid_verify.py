"""
Tests for DCPP CID Verification Module
"""

import pytest
from dcpp_python.cid_verify import (
    parse_cid,
    verify_cid,
    compute_cid,
    compute_multihash,
    cid_to_bytes,
    bytes_to_cid,
    CidInfo,
    Multicodec,
    Multihash,
    _encode_varint,
    _decode_varint,
    _base32_encode,
    _base32_decode,
)


class TestVarint:
    """Tests for varint encoding/decoding."""

    def test_encode_zero(self):
        assert _encode_varint(0) == b"\x00"

    def test_encode_small(self):
        assert _encode_varint(1) == b"\x01"
        assert _encode_varint(127) == b"\x7f"

    def test_encode_medium(self):
        assert _encode_varint(128) == b"\x80\x01"
        assert _encode_varint(300) == b"\xac\x02"

    def test_encode_large(self):
        # 0x55 (85) - raw codec
        assert _encode_varint(0x55) == b"\x55"
        # 0x70 (112) - dag-pb codec
        assert _encode_varint(0x70) == b"\x70"

    def test_decode_zero(self):
        value, consumed = _decode_varint(b"\x00")
        assert value == 0
        assert consumed == 1

    def test_decode_small(self):
        value, consumed = _decode_varint(b"\x01")
        assert value == 1
        assert consumed == 1

    def test_decode_medium(self):
        value, consumed = _decode_varint(b"\x80\x01")
        assert value == 128
        assert consumed == 2

    def test_decode_with_offset(self):
        value, consumed = _decode_varint(b"\xff\x80\x01", offset=1)
        assert value == 128
        assert consumed == 2

    def test_roundtrip(self):
        for value in [0, 1, 127, 128, 255, 256, 0x55, 0x70, 0x12, 0x1220, 65535]:
            encoded = _encode_varint(value)
            decoded, _ = _decode_varint(encoded)
            assert decoded == value


class TestBase32:
    """Tests for base32 encoding/decoding."""

    def test_encode_empty(self):
        assert _base32_encode(b"") == ""

    def test_encode_simple(self):
        # "f" encodes to "my" in base32
        assert _base32_encode(b"f") == "my"

    def test_decode_roundtrip(self):
        test_data = [
            b"",
            b"hello",
            b"\x00\x01\x02",
            bytes(range(256)),
        ]
        for data in test_data:
            encoded = _base32_encode(data)
            decoded = _base32_decode(encoded)
            assert decoded == data


class TestParseCid:
    """Tests for CID parsing."""

    def test_parse_valid_cidv1_raw(self):
        # Generate a known CIDv1 for test data
        test_data = b"hello world"
        cid_str = compute_cid(test_data, codec=Multicodec.RAW)

        info = parse_cid(cid_str)
        assert info.version == 1
        assert info.codec == Multicodec.RAW
        assert info.hash_func == Multihash.SHA2_256
        assert len(info.digest) == 32

    def test_parse_valid_cidv1_dag_pb(self):
        test_data = b"test content"
        cid_str = compute_cid(test_data, codec=Multicodec.DAG_PB)

        info = parse_cid(cid_str)
        assert info.version == 1
        assert info.codec == Multicodec.DAG_PB
        assert info.hash_func == Multihash.SHA2_256

    def test_parse_without_multibase_prefix_lenient(self):
        # CID without 'b' prefix should work in lenient mode
        test_data = b"test"
        cid_str = compute_cid(test_data)
        # Remove the 'b' prefix
        cid_no_prefix = cid_str[1:]

        # Lenient mode (strict=False) should accept missing prefix
        info = parse_cid(cid_no_prefix, strict=False)
        assert info.version == 1

    def test_parse_without_multibase_prefix_strict_rejects(self):
        # CID without 'b' prefix should be rejected in strict mode (RFC Section 3.3)
        test_data = b"test"
        cid_str = compute_cid(test_data)
        cid_no_prefix = cid_str[1:]

        with pytest.raises(ValueError, match="missing multibase prefix"):
            parse_cid(cid_no_prefix, strict=True)  # Default is strict=True

    def test_parse_base16_strict_rejects(self):
        # Base16 (hex) prefix should be rejected in strict mode (RFC Section 3.3)
        test_data = b"test"
        cid_str = compute_cid(test_data)
        # Convert to base16 format
        raw_bytes = cid_to_bytes(cid_str, strict=False)
        cid_hex = "f" + raw_bytes.hex()

        with pytest.raises(ValueError, match="Base16.*not allowed"):
            parse_cid(cid_hex, strict=True)

    def test_parse_uppercase_base32_strict_rejects(self):
        # Uppercase base32 should be rejected in strict mode (RFC Section 3.3)
        test_data = b"test"
        cid_str = compute_cid(test_data)
        # Convert to uppercase (keeping 'b' prefix lowercase)
        cid_upper = "b" + cid_str[1:].upper()

        with pytest.raises(ValueError, match="uppercase characters"):
            parse_cid(cid_upper, strict=True)

    def test_parse_uppercase_base32_lenient_accepts(self):
        # Uppercase base32 should be accepted in lenient mode
        test_data = b"test"
        cid_str = compute_cid(test_data)
        cid_upper = "b" + cid_str[1:].upper()

        # Lenient mode should accept uppercase
        info = parse_cid(cid_upper, strict=False)
        assert info.version == 1

    def test_parse_empty_raises(self):
        with pytest.raises(ValueError, match="Empty CID"):
            parse_cid("")

    def test_parse_cidv0_raises(self):
        # CIDv0 starts with "Qm"
        with pytest.raises(ValueError, match="CIDv0"):
            parse_cid("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")

    def test_cid_info_names(self):
        test_data = b"test"
        cid_str = compute_cid(test_data, codec=Multicodec.RAW)
        info = parse_cid(cid_str)

        assert info.codec_name == "raw"
        assert info.hash_func_name == "sha2-256"


class TestVerifyCid:
    """Tests for CID verification."""

    def test_verify_valid_content(self):
        test_data = b"hello world"
        cid_str = compute_cid(test_data)

        assert verify_cid(cid_str, test_data) is True

    def test_verify_invalid_content(self):
        test_data = b"hello world"
        cid_str = compute_cid(test_data)

        # Different data should fail
        assert verify_cid(cid_str, b"different data") is False

    def test_verify_empty_content(self):
        test_data = b""
        cid_str = compute_cid(test_data)

        assert verify_cid(cid_str, test_data) is True
        assert verify_cid(cid_str, b"not empty") is False

    def test_verify_large_content(self):
        test_data = b"x" * 10000
        cid_str = compute_cid(test_data)

        assert verify_cid(cid_str, test_data) is True

    def test_verify_binary_content(self):
        test_data = bytes(range(256))
        cid_str = compute_cid(test_data)

        assert verify_cid(cid_str, test_data) is True


class TestComputeCid:
    """Tests for CID computation."""

    def test_compute_deterministic(self):
        test_data = b"test content"
        cid1 = compute_cid(test_data)
        cid2 = compute_cid(test_data)

        assert cid1 == cid2

    def test_compute_different_data(self):
        cid1 = compute_cid(b"data1")
        cid2 = compute_cid(b"data2")

        assert cid1 != cid2

    def test_compute_with_raw_codec(self):
        cid = compute_cid(b"test", codec=Multicodec.RAW)
        info = parse_cid(cid)
        assert info.codec == Multicodec.RAW

    def test_compute_with_dag_pb_codec(self):
        cid = compute_cid(b"test", codec=Multicodec.DAG_PB)
        info = parse_cid(cid)
        assert info.codec == Multicodec.DAG_PB

    def test_compute_starts_with_b_prefix(self):
        cid = compute_cid(b"test")
        assert cid.startswith("b")

    def test_compute_roundtrip_verify(self):
        test_cases = [
            b"",
            b"a",
            b"hello world",
            bytes(range(256)),
            b"\x00" * 1000,
        ]
        for data in test_cases:
            cid = compute_cid(data)
            assert verify_cid(cid, data) is True


class TestComputeMultihash:
    """Tests for multihash computation."""

    def test_sha256_multihash(self):
        data = b"test"
        mh = compute_multihash(data, Multihash.SHA2_256)

        # First byte should be hash function code (0x12)
        assert mh[0] == 0x12
        # Second byte should be length (32)
        assert mh[1] == 0x20
        # Total length: 2 header bytes + 32 digest bytes
        assert len(mh) == 34

    def test_identity_multihash(self):
        data = b"short"
        mh = compute_multihash(data, Multihash.IDENTITY)

        assert mh[0] == 0x00  # identity
        assert mh[1] == len(data)
        assert mh[2:] == data


class TestCidBytesConversion:
    """Tests for CID string/bytes conversion."""

    def test_cid_to_bytes_base32(self):
        cid = compute_cid(b"test")
        raw_bytes = cid_to_bytes(cid)

        # Should be able to parse the raw bytes
        info = parse_cid(bytes_to_cid(raw_bytes))
        assert info.version == 1

    def test_bytes_to_cid_base32(self):
        cid = compute_cid(b"test")
        raw_bytes = cid_to_bytes(cid)
        reconstructed = bytes_to_cid(raw_bytes, "base32")

        assert reconstructed == cid

    def test_bytes_to_cid_base16_lenient(self):
        # Base16 conversion works in lenient mode
        raw_bytes = b"\x01\x55\x12\x20" + b"\x00" * 32
        cid = bytes_to_cid(raw_bytes, "base16")

        assert cid.startswith("f")
        # Lenient mode should accept base16
        assert cid_to_bytes(cid, strict=False) == raw_bytes

    def test_cid_to_bytes_base16_strict_rejects(self):
        # Base16 should be rejected in strict mode (RFC Section 3.3)
        raw_bytes = b"\x01\x55\x12\x20" + b"\x00" * 32
        cid = bytes_to_cid(raw_bytes, "base16")

        with pytest.raises(ValueError, match="Base16.*not allowed"):
            cid_to_bytes(cid, strict=True)


class TestKnownVectors:
    """Tests using known test vectors for interoperability."""

    def test_empty_data_cid(self):
        # SHA-256 of empty data is a well-known value
        empty_hash = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        cid = compute_cid(b"")
        info = parse_cid(cid)

        assert info.digest == empty_hash

    def test_hello_world_cid(self):
        # SHA-256 of "hello world" is well-known
        expected_hash = bytes.fromhex(
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        )
        cid = compute_cid(b"hello world")
        info = parse_cid(cid)

        assert info.digest == expected_hash
