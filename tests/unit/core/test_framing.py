"""Tests for DCPP message framing."""

import io
import pytest

from dcpp_python.core.constants import MAGIC_BYTES, MAX_MESSAGE_SIZE, MessageType
from dcpp_python.framing import (
    ChecksumError,
    Frame,
    FramingError,
    MagicBytesError,
    MessageTooLargeError,
    Profile1Framer,
)
from dcpp_python.utils import crc32c


class TestFrame:
    """Test Frame dataclass."""

    def test_decode_payload(self):
        """Test CBOR payload decoding."""
        import cbor2

        payload = cbor2.dumps({"key": "value", "number": 42})
        frame = Frame(message_type=MessageType.HELLO, payload=payload)

        decoded = frame.decode_payload()
        assert decoded == {"key": "value", "number": 42}


class TestProfile1Framer:
    """Test Profile 1 (raw transport) framing."""

    def test_encode_includes_magic(self):
        """Encoded message should start with magic bytes."""
        encoded = Profile1Framer.encode(MessageType.HELLO, {"test": "data"})
        assert encoded[:4] == MAGIC_BYTES

    def test_encode_header_structure(self):
        """Verify header structure."""
        payload = {"test": "data"}
        encoded = Profile1Framer.encode(MessageType.HELLO, payload)

        # Magic (4 bytes)
        assert encoded[0:4] == b"DCPP"
        # Version (2 bytes) - 0x0100 for DCPP v1.0
        assert encoded[4:6] == b"\x01\x00"
        # Type (2 bytes) - HELLO = 0x0001
        assert encoded[6:8] == b"\x00\x01"
        # Length (4 bytes) - should match actual CBOR length
        import cbor2
        import struct

        expected_len = len(cbor2.dumps(payload))
        # Length is at bytes 12-15 (after Magic+Version+Type+RequestID)
        actual_len = struct.unpack(">I", encoded[12:16])[0]
        assert actual_len == expected_len

    def test_encode_crc_verification(self):
        """Verify CRC is computed correctly."""
        import struct

        import cbor2

        payload = {"test": "data"}
        encoded = Profile1Framer.encode(MessageType.HELLO, payload)

        # Extract CRC from header (bytes 16-19, after Magic+Version+Type+RequestID+Length)
        stored_crc = struct.unpack(">I", encoded[16:20])[0]
        # Compute CRC of payload
        payload_bytes = cbor2.dumps(payload)
        computed_crc = crc32c(payload_bytes)
        assert stored_crc == computed_crc

    def test_encode_message_too_large(self):
        """Encoding oversized payload should raise."""
        payload = b"\x00" * (MAX_MESSAGE_SIZE + 1)
        with pytest.raises(MessageTooLargeError):
            Profile1Framer.encode(MessageType.HELLO, payload)

    def test_decode_bytes(self):
        """Decode from bytes."""
        payload = {"hello": "world"}
        encoded = Profile1Framer.encode(MessageType.HELLO, payload)

        frame = Profile1Framer.decode(encoded)
        assert frame.message_type == MessageType.HELLO
        assert frame.decode_payload() == payload

    def test_decode_stream(self):
        """Decode from stream."""
        payload = {"stream": "test"}
        encoded = Profile1Framer.encode(MessageType.GET_PEERS, payload)
        stream = io.BytesIO(encoded + b"trailing")

        frame = Profile1Framer.decode(stream)
        assert frame.message_type == MessageType.GET_PEERS
        assert frame.decode_payload() == payload
        assert stream.read() == b"trailing"

    def test_decode_bad_magic(self):
        """Decoding with wrong magic should raise."""
        encoded = Profile1Framer.encode(MessageType.HELLO, {"test": "data"})
        bad_magic = b"XXXX" + encoded[4:]
        with pytest.raises(MagicBytesError):
            Profile1Framer.decode(bad_magic)

    def test_decode_bad_checksum(self):
        """Decoding with wrong checksum should raise."""
        encoded = Profile1Framer.encode(MessageType.HELLO, {"test": "data"})
        # Corrupt the CRC field (bytes 16-19)
        corrupted = encoded[:16] + b"\xff\xff\xff\xff" + encoded[20:]
        with pytest.raises(ChecksumError):
            Profile1Framer.decode(corrupted)

    def test_crc_verification_mandatory(self):
        """CRC verification is MANDATORY per spec - cannot be disabled.

        Per RFC Section 5.2: "CRC-32C MUST be verified on all inbound messages
        (drop on mismatch)". There is no option to skip checksum verification.
        """
        encoded = Profile1Framer.encode(MessageType.HELLO, {"test": "data"})
        # Corrupt the CRC field (bytes 16-19)
        corrupted = encoded[:16] + b"\xff\xff\xff\xff" + encoded[20:]
        # MUST raise ChecksumError - verification cannot be disabled
        with pytest.raises(ChecksumError):
            Profile1Framer.decode(corrupted)

    def test_decode_incomplete_header(self):
        """Decoding incomplete header should raise."""
        with pytest.raises(FramingError, match="Insufficient data"):
            Profile1Framer.decode(b"DCPP\x00\x00")

    def test_decode_incomplete_payload(self):
        """Decoding incomplete payload should raise."""
        encoded = Profile1Framer.encode(MessageType.HELLO, {"test": "data"})
        with pytest.raises(FramingError, match="Incomplete payload"):
            Profile1Framer.decode(encoded[:-2])

    def test_detect_profile1(self):
        """Test magic byte detection."""
        assert Profile1Framer.detect_profile1(b"DCPP...")
        assert Profile1Framer.detect_profile1(MAGIC_BYTES + b"more data")
        assert not Profile1Framer.detect_profile1(b"XXXX...")
        assert not Profile1Framer.detect_profile1(b"DCP")  # Too short

    def test_roundtrip_all_message_types(self):
        """Roundtrip encoding/decoding for various message types."""
        test_cases = [
            (MessageType.HELLO, {"node_id": b"test", "timestamp": 12345}),
            (MessageType.ANNOUNCE, {"collections": [], "signature": b"sig"}),
            (MessageType.MANIFEST, {"collection_id": "test", "manifest": {}}),
            (MessageType.PEERS, {"collection_id": "test", "peers": []}),
            (MessageType.HEALTH_PROBE, {"nonce": b"nonce", "challenges": []}),
            (MessageType.HEALTH_RESPONSE, {"nonce": b"nonce", "responses": []}),
            (MessageType.GOODBYE, {"reason": "shutdown"}),
            (MessageType.ERROR, {"code": 1, "message": "error", "request_type": 1}),
        ]

        for msg_type, payload in test_cases:
            encoded = Profile1Framer.encode(msg_type, payload)
            frame = Profile1Framer.decode(encoded)
            assert frame.message_type == msg_type
            assert frame.decode_payload() == payload
