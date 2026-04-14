"""
DCPP Wire Protocol Framing

Implements the full envelope framing for all DCPP transports.
Based on Section 5 of the DCPP/1.0 Wire Protocol Specification.

IMPORTANT: All production DCPP traffic MUST use the full envelope format
(DCPPFramer / Profile1Framer) with:
- Magic bytes (0x44435050 "DCPP") - REQUIRED
- Version field - strict checking (only 0x01xx accepted)
- Request ID - REQUIRED for correlation
- CRC-32C checksum - MANDATORY verification

"""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, cast

import cbor2

from .constants import (
    MAGIC_BYTES,
    MAGIC_INT,
    MAX_MESSAGE_SIZE,
    MessageType,
)
from .utils import (
    crc32c,
    decode_uint16_be,
    decode_uint32_be,
    encode_uint16_be,
    encode_uint32_be,
    verify_crc32c,
)


class FramingError(Exception):
    """Exception raised for framing errors."""

    pass


class MessageTooLargeError(FramingError):
    """Exception raised when message exceeds maximum size."""

    pass


class ChecksumError(FramingError):
    """Exception raised when checksum verification fails."""

    pass


class MagicBytesError(FramingError):
    """Exception raised when magic bytes don't match."""

    pass


@dataclass
class Frame:
    """
    Represents a framed DCPP message.

    Attributes:
        message_type: The message type code
        payload: The CBOR-encoded message payload
    request_id: Optional request ID for correlation (Profile 1 only)
    """

    message_type: MessageType
    payload: bytes
    request_id: int = 0

    def decode_payload(self) -> dict[str, object]:
        """Decode the CBOR payload to a dictionary."""
        return cast(dict[str, object], cbor2.loads(self.payload))


class Profile1Framer:
    """
    Profile 1: Full Envelope (All Transports)

    This is the REQUIRED framing for all DCPP traffic (per RFC Section 5.1):

    +-----------------------------------------+
    |  Magic (4 bytes): 0x44435050 ("DCPP")   |  <- REQUIRED
    +-----------------------------------------+
    |  Version (2 bytes): 0x0100 (v1.0)       |  <- Big-endian, major.minor
    +-----------------------------------------+
    |  Type (2 bytes): Message type code      |  <- Big-endian
    +-----------------------------------------+
    |  Request ID (4 bytes): Correlation ID   |  <- REQUIRED for request/response matching
    +-----------------------------------------+
    |  Length (4 bytes): Payload length       |  <- Big-endian, unsigned
    +-----------------------------------------+
    |  CRC32 (4 bytes): Payload checksum      |  <- CRC-32C Castagnoli, MANDATORY
    +-----------------------------------------+
    |  Payload (variable): CBOR message       |
    +-----------------------------------------+

    Total header size: 20 bytes

    REQUIREMENTS:
    - Magic bytes MUST be included in all outbound messages
    - CRC-32C MUST be verified on all inbound messages (drop on mismatch)
    - Request ID MUST be generated for requests and echoed in responses
    - Version MUST be exactly 0x0100 (v1.0); other versions MUST be rejected (no backwards compatibility)
    """

    HEADER_SIZE = 20
    PROTOCOL_VERSION_1_0 = 0x0100  # DCPP v1.0
    # Per spec update: only accept exact version 0x0100, no backwards compatibility
    SUPPORTED_VERSION = 0x0100

    @staticmethod
    def encode(
        message_type: MessageType,
        payload: object,
        request_id: int | None = None,
    ) -> bytes:
        """
        Encode a message using Profile 1 framing.

        Args:
            message_type: The message type code
            payload: The message payload (dict to be CBOR-encoded, or raw bytes)
            request_id: Correlation ID (REQUIRED - random generated if not provided)

        Returns:
            Framed message bytes with full envelope (magic, version, request_id, CRC)

        Raises:
            MessageTooLargeError: If the payload exceeds maximum size
        """
        import random

        if isinstance(payload, (bytes, bytearray)):
            payload_bytes = bytes(payload)
        else:
            payload_bytes = cbor2.dumps(payload)

        if len(payload_bytes) > MAX_MESSAGE_SIZE:
            raise MessageTooLargeError(
                f"Payload size {len(payload_bytes)} exceeds maximum {MAX_MESSAGE_SIZE}"
            )

        # Generate random request ID if not provided (REQUIRED)
        if request_id is None:
            request_id = random.randint(1, 0xFFFFFFFF)  # Start from 1, reserve 0

        # Calculate CRC32C of payload (MANDATORY)
        checksum = crc32c(payload_bytes)

        # Build header (20 bytes - magic is REQUIRED)
        header = (
            MAGIC_BYTES  # Magic (4 bytes)
            + encode_uint16_be(Profile1Framer.PROTOCOL_VERSION_1_0)  # Version (2 bytes)
            + encode_uint16_be(message_type)  # Type (2 bytes)
            + encode_uint32_be(request_id)  # Request ID (4 bytes)
            + encode_uint32_be(len(payload_bytes))  # Length (4 bytes)
            + encode_uint32_be(checksum)  # CRC32 (4 bytes)
        )

        return header + payload_bytes

    @staticmethod
    def decode(data: bytes | BinaryIO) -> Frame:
        """
        Decode a Profile 1 framed message with MANDATORY CRC verification.

        Args:
            data: Framed message bytes or stream

        Returns:
            Decoded Frame

        Raises:
            FramingError: If framing is invalid or version unsupported
            MagicBytesError: If magic bytes don't match
            ChecksumError: If CRC-32C verification fails (MANDATORY)
            MessageTooLargeError: If payload exceeds maximum size
        """
        if isinstance(data, (bytes, bytearray)):
            return Profile1Framer._decode_bytes(bytes(data))
        return Profile1Framer._decode_stream(data)

    @staticmethod
    def _decode_bytes(data: bytes) -> Frame:
        """Decode from bytes with strict validation."""
        if len(data) < Profile1Framer.HEADER_SIZE:
            raise FramingError(
                f"Insufficient data for Profile 1 header: "
                f"expected {Profile1Framer.HEADER_SIZE}, got {len(data)}"
            )

        # Magic bytes (4 bytes) - REQUIRED
        magic = data[0:4]
        if magic != MAGIC_BYTES:
            raise MagicBytesError(f"Invalid magic bytes: expected {MAGIC_BYTES!r}, got {magic!r}")

        # Version (2 bytes) - STRICT: only accept exact v1.0 (no backwards compatibility)
        version = decode_uint16_be(data, 4)
        if version != Profile1Framer.SUPPORTED_VERSION:
            raise FramingError(
                f"Unsupported protocol version: 0x{version:04X}. "
                f"Only DCPP v1.0 (0x0100) is supported."
            )

        # Type (2 bytes)
        message_type = MessageType(decode_uint16_be(data, 6))

        # Request ID (4 bytes) - for correlation
        request_id = decode_uint32_be(data, 8)

        # Length (4 bytes)
        length = decode_uint32_be(data, 12)

        if length > MAX_MESSAGE_SIZE:
            raise MessageTooLargeError(f"Payload size {length} exceeds maximum {MAX_MESSAGE_SIZE}")

        # CRC32 (4 bytes)
        expected_crc = decode_uint32_be(data, 16)

        # Payload
        if len(data) < Profile1Framer.HEADER_SIZE + length:
            raise FramingError(
                f"Incomplete payload: expected {length} bytes, "
                f"got {len(data) - Profile1Framer.HEADER_SIZE}"
            )

        payload = data[Profile1Framer.HEADER_SIZE : Profile1Framer.HEADER_SIZE + length]

        # Verify checksum - MANDATORY (drop frame on mismatch)
        if not verify_crc32c(payload, expected_crc):
            actual_crc = crc32c(payload)
            raise ChecksumError(
                f"CRC32C mismatch: expected 0x{expected_crc:08X}, "
                f"got 0x{actual_crc:08X}. Frame dropped."
            )

        return Frame(message_type=message_type, payload=payload, request_id=request_id)

    @staticmethod
    def _decode_stream(stream: BinaryIO) -> Frame:
        """Decode from a stream with strict validation."""
        # Read full header (20 bytes)
        header = stream.read(Profile1Framer.HEADER_SIZE)
        if len(header) < Profile1Framer.HEADER_SIZE:
            raise FramingError(
                f"Incomplete header: expected {Profile1Framer.HEADER_SIZE}, got {len(header)}"
            )

        # Magic bytes (4 bytes) - REQUIRED
        magic = header[0:4]
        if magic != MAGIC_BYTES:
            raise MagicBytesError(f"Invalid magic bytes: expected {MAGIC_BYTES!r}, got {magic!r}")

        # Version (2 bytes) - STRICT: only accept exact v1.0 (no backwards compatibility)
        version = decode_uint16_be(header, 4)
        if version != Profile1Framer.SUPPORTED_VERSION:
            raise FramingError(
                f"Unsupported protocol version: 0x{version:04X}. "
                f"Only DCPP v1.0 (0x0100) is supported."
            )

        # Type (2 bytes)
        message_type = MessageType(decode_uint16_be(header, 6))

        # Request ID (4 bytes)
        request_id = decode_uint32_be(header, 8)

        # Length (4 bytes)
        length = decode_uint32_be(header, 12)

        if length > MAX_MESSAGE_SIZE:
            raise MessageTooLargeError(f"Payload size {length} exceeds maximum {MAX_MESSAGE_SIZE}")

        # CRC32 (4 bytes)
        expected_crc = decode_uint32_be(header, 16)

        # Payload
        payload = stream.read(length)
        if len(payload) < length:
            raise FramingError(f"Incomplete payload: expected {length} bytes, got {len(payload)}")

        # Verify checksum - MANDATORY (drop frame on mismatch)
        if not verify_crc32c(payload, expected_crc):
            actual_crc = crc32c(payload)
            raise ChecksumError(
                f"CRC32C mismatch: expected 0x{expected_crc:08X}, "
                f"got 0x{actual_crc:08X}. Frame dropped."
            )

        return Frame(message_type=message_type, payload=payload, request_id=request_id)

    @staticmethod
    def detect_profile1(data: bytes) -> bool:
        """
        Detect if data starts with Profile 1 magic bytes.

        Args:
            data: Data to check

        Returns:
            True if data starts with DCPP magic bytes
        """
        return len(data) >= 4 and data[:4] == MAGIC_BYTES


# =============================================================================
# DCPPFramer - Recommended framer for all production use
# =============================================================================


class DCPPFramer:
    """
    DCPP Protocol Framer - The REQUIRED framer for all production DCPP traffic.

    This is an alias for Profile1Framer with additional helpers for request/response
    correlation via Request IDs.

    All DCPP implementations MUST use this framer for:
    - libp2p streams (with Noise encryption)
    - Raw TCP connections (test-only)
    - Any other transport

    Features:
    - Magic bytes (0x44435050 "DCPP") - REQUIRED on all messages
    - Protocol version validation - STRICT (only v1.x accepted)
    - Request ID correlation - REQUIRED for all request/response pairs
    - CRC-32C integrity - MANDATORY verification (frames dropped on mismatch)
    """

    HEADER_SIZE = Profile1Framer.HEADER_SIZE
    PROTOCOL_VERSION = Profile1Framer.PROTOCOL_VERSION_1_0

    # Pending request tracking for correlation
    _pending_requests: dict[int, tuple[MessageType, float]] = {}

    @classmethod
    def encode_request(
        cls,
        message_type: MessageType,
        payload: dict[str, object] | bytes,
    ) -> tuple[bytes, int]:
        """
        Encode an outbound request message.

        Args:
            message_type: The message type code
            payload: The message payload

        Returns:
            Tuple of (framed_bytes, request_id) for correlation
        """
        import random
        import time

        request_id = random.randint(1, 0xFFFFFFFF)
        frame = Profile1Framer.encode(message_type, payload, request_id)

        # Track pending request for correlation
        cls._pending_requests[request_id] = (message_type, time.time())

        return frame, request_id

    @classmethod
    def encode_response(
        cls,
        message_type: MessageType,
        payload: dict[str, object] | bytes,
        request_id: int,
    ) -> bytes:
        """
        Encode a response message, echoing the request ID.

        Args:
            message_type: The response message type code
            payload: The response payload
            request_id: The request ID to echo (from the original request)

        Returns:
            Framed response bytes
        """
        return Profile1Framer.encode(message_type, payload, request_id)

    @classmethod
    def decode(cls, data: bytes | BinaryIO) -> Frame:
        """
        Decode a framed message with MANDATORY CRC verification.

        Args:
            data: Framed message bytes or stream

        Returns:
            Decoded Frame with request_id for correlation

        Raises:
            FramingError, MagicBytesError, ChecksumError, MessageTooLargeError
        """
        return Profile1Framer.decode(data)

    @classmethod
    def correlate_response(cls, frame: Frame) -> MessageType | None:
        """
        Correlate a response frame with its original request.

        Args:
            frame: The decoded response frame

        Returns:
            The original request message type if found, None otherwise
        """
        if frame.request_id in cls._pending_requests:
            original_type, _ = cls._pending_requests.pop(frame.request_id)
            return original_type
        return None

    @classmethod
    def clear_stale_requests(cls, max_age_seconds: float = 60.0) -> int:
        """
        Clear stale pending requests older than max_age_seconds.

        Args:
            max_age_seconds: Maximum age of pending requests

        Returns:
            Number of requests cleared
        """
        import time

        now = time.time()
        stale = [
            rid for rid, (_, ts) in cls._pending_requests.items() if now - ts > max_age_seconds
        ]
        for rid in stale:
            del cls._pending_requests[rid]
        return len(stale)
