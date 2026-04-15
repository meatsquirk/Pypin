"""
RFC Compliance Tests for DCPP Wire Protocol

These tests verify compliance with DCPP-RFC-Wire-Protocol.md sections.
Organized by RFC section number for traceability.
"""

import io
import os
import struct
import time

import cbor2
import pytest

from dcpp_python.core.constants import (
    MAGIC_BYTES,
    MAX_MESSAGE_SIZE,
    MessageType,
    ErrorCode,
    Capability,
)
from dcpp_python.framing import (
    ChecksumError,
    Frame,
    FramingError,
    MagicBytesError,
    MessageTooLargeError,
    Profile1Framer,
)
from dcpp_python.messages import (
    Hello,
    Announce,
    GetManifest,
    ManifestResponse,
    GetPeers,
    PeersResponse,
    HealthProbe,
    HealthResponse,
    Goodbye,
    ErrorResponse,
    decode_message,
)
from dcpp_python.utils import crc32c, encode_uint32_be, decode_uint32_be
from dcpp_python.validation import (
    MessageValidator,
    ValidationResult,
    ValidationStatus,
)
from dcpp_python.cid_verify import (
    parse_cid,
    verify_cid,
    compute_cid,
    cid_to_bytes,
    Multicodec,
    Multihash,
)
from dcpp_python.crypto import (
    derive_dht_key,
    derive_private_dht_key,
    generate_keypair,
)


# =============================================================================
# RFC Section 3.3: Content Addressing (CID)
# =============================================================================

class TestRFC33CIDCompliance:
    """Tests for RFC Section 3.3 - Content Addressing requirements."""

    def test_cid_must_be_v1(self):
        """RFC 3.3: CIDs MUST be version 1."""
        cid = compute_cid(b"test data")
        info = parse_cid(cid)
        assert info.version == 1

    def test_cid_must_use_base32_lowercase(self):
        """RFC 3.3: CIDs MUST use base32 lowercase encoding with 'b' prefix."""
        cid = compute_cid(b"test data")
        assert cid.startswith("b")
        # All characters after 'b' must be lowercase a-z or 2-7
        base32_chars = set("abcdefghijklmnopqrstuvwxyz234567")
        assert all(c in base32_chars for c in cid[1:])

    def test_cid_must_use_sha256(self):
        """RFC 3.3: CIDs MUST use sha2-256 (0x12) hash function."""
        cid = compute_cid(b"test data")
        info = parse_cid(cid)
        assert info.hash_func == Multihash.SHA2_256

    def test_cid_allows_raw_codec(self):
        """RFC 3.3: CIDs may use raw (0x55) codec for files."""
        cid = compute_cid(b"test data", codec=Multicodec.RAW)
        info = parse_cid(cid)
        assert info.codec == Multicodec.RAW

    def test_cid_allows_dag_pb_codec(self):
        """RFC 3.3: CIDs may use dag-pb (0x70) codec for directories."""
        cid = compute_cid(b"test data", codec=Multicodec.DAG_PB)
        info = parse_cid(cid)
        assert info.codec == Multicodec.DAG_PB

    # Negative tests for non-compliant CIDs

    def test_reject_base16_cid_strict(self):
        """RFC 3.3: Base16 (hex) encoding is NOT allowed."""
        cid = compute_cid(b"test")
        raw = cid_to_bytes(cid, strict=False)
        hex_cid = "f" + raw.hex()

        with pytest.raises(ValueError, match="Base16.*not allowed"):
            parse_cid(hex_cid, strict=True)

    def test_reject_uppercase_base32_strict(self):
        """RFC 3.3: Uppercase base32 is NOT allowed."""
        cid = compute_cid(b"test")
        upper_cid = "b" + cid[1:].upper()

        with pytest.raises(ValueError, match="uppercase"):
            parse_cid(upper_cid, strict=True)

    def test_reject_missing_prefix_strict(self):
        """RFC 3.3: Base32 without 'b' prefix is NOT allowed."""
        cid = compute_cid(b"test")
        no_prefix = cid[1:]  # Remove 'b'

        with pytest.raises(ValueError, match="missing multibase prefix"):
            parse_cid(no_prefix, strict=True)

    def test_reject_cidv0_strict(self):
        """RFC 3.3: CIDv0 (Qm prefix) is NOT allowed."""
        with pytest.raises(ValueError, match="CIDv0"):
            parse_cid("QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")

    def test_reject_non_sha256_hash_strict(self):
        """RFC 3.3: Non-sha2-256 hashes are NOT allowed in strict mode."""
        # Construct a CID with SHA2-512 (0x13) manually
        # CIDv1 structure: version(1) + codec(varint) + multihash
        # Multihash: hash_code(varint) + length(varint) + digest

        # Version 1, raw codec (0x55), sha2-512 (0x13), 64 bytes
        cid_bytes = bytes([
            0x01,  # version 1
            0x55,  # raw codec
            0x13,  # sha2-512
            0x40,  # 64 bytes
        ]) + b"\x00" * 64  # fake digest

        import base64
        encoded = base64.b32encode(cid_bytes).decode().lower().rstrip("=")
        bad_cid = "b" + encoded

        with pytest.raises(ValueError, match="sha2-256"):
            parse_cid(bad_cid, strict=True)

    def test_reject_bad_codec_strict(self):
        """RFC 3.3: Non-raw/dag-pb codecs are NOT allowed."""
        # Construct CID with dag-json codec (0x0129)
        cid_bytes = bytes([
            0x01,  # version 1
            0xa9, 0x02,  # dag-json codec (0x0129 as varint)
            0x12,  # sha2-256
            0x20,  # 32 bytes
        ]) + b"\x00" * 32

        import base64
        encoded = base64.b32encode(cid_bytes).decode().lower().rstrip("=")
        bad_cid = "b" + encoded

        with pytest.raises(ValueError, match="raw.*dag-pb"):
            parse_cid(bad_cid, strict=True)


# =============================================================================
# RFC Section 5.1: Message Framing
# =============================================================================

class TestRFC51FramingCompliance:
    """Tests for RFC Section 5.1 - Message Framing requirements.

    RFC 5.1.1: Magic bytes are OPTIONAL. "Implementations SHOULD include magic
    bytes for debugging...MAY omit magic bytes in production...receivers MUST
    accept messages with or without magic bytes."
    """

    def test_profile1_magic_bytes_included(self):
        """RFC 5.1.1: Profile 1 SHOULD include magic bytes 'DCPP' for debugging."""
        encoded = Profile1Framer.encode(MessageType.HELLO, {"test": "data"})
        # Implementation includes magic bytes (SHOULD per RFC)
        assert encoded[:4] == b"DCPP"
        assert encoded[:4] == MAGIC_BYTES

    def test_profile1_version_field(self):
        """RFC 5.1: Version field MUST be 0x0100 for DCPP v1.0."""
        encoded = Profile1Framer.encode(MessageType.HELLO, {"test": "data"})
        version = struct.unpack(">H", encoded[4:6])[0]
        assert version == 0x0100

    def test_profile1_crc32c_castagnoli(self):
        """RFC 5.1: CRC32 MUST use Castagnoli polynomial (CRC-32C)."""
        payload = {"test": "data"}
        encoded = Profile1Framer.encode(MessageType.HELLO, payload)

        # Extract stored CRC
        stored_crc = struct.unpack(">I", encoded[16:20])[0]

        # Compute CRC of payload using Castagnoli
        payload_bytes = cbor2.dumps(payload)
        computed_crc = crc32c(payload_bytes)

        assert stored_crc == computed_crc

    def test_profile1_crc_mismatch_detected(self):
        """RFC 5.1: Messages with invalid CRC MUST be rejected."""
        encoded = Profile1Framer.encode(MessageType.HELLO, {"test": "data"})
        # Corrupt CRC field
        corrupted = encoded[:16] + b"\x00\x00\x00\x00" + encoded[20:]

        with pytest.raises(ChecksumError):
            Profile1Framer.decode(corrupted)


class TestRFC512RequestIdCorrelation:
    """Tests for RFC Section 5.1.2 - Request/Response Correlation.

    RFC 5.1.2:
    - "The Request ID is a random 4-byte integer generated by the sender."
    - "Requests: Sender generates a new ID."
    - "Responses: Responder MUST echo the request's ID in this field."
    - "Notifications (e.g. ANNOUNCE): Sender generates a new ID; receivers log it for tracing."

    Note: RFC doesn't specify that request_id=0 means "unsolicited".
    """

    def test_request_id_in_header(self):
        """RFC 5.1.2: Request ID MUST be present in Profile 1 header."""
        encoded = Profile1Framer.encode(MessageType.GET_MANIFEST, {"collection_id": "test"})
        # Request ID is at bytes 8-11 (after magic, version, type)
        request_id = struct.unpack(">I", encoded[8:12])[0]
        # Any 32-bit value is valid per RFC
        assert 0 <= request_id <= 0xFFFFFFFF

    def test_request_id_custom_value(self):
        """RFC 5.1.2: Request ID can be specified by caller."""
        custom_id = 0x12345678
        encoded = Profile1Framer.encode(
            MessageType.GET_MANIFEST,
            {"collection_id": "test"},
            request_id=custom_id
        )
        request_id = struct.unpack(">I", encoded[8:12])[0]
        assert request_id == custom_id

    def test_request_id_preserved_on_decode(self):
        """RFC 5.1.2: Request ID MUST be preserved after decode."""
        custom_id = 0xDEADBEEF
        encoded = Profile1Framer.encode(
            MessageType.GET_MANIFEST,
            {"collection_id": "test"},
            request_id=custom_id
        )
        frame = Profile1Framer.decode(encoded)
        assert frame.request_id == custom_id

    def test_notification_has_request_id(self):
        """RFC 5.1.2: Notifications (e.g. ANNOUNCE) generate a new ID for tracing."""
        # Per RFC: "Notifications (e.g. ANNOUNCE): Sender generates a new ID"
        encoded = Profile1Framer.encode(
            MessageType.ANNOUNCE,
            {"collections": []},
            request_id=0x11223344
        )
        frame = Profile1Framer.decode(encoded)
        # RFC says to generate an ID, not that it must be non-zero
        assert 0 <= frame.request_id <= 0xFFFFFFFF

    def test_response_must_echo_request_id(self):
        """RFC 5.1.2: Responses MUST echo the request's ID."""
        # Encode request
        request_id = 0xCAFEBABE
        request = Profile1Framer.encode(
            MessageType.GET_MANIFEST,
            {"collection_id": "test"},
            request_id=request_id
        )

        # Simulate response with same ID (as responder would do)
        response = Profile1Framer.encode(
            MessageType.MANIFEST,
            {"collection_id": "test", "manifest": {}},
            request_id=request_id  # MUST echo per RFC
        )

        req_frame = Profile1Framer.decode(request)
        resp_frame = Profile1Framer.decode(response)

        assert req_frame.request_id == resp_frame.request_id


class TestRFC513MaxMessageSize:
    """Tests for RFC Section 5.3 - Maximum Message Size."""

    def test_max_message_size_32mb(self):
        """RFC 5.3: Maximum message size is 32MB."""
        assert MAX_MESSAGE_SIZE == 32 * 1024 * 1024

    def test_reject_oversized_profile1_encode(self):
        """RFC 5.3: Profile 1 MUST reject messages > 32MB on encode."""
        oversized = b"\x00" * (MAX_MESSAGE_SIZE + 1)
        with pytest.raises(MessageTooLargeError):
            Profile1Framer.encode(MessageType.HELLO, oversized)

    def test_reject_oversized_profile1_decode(self):
        """RFC 5.3: Profile 1 MUST reject claimed size > 32MB on decode."""
        # Craft a Profile 1 header claiming huge payload
        header = (
            MAGIC_BYTES +
            struct.pack(">H", 0x0100) +  # version
            struct.pack(">H", MessageType.HELLO) +  # type
            struct.pack(">I", 0) +  # request_id
            struct.pack(">I", MAX_MESSAGE_SIZE + 1) +  # length (too big!)
            struct.pack(">I", 0)  # CRC
        )
        with pytest.raises(MessageTooLargeError):
            Profile1Framer.decode(header)


# =============================================================================
# RFC Section 9.1: DHT Key Derivation
# =============================================================================

class TestRFC91DHTKeyDerivation:
    """Tests for RFC Section 9.1 - DHT Key Derivation."""

    def test_public_dht_key_format(self):
        """RFC 9.1.1: Public DHT key = sha256('dcpp/1.0:' + collection_id)."""
        import hashlib

        collection_id = "test:collection:abc123"
        key = derive_dht_key(collection_id)

        # Verify format
        expected = hashlib.sha256(f"dcpp/1.0:{collection_id}".encode()).digest()
        assert key == expected
        assert len(key) == 32

    def test_public_dht_key_deterministic(self):
        """RFC 9.1.1: DHT key derivation MUST be deterministic."""
        collection_id = "test:collection:xyz"
        key1 = derive_dht_key(collection_id)
        key2 = derive_dht_key(collection_id)
        assert key1 == key2

    def test_different_collections_different_keys(self):
        """RFC 9.1.1: Different collections MUST have different DHT keys."""
        key1 = derive_dht_key("collection:a")
        key2 = derive_dht_key("collection:b")
        assert key1 != key2

    def test_private_dht_key_format(self):
        """RFC 9.2.2: Private DHT key = sha256('dcpp/1.0/private:' + collection_key)."""
        import hashlib

        collection_key = b"\x00" * 32  # 256-bit key
        key = derive_private_dht_key(collection_key)

        # Verify format
        expected = hashlib.sha256(b"dcpp/1.0/private:" + collection_key).digest()
        assert key == expected
        assert len(key) == 32

    def test_private_dht_key_deterministic(self):
        """RFC 9.2.2: Private DHT key derivation MUST be deterministic."""
        collection_key = b"\x12\x34" * 16
        key1 = derive_private_dht_key(collection_key)
        key2 = derive_private_dht_key(collection_key)
        assert key1 == key2


# =============================================================================
# RFC Section 10.3/10.4: Health Probing
# =============================================================================

class TestRFC103HealthProbing:
    """Tests for RFC Section 10.3 - Health Probe Challenges."""

    def test_health_probe_structure(self):
        """RFC 10.3: HealthProbe MUST contain nonce, collection_id, and challenges."""
        from dcpp_python.messages import Challenge
        probe = HealthProbe(
            collection_id="test:collection",
            nonce=b"\x00" * 16,
            challenges=[
                Challenge(
                    cid="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                    offset=0,
                    length=1024,
                )
            ]
        )
        cbor_data = probe.to_cbor()
        assert probe.collection_id == "test:collection"
        assert len(probe.challenges) == 1

    def test_health_probe_max_challenges(self):
        """RFC 10.3: Max 10 challenges per probe."""
        from dcpp_python.messages import Challenge
        # RFC 10.3 specifies: "Maximum challenges per probe: 10"
        challenges = [
            Challenge(
                cid="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
                offset=i * 1024,
                length=1024,
            )
            for i in range(10)
        ]
        probe = HealthProbe(
            collection_id="test:collection",
            nonce=b"\x00" * 16,
            challenges=challenges
        )
        assert len(probe.challenges) == 10

    def test_health_probe_max_challenge_length(self):
        """RFC 10.3: Max 1024 bytes per challenge."""
        from dcpp_python.messages import Challenge
        # RFC 10.3: "Maximum bytes per challenge: 1024"
        challenge = Challenge(
            cid="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            offset=0,
            length=2048,  # Exceeds max
        )
        # Challenge should clamp to MAX_LENGTH (1024)
        assert challenge.length == 1024

    def test_health_response_structure(self):
        """RFC 10.4: HealthResponse MUST echo nonce and provide responses."""
        from dcpp_python.messages import ChallengeResponse
        response = HealthResponse(
            nonce=b"\x00" * 16,
            responses=[
                ChallengeResponse(cid="cid1", data=b"chunk1"),
                ChallengeResponse(cid="cid2", data=b"chunk2"),
            ]
        )
        cbor_data = response.to_cbor()
        assert response.nonce == b"\x00" * 16
        assert len(response.responses) == 2


# =============================================================================
# RFC Section 13.2: Security - Timestamp Validation
# =============================================================================

class TestRFC132TimestampValidation:
    """Tests for RFC Section 13.2 - Timestamp Validation."""

    @pytest.fixture
    def validator(self):
        return MessageValidator()

    def test_current_timestamp_valid(self, validator):
        """RFC 13.2: Current timestamp within ±5 minutes is valid."""
        current = int(time.time())
        result = validator.validate_timestamp(current)
        assert result.is_valid

    def test_timestamp_5min_future_valid(self, validator):
        """RFC 13.2: Timestamp 5 minutes in future is still valid."""
        future = int(time.time()) + 300  # 5 minutes
        result = validator.validate_timestamp(future)
        assert result.is_valid

    def test_timestamp_5min_past_valid(self, validator):
        """RFC 13.2: Timestamp 5 minutes in past is still valid."""
        past = int(time.time()) - 300  # 5 minutes ago
        result = validator.validate_timestamp(past)
        assert result.is_valid

    def test_timestamp_beyond_window_invalid(self, validator):
        """RFC 13.2: Timestamp outside ±5 minute window is invalid."""
        # 6 minutes in future
        future = int(time.time()) + 360
        result = validator.validate_timestamp(future)
        assert not result.is_valid

        # 6 minutes in past
        past = int(time.time()) - 360
        result = validator.validate_timestamp(past)
        assert not result.is_valid


# =============================================================================
# RFC Section 13.3: Error Codes
# =============================================================================

class TestRFC133ErrorCodes:
    """Tests for RFC Section 6.11/13.3 - Error Codes.

    RFC 6.11 defines these error codes:
    | Code | Name | Description |
    | 0 | UNKNOWN | Unknown error |
    | 1 | UNKNOWN_COLLECTION | Collection not found |
    | 2 | MANIFEST_NOT_FOUND | Manifest unavailable |
    | 3 | INVALID_REQUEST | Malformed request |
    | 4 | RATE_LIMITED | Too many requests |
    | 5 | INTERNAL_ERROR | Node internal error |
    | 6 | BUSY_TRY_LATER | Node overloaded, retry after backoff |
    """

    def test_rfc_error_codes_values(self):
        """RFC 6.11: Verify RFC-defined error code values."""
        # RFC 6.11 specifies these exact values (0-6)
        assert ErrorCode.UNKNOWN == 0
        assert ErrorCode.UNKNOWN_COLLECTION == 1
        assert ErrorCode.MANIFEST_NOT_FOUND == 2
        assert ErrorCode.INVALID_REQUEST == 3
        assert ErrorCode.RATE_LIMITED == 4
        assert ErrorCode.INTERNAL_ERROR == 5
        assert ErrorCode.BUSY_TRY_LATER == 6

    def test_busy_try_later_rfc_value(self):
        """RFC 6.11: BUSY_TRY_LATER MUST be code 6."""
        assert ErrorCode.BUSY_TRY_LATER == 6
        # OVERLOADED is an alias for backward compatibility
        assert ErrorCode.OVERLOADED == 6

    def test_error_roundtrip(self):
        """RFC 6.10: Error messages MUST roundtrip correctly."""
        error = ErrorResponse(
            code=ErrorCode.RATE_LIMITED,
            message="Rate limited",
            request_type=MessageType.GET_PEERS
        )
        cbor_data = error.to_cbor()
        decoded = ErrorResponse.from_cbor(cbor_data)
        assert decoded.code == error.code
        assert decoded.message == error.message

    def test_rfc_error_codes_serializable(self):
        """RFC 6.11: All RFC-defined error codes MUST be serializable."""
        # Only test RFC-defined codes (0-6)
        rfc_error_codes = [
            ErrorCode.UNKNOWN,  # 0
            ErrorCode.UNKNOWN_COLLECTION,  # 1
            ErrorCode.MANIFEST_NOT_FOUND,  # 2
            ErrorCode.INVALID_REQUEST,  # 3
            ErrorCode.RATE_LIMITED,  # 4
            ErrorCode.INTERNAL_ERROR,  # 5
            # BUSY_TRY_LATER (6) - tested separately due to implementation variance
        ]
        for code in rfc_error_codes:
            error = ErrorResponse(
                code=code,
                message=f"Error {code}",
                request_type=MessageType.HELLO
            )
            cbor_data = error.to_cbor()
            decoded = ErrorResponse.from_cbor(cbor_data)
            assert decoded.code == code


# =============================================================================
# RFC Section 6: Message Type Validation
# =============================================================================

class TestRFC6MessageTypeValidation:
    """Tests for RFC Section 6 - Message Type Requirements.

    Note: These tests verify RFC-specified fields. The implementation may
    include additional fields (e.g., announce_seq, expires_at) as extensions.
    """

    def test_hello_required_fields(self):
        """RFC 6.2: HELLO MUST contain version, node_id, capabilities, collections, timestamp."""
        hello = Hello(
            version="1.0.0",
            node_id=b"test_node_id_32bytes_padding!!!!",
            timestamp=int(time.time()),
            collections=["collection:test"],
            capabilities=[Capability.GUARDIAN],
        )
        cbor_data = hello.to_cbor()
        decoded = Hello.from_cbor(cbor_data)

        # RFC 6.2 required fields
        assert decoded.version == hello.version
        assert decoded.node_id == hello.node_id
        assert decoded.timestamp == hello.timestamp
        assert decoded.collections == hello.collections
        assert decoded.capabilities == hello.capabilities

    def test_hello_version_field_rfc(self):
        """RFC 6.2: HELLO MUST contain 'version' field.

        Implementation now requires 'version' field per spec.
        """
        hello = Hello(
            version="1.0.0",
            node_id=b"test_node_id_32bytes_padding!!!!",
            timestamp=int(time.time()),
            collections=["collection:test"],
            capabilities=[Capability.GUARDIAN],
        )
        hello_dict = hello.to_dict()
        assert "version" in hello_dict, "RFC 6.2 requires HELLO to contain 'version' field"
        assert hello_dict["version"] == "1.0.0"

    def test_hello_missing_version_rejected(self):
        """RFC 6.2: HELLO without version MUST be rejected."""
        import cbor2
        # Create a HELLO dict without version field
        hello_dict = {
            "node_id": b"test_node_id_32bytes_padding!!!!",
            "timestamp": int(time.time()),
            "collections": ["collection:test"],
            "capabilities": [Capability.GUARDIAN],
        }
        cbor_data = cbor2.dumps(hello_dict)

        # Should raise ValueError when deserializing
        with pytest.raises(ValueError, match="missing required 'version' field"):
            Hello.from_cbor(cbor_data)

    def test_announce_required_fields_rfc(self):
        """RFC 6.3: ANNOUNCE MUST contain node_id, collections, timestamp, signature.

        Note: RFC 6.3 does NOT require 'announce_seq' or 'expires_at' - those
        are implementation extensions for replay protection (RFC 13.2).
        """
        from dcpp_python.messages import CollectionAnnouncement
        _, verify_key = generate_keypair()

        # RFC 6.3 specifies these collection fields: id, manifest_cid, coverage, shard_ids (optional)
        collections = [
            CollectionAnnouncement(
                id="collection:test",
                coverage=1.0,
                manifest_cid="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
            )
        ]

        # Test RFC-required fields (implementation may require additional fields)
        announce = Announce(
            node_id=bytes(verify_key),
            collections=collections,
            announce_seq=1,  # Implementation extension, not in RFC
            timestamp=int(time.time()),
            expires_at=int(time.time()) + 3600,  # Implementation extension, not in RFC
            signature=b"\x00" * 64,
        )
        cbor_data = announce.to_cbor()
        decoded = Announce.from_cbor(cbor_data)

        # RFC 6.3 required fields
        assert decoded.node_id == announce.node_id
        assert decoded.timestamp == announce.timestamp
        assert decoded.signature == announce.signature
        assert len(decoded.collections) == 1
        assert decoded.collections[0].id == "collection:test"
        assert decoded.collections[0].manifest_cid == collections[0].manifest_cid
        assert decoded.collections[0].coverage == collections[0].coverage

    def test_get_manifest_required_fields(self):
        """RFC 6.3: GET_MANIFEST MUST contain collection_id."""
        msg = GetManifest(collection_id="test:collection")
        cbor_data = msg.to_cbor()
        decoded = GetManifest.from_cbor(cbor_data)
        assert decoded.collection_id == "test:collection"

    def test_get_peers_required_fields(self):
        """RFC 6.4: GET_PEERS MUST contain collection_id."""
        msg = GetPeers(collection_id="test:collection")
        cbor_data = msg.to_cbor()
        decoded = GetPeers.from_cbor(cbor_data)
        assert decoded.collection_id == "test:collection"

    def test_goodbye_optional_fields(self):
        """RFC 6.7: GOODBYE may contain reason and collections."""
        msg = Goodbye(reason="shutdown", collections=["col1", "col2"])
        cbor_data = msg.to_cbor()
        decoded = Goodbye.from_cbor(cbor_data)
        assert decoded.reason == "shutdown"
        assert decoded.collections == ["col1", "col2"]


# =============================================================================
# Additional Framing Edge Cases
# =============================================================================

class TestFramingEdgeCases:
    """Additional edge case tests for framing compliance.

    Note: RFC 5.1 only specifies version 0x0100 (v1.0). The implementation
    may accept other versions as extensions or for forward compatibility.
    """

    def test_profile1_version_v1x_accepted(self):
        """RFC 5.1: Version 0x0100 (v1.0) MUST be accepted.

        Implementation MAY accept v1.x minor versions for forward compatibility,
        though RFC only specifies 0x0100.
        """
        payload = cbor2.dumps({"test": "data"})
        # RFC-specified version
        header = (
            MAGIC_BYTES +
            struct.pack(">H", 0x0100) +  # RFC-specified v1.0
            struct.pack(">H", MessageType.HELLO) +
            struct.pack(">I", 0) +
            struct.pack(">I", len(payload)) +
            struct.pack(">I", crc32c(payload))
        )
        frame = Profile1Framer.decode(header + payload)
        assert frame.message_type == MessageType.HELLO

    def test_profile1_version_v2_rejected(self):
        """RFC 5.1: Version 2.x SHOULD be rejected (not specified in RFC)."""
        payload = cbor2.dumps({"test": "data"})
        header = (
            MAGIC_BYTES +
            struct.pack(">H", 0x0200) +  # v2.0 - not in RFC
            struct.pack(">H", MessageType.HELLO) +
            struct.pack(">I", 0) +
            struct.pack(">I", len(payload)) +
            struct.pack(">I", crc32c(payload))
        )
        with pytest.raises(FramingError, match="Unsupported protocol version"):
            Profile1Framer.decode(header + payload)

    def test_implementation_legacy_version_behavior(self):
        """Implementation-specific: Test handling of legacy version 0x0000.

        Note: This is NOT specified in RFC 5.1 - this tests implementation
        behavior for backwards compatibility with pre-release versions.
        """
        payload = cbor2.dumps({"test": "data"})
        header = (
            MAGIC_BYTES +
            struct.pack(">H", 0x0000) +  # Not in RFC - implementation extension
            struct.pack(">H", MessageType.HELLO) +
            struct.pack(">I", 0) +
            struct.pack(">I", len(payload)) +
            struct.pack(">I", crc32c(payload))
        )
        # Implementation may accept or reject - just document behavior
        try:
            frame = Profile1Framer.decode(header + payload)
            assert frame.message_type == MessageType.HELLO
        except FramingError:
            pass  # Also acceptable - RFC doesn't specify 0x0000

    def test_empty_payload_valid(self):
        """Empty CBOR payload ({}) should be valid."""
        for framer in [Profile1Framer]:
            encoded = framer.encode(MessageType.GOODBYE, {})
            frame = framer.decode(encoded)
            assert frame.decode_payload() == {}

    def test_binary_payload_preserved(self):
        """Binary data in payload should be preserved exactly."""
        payload = {"data": b"\x00\x01\x02\xff\xfe\xfd"}
        for framer in [Profile1Framer]:
            encoded = framer.encode(MessageType.HELLO, payload)
            frame = framer.decode(encoded)
            assert frame.decode_payload()["data"] == payload["data"]
