"""Tests for DCPP message validation."""

import time

import pytest

from dcpp_python.validation import (
    MessageValidator,
    ValidationResult,
    ValidationStatus,
    PendingRequest,
    filter_capabilities,
    is_known_capability,
    parse_capabilities,
)
from dcpp_python.core.constants import Capability, CLOCK_SKEW_TOLERANCE_SECONDS


class TestTimestampValidation:
    """Test timestamp validation for clock skew."""

    def test_valid_current_timestamp(self):
        """Current timestamp should be valid."""
        validator = MessageValidator()
        now = validator.current_timestamp()
        result = validator.validate_timestamp(now)
        assert result.is_valid
        assert result.status == ValidationStatus.VALID

    def test_valid_within_tolerance(self):
        """Timestamps within 5-minute window should be valid."""
        validator = MessageValidator()
        now = validator.current_timestamp()

        # 1 minute in future
        result = validator.validate_timestamp(now + 60)
        assert result.is_valid

        # 1 minute in past
        result = validator.validate_timestamp(now - 60)
        assert result.is_valid

        # Just under 5 minutes
        result = validator.validate_timestamp(now + 299)
        assert result.is_valid

        result = validator.validate_timestamp(now - 299)
        assert result.is_valid

    def test_invalid_outside_tolerance(self):
        """Timestamps outside 5-minute window should be invalid."""
        validator = MessageValidator()
        now = validator.current_timestamp()

        # 6 minutes in future
        result = validator.validate_timestamp(now + 400)
        assert not result.is_valid
        assert result.status == ValidationStatus.INVALID_TIMESTAMP

        # 6 minutes in past
        result = validator.validate_timestamp(now - 400)
        assert not result.is_valid

    def test_validation_result_details(self):
        """Validation result should include details."""
        validator = MessageValidator()
        now = validator.current_timestamp()

        result = validator.validate_timestamp(now + 600)
        assert not result.is_valid
        assert "message_timestamp" in result.details
        assert "local_timestamp" in result.details
        assert "skew_seconds" in result.details


class TestAnnounceValidation:
    """Test ANNOUNCE message replay protection."""

    def test_valid_first_announce(self):
        """First ANNOUNCE from a node should be valid."""
        validator = MessageValidator()
        node_id = b"test_node_12345678"
        now = validator.current_timestamp()
        expires = now + 3600

        result = validator.validate_announce(node_id, now, expires, 100)
        assert result.is_valid

    def test_valid_increasing_seq(self):
        """ANNOUNCE with increasing seq should be valid."""
        validator = MessageValidator()
        node_id = b"test_node"
        now = validator.current_timestamp()
        expires = now + 3600

        result = validator.validate_announce(node_id, now, expires, 100)
        assert result.is_valid

        result = validator.validate_announce(node_id, now, expires, 101)
        assert result.is_valid

        result = validator.validate_announce(node_id, now, expires, 200)
        assert result.is_valid

    def test_replay_same_seq(self):
        """ANNOUNCE with same seq should be detected as replay."""
        validator = MessageValidator()
        node_id = b"test_node"
        now = validator.current_timestamp()
        expires = now + 3600

        result = validator.validate_announce(node_id, now, expires, 100)
        assert result.is_valid

        result = validator.validate_announce(node_id, now, expires, 100)
        assert not result.is_valid
        assert result.status == ValidationStatus.REPLAY_DETECTED

    def test_replay_lower_seq(self):
        """ANNOUNCE with lower seq should be detected as replay."""
        validator = MessageValidator()
        node_id = b"test_node"
        now = validator.current_timestamp()
        expires = now + 3600

        result = validator.validate_announce(node_id, now, expires, 100)
        assert result.is_valid

        result = validator.validate_announce(node_id, now, expires, 50)
        assert not result.is_valid
        assert result.status == ValidationStatus.REPLAY_DETECTED

    def test_expired_announce(self):
        """Expired ANNOUNCE should be rejected."""
        validator = MessageValidator()
        node_id = b"test_node"
        now = validator.current_timestamp()
        expires = now - 1  # Already expired

        result = validator.validate_announce(node_id, now, expires, 100)
        assert not result.is_valid
        assert result.status == ValidationStatus.EXPIRED

    def test_invalid_timestamp_announce(self):
        """ANNOUNCE with bad timestamp should be rejected."""
        validator = MessageValidator()
        node_id = b"test_node"
        now = validator.current_timestamp()
        old_timestamp = now - 600  # 10 minutes ago
        expires = now + 3600

        result = validator.validate_announce(node_id, old_timestamp, expires, 100)
        assert not result.is_valid
        assert result.status == ValidationStatus.INVALID_TIMESTAMP

    def test_different_nodes_independent(self):
        """Different nodes should have independent seq tracking."""
        validator = MessageValidator()
        node1 = b"node_one"
        node2 = b"node_two"
        now = validator.current_timestamp()
        expires = now + 3600

        # Node 1 at seq 100
        result = validator.validate_announce(node1, now, expires, 100)
        assert result.is_valid

        # Node 2 can also use seq 100
        result = validator.validate_announce(node2, now, expires, 100)
        assert result.is_valid

        # Node 1 replay detected
        result = validator.validate_announce(node1, now, expires, 100)
        assert not result.is_valid


class TestRequestIdCorrelation:
    """Test request ID generation and correlation."""

    def test_generate_request_id(self):
        """Should generate unique request IDs."""
        validator = MessageValidator()

        ids = [validator.next_request_id() for _ in range(100)]
        assert len(set(ids)) == 100  # All unique

    def test_request_id_nonzero(self):
        """Request IDs should not be zero."""
        validator = MessageValidator()

        for _ in range(1000):
            rid = validator.next_request_id()
            assert rid != 0 or validator._next_request_id == 1

    def test_register_and_correlate(self):
        """Should be able to register and correlate requests."""
        validator = MessageValidator()

        rid1 = validator.next_request_id()
        rid2 = validator.next_request_id()

        validator.register_request(rid1, 0x0003, "get_manifest for collection X")
        validator.register_request(rid2, 0x0005, "get_peers")

        assert validator.pending_request_count == 2

        # Correlate first request
        req = validator.correlate_response(rid1)
        assert req is not None
        assert req.message_type == 0x0003
        assert req.context == "get_manifest for collection X"

        assert validator.pending_request_count == 1

        # Correlate second request
        req = validator.correlate_response(rid2)
        assert req is not None
        assert req.message_type == 0x0005

        assert validator.pending_request_count == 0

    def test_correlate_unknown_id(self):
        """Unknown request ID should return None."""
        validator = MessageValidator()
        result = validator.correlate_response(999)
        assert result is None

    def test_cleanup_stale_requests(self):
        """Should clean up stale requests."""
        validator = MessageValidator()

        rid = validator.next_request_id()
        validator.register_request(rid, 0x0003, None)

        # Manually set sent_at to old time
        validator._pending_requests[rid].sent_at = time.time() - 120

        cleaned = validator.cleanup_stale_requests(timeout_seconds=60)
        assert cleaned == 1
        assert validator.pending_request_count == 0


class TestCapabilityFiltering:
    """Test capability forward compatibility."""

    def test_filter_known_capabilities(self):
        """Known capabilities should pass through."""
        caps = [
            Capability.GUARDIAN,
            Capability.SEEDER,
            Capability.PRIVATE,
        ]
        filtered = filter_capabilities(caps)
        assert len(filtered) == 3
        assert Capability.GUARDIAN in filtered
        assert Capability.SEEDER in filtered
        assert Capability.PRIVATE in filtered

    def test_filter_string_capabilities(self):
        """String capabilities should be converted."""
        caps = ["guardian", "seeder", "observer"]
        filtered = filter_capabilities(caps)
        assert len(filtered) == 3

    def test_filter_unknown_capabilities(self):
        """Unknown capabilities should be filtered out."""
        caps = ["guardian", "future-cap-v2", "seeder", "unknown-thing"]
        filtered = filter_capabilities(caps)
        assert len(filtered) == 2
        assert Capability.GUARDIAN in filtered
        assert Capability.SEEDER in filtered

    def test_is_known_capability_enum(self):
        """Capability enum values should be known."""
        assert is_known_capability(Capability.GUARDIAN)
        assert is_known_capability(Capability.SEEDER)
        assert is_known_capability(Capability.PRIVATE)

    def test_is_known_capability_string(self):
        """Valid capability strings should be known."""
        assert is_known_capability("guardian")
        assert is_known_capability("seeder")
        assert is_known_capability("private")

    def test_is_known_capability_unknown(self):
        """Unknown capability strings should return False."""
        assert not is_known_capability("future-capability")
        assert not is_known_capability("unknown")
        assert not is_known_capability("invalid")

    def test_parse_capabilities(self):
        """Should parse known capabilities from strings."""
        strings = ["guardian", "seeder", "future-v2", "private", "unknown"]
        parsed = parse_capabilities(strings)
        assert len(parsed) == 3
        assert Capability.GUARDIAN in parsed
        assert Capability.SEEDER in parsed
        assert Capability.PRIVATE in parsed


class TestValidationResultConversion:
    """Test ValidationResult to error code conversion."""

    def test_valid_no_error_code(self):
        """Valid result should have no error code."""
        result = ValidationResult.valid()
        assert result.to_error_code() is None

    def test_invalid_timestamp_error_code(self):
        """Invalid timestamp should map to PROTOCOL_ERROR."""
        from dcpp_python.core.constants import ErrorCode

        result = ValidationResult.invalid_timestamp(100, 1000, -900)
        assert result.to_error_code() == ErrorCode.PROTOCOL_ERROR

    def test_expired_error_code(self):
        """Expired message should map to INVALID_REQUEST."""
        from dcpp_python.core.constants import ErrorCode

        result = ValidationResult.expired(100, 200)
        assert result.to_error_code() == ErrorCode.INVALID_REQUEST

    def test_replay_error_code(self):
        """Replay detected should map to INVALID_REQUEST."""
        from dcpp_python.core.constants import ErrorCode

        result = ValidationResult.replay_detected(100, b"node")
        assert result.to_error_code() == ErrorCode.INVALID_REQUEST
