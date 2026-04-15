"""
Message Validation Module

This module provides validation utilities for DCPP messages including:
- Clock skew validation (Section 13.2 - Replay Protection)
- Forward compatibility for unknown capabilities (Section 6.2)
- Request ID correlation tracking

Per RFC Section 13.2: Messages with timestamps deviating more than
5 minutes from local time MUST be rejected.

Per RFC Section 6.2: Unknown capabilities MUST be ignored (not rejected).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Protocol, TypedDict
from typing_extensions import NotRequired

from .constants import (
    CLOCK_SKEW_TOLERANCE_SECONDS,
    Capability,
    filter_capabilities as _filter_capabilities,
)
from .messages import CollectionAnnouncementPayload
from typing import cast
from dcpp_python.manifest.verify import ManifestVerificationPipeline
from dcpp_python.manifest.manifest import Manifest

_logger = logging.getLogger(__name__)


class ValidationStatus(Enum):
    """Validation result status."""

    VALID = auto()
    INVALID_TIMESTAMP = auto()
    EXPIRED = auto()
    REPLAY_DETECTED = auto()


def _empty_validation_details() -> "ValidationDetailsPayload":
    return {}


@dataclass
class ValidationResult:
    """Result of message validation."""

    status: ValidationStatus
    message: str = ""
    details: "ValidationDetailsPayload" = field(default_factory=_empty_validation_details)

    @property
    def is_valid(self) -> bool:
        """Check if validation passed."""
        return self.status == ValidationStatus.VALID

    def to_error_code(self) -> "int | None":
        """Convert to error code if validation failed."""
        from .constants import ErrorCode

        if self.status == ValidationStatus.VALID:
            return None
        if self.status == ValidationStatus.INVALID_TIMESTAMP:
            return ErrorCode.PROTOCOL_ERROR
        if self.status == ValidationStatus.EXPIRED:
            return ErrorCode.INVALID_REQUEST
        if self.status == ValidationStatus.REPLAY_DETECTED:
            return ErrorCode.INVALID_REQUEST
        return ErrorCode.INVALID_REQUEST

    def to_dict(self) -> "ValidationResultPayload":
        """Serialize validation result."""
        return {
            "status": self.status.name,
            "message": self.message,
            "details": self.details,
        }

    @classmethod
    def valid(cls) -> "ValidationResult":
        """Create a valid result."""
        return cls(status=ValidationStatus.VALID)

    @classmethod
    def invalid_timestamp(
        cls, message_timestamp: int, local_timestamp: int, skew_seconds: int
    ) -> "ValidationResult":
        """Create invalid timestamp result."""
        return cls(
            status=ValidationStatus.INVALID_TIMESTAMP,
            message=f"Timestamp skew {skew_seconds}s exceeds tolerance",
            details={
                "message_timestamp": message_timestamp,
                "local_timestamp": local_timestamp,
                "skew_seconds": skew_seconds,
            },
        )

    @classmethod
    def expired(cls, expires_at: int, current_time: int) -> "ValidationResult":
        """Create expired message result."""
        return cls(
            status=ValidationStatus.EXPIRED,
            message="Message has expired",
            details={"expires_at": expires_at, "current_time": current_time},
        )

    @classmethod
    def replay_detected(cls, announce_seq: int, node_id: bytes) -> "ValidationResult":
        """Create replay detection result."""
        return cls(
            status=ValidationStatus.REPLAY_DETECTED,
            message=f"Replay detected: announce_seq {announce_seq} already seen",
            details={"announce_seq": announce_seq, "node_id": node_id.hex()},
        )


class ValidationDetailsPayload(TypedDict):
    message_timestamp: NotRequired[int]
    local_timestamp: NotRequired[int]
    skew_seconds: NotRequired[int]
    expires_at: NotRequired[int]
    current_time: NotRequired[int]
    announce_seq: NotRequired[int]
    node_id: NotRequired[str]


class ValidationResultPayload(TypedDict):
    status: str
    message: str
    details: ValidationDetailsPayload


@dataclass
class PendingRequest:
    """A pending request awaiting response."""

    message_type: int
    sent_at: float
    context: "str | None" = None


class MessageValidator:
    """
    Message validator for DCPP protocol.

    Handles:
    - Timestamp validation (clock skew within 5 minutes)
    - ANNOUNCE replay detection (tracking announce_seq per node)
    - Request ID correlation
    """

    def __init__(self) -> None:
        # Track last announce_seq per node_id to detect replays
        # Key: node_id (hex), Value: last seen announce_seq
        self._announce_seq_tracker: dict[str, int] = {}

        # Track pending requests for correlation
        # Key: request_id, Value: PendingRequest
        self._pending_requests: dict[int, PendingRequest] = {}

        # Next request ID to assign
        self._next_request_id: int = 1

    @staticmethod
    def current_timestamp() -> int:
        """Get current Unix timestamp in seconds."""
        return int(time.time())

    def validate_timestamp(self, message_timestamp: int) -> ValidationResult:
        """
        Validate a message timestamp against local time.

        Per RFC Section 13.2: Messages with timestamps deviating more than
        5 minutes from local time MUST be rejected.
        """
        local_timestamp = self.current_timestamp()
        skew = message_timestamp - local_timestamp

        if abs(skew) > CLOCK_SKEW_TOLERANCE_SECONDS:
            return ValidationResult.invalid_timestamp(message_timestamp, local_timestamp, skew)

        return ValidationResult.valid()

    def validate_announce(
        self,
        node_id: bytes,
        timestamp: int,
        expires_at: int,
        announce_seq: int,
    ) -> ValidationResult:
        """
        Validate ANNOUNCE message for replay attacks.

        Checks:
        1. Timestamp is within clock skew tolerance
        2. Message hasn't expired (expires_at > now)
        3. announce_seq is greater than last seen for this node
        """
        # First check timestamp
        timestamp_result = self.validate_timestamp(timestamp)
        if not timestamp_result.is_valid:
            return timestamp_result

        # Check expiry
        now = self.current_timestamp()
        if expires_at <= now:
            return ValidationResult.expired(expires_at, now)

        # Check for replay (announce_seq must be strictly increasing)
        node_id_hex = node_id.hex()
        if node_id_hex in self._announce_seq_tracker:
            last_seq = self._announce_seq_tracker[node_id_hex]
            if announce_seq <= last_seq:
                return ValidationResult.replay_detected(announce_seq, node_id)

        # Update tracker
        self._announce_seq_tracker[node_id_hex] = announce_seq

        return ValidationResult.valid()

    def next_request_id(self) -> int:
        """Generate a new request ID for outgoing messages."""
        request_id = self._next_request_id
        self._next_request_id += 1
        # Skip 0 as it's often used as "no request ID"
        if self._next_request_id == 0:
            self._next_request_id = 1
        # Wrap at 32-bit boundary
        if self._next_request_id > 0xFFFFFFFF:
            self._next_request_id = 1
        return request_id

    def register_request(
        self, request_id: int, message_type: int, context: "str | None" = None
    ) -> None:
        """Register a pending request for correlation."""
        self._pending_requests[request_id] = PendingRequest(
            message_type=message_type,
            sent_at=time.time(),
            context=context,
        )

    def correlate_response(self, request_id: int) -> "PendingRequest | None":
        """
        Correlate a response with its original request.

        Returns the original request info if found, removing it from tracking.
        """
        return self._pending_requests.pop(request_id, None)

    def cleanup_stale_requests(self, timeout_seconds: float = 60.0) -> int:
        """
        Clean up old pending requests (older than timeout_seconds).

        Returns the number of requests cleaned up.
        """
        now = time.time()
        stale_ids = [
            rid
            for rid, req in self._pending_requests.items()
            if now - req.sent_at >= timeout_seconds
        ]
        for rid in stale_ids:
            del self._pending_requests[rid]
        return len(stale_ids)

    @property
    def pending_request_count(self) -> int:
        """Get count of pending requests."""
        return len(self._pending_requests)


def filter_capabilities(capabilities: list[Capability | str]) -> list[Capability]:
    """
    Process capabilities with forward compatibility.

    Per RFC Section 6.2: Unknown capabilities MUST be ignored (not rejected).
    This function filters out unknown capabilities and returns only known ones.

    Args:
        capabilities: List of capability strings or Capability enum values

    Returns:
        List of known Capability enum values
    """
    return _filter_capabilities(capabilities)


def is_known_capability(cap: "str | Capability") -> bool:
    """
    Check if a capability is known (not unknown).

    Args:
        cap: Capability string or enum value

    Returns:
        True if the capability is known, False otherwise
    """
    if isinstance(cap, Capability):
        return True
    try:
        Capability(cap)
        return True
    except ValueError:
        return False


def parse_capabilities(capability_strings: list[str]) -> list[Capability]:
    """
    Parse capabilities from strings with forward compatibility.

    Unknown capability strings are logged but not included in the result.
    Use this to parse incoming capability lists from peer messages.

    Args:
        capability_strings: List of capability strings

    Returns:
        List of known Capability enum values
    """
    result = []
    for s in capability_strings:
        try:
            result.append(Capability(s))
        except ValueError:
            _logger.debug(f"Ignoring unknown capability '{s}' for forward compatibility")
    return result


# =============================================================================
# Enhanced ANNOUNCE Handling (RFC Section 7.4, 7.5)
# =============================================================================


class AnnounceHandleStatus(Enum):
    """Status of ANNOUNCE handling result."""

    ACCEPTED = auto()  # ANNOUNCE accepted, collections valid
    REJECTED = auto()  # ANNOUNCE rejected (validation failed)
    PARTIALLY_ACCEPTED = auto()  # Some collections accepted, some rejected
    FETCH_NEEDED = auto()  # Unknown manifests need fetching


class CollectionVerificationPayload(TypedDict):
    collection_id: str
    manifest_cid: str
    accepted: bool
    needs_fetch: bool
    message: str
    is_conflict: bool


class AnnounceHandleResultPayload(TypedDict):
    status: str
    validation_result: ValidationResultPayload
    collection_results: list[CollectionVerificationPayload]
    collections_to_fetch: list[str]


@dataclass
class CollectionVerificationResult:
    """Verification result for a single collection in an ANNOUNCE."""

    collection_id: str
    manifest_cid: str
    accepted: bool
    needs_fetch: bool = False
    message: str = ""
    is_conflict: bool = False

    def to_dict(self) -> "CollectionVerificationPayload":
        """Serialize collection verification result."""
        return {
            "collection_id": self.collection_id,
            "manifest_cid": self.manifest_cid,
            "accepted": self.accepted,
            "needs_fetch": self.needs_fetch,
            "message": self.message,
            "is_conflict": self.is_conflict,
        }


@dataclass
class AnnounceHandleResult:
    """Result of handling an ANNOUNCE message."""

    status: AnnounceHandleStatus
    validation_result: ValidationResult
    collection_results: list[CollectionVerificationResult] = field(default_factory=list)
    collections_to_fetch: list[str] = field(default_factory=list)

    def to_dict(self) -> "AnnounceHandleResultPayload":
        """Serialize announce handling result."""
        return {
            "status": self.status.name,
            "validation_result": self.validation_result.to_dict(),
            "collection_results": [r.to_dict() for r in self.collection_results],
            "collections_to_fetch": list(self.collections_to_fetch),
        }

    @property
    def is_accepted(self) -> bool:
        """Check if ANNOUNCE was accepted."""
        return self.status in {
            AnnounceHandleStatus.ACCEPTED,
            AnnounceHandleStatus.PARTIALLY_ACCEPTED,
            AnnounceHandleStatus.FETCH_NEEDED,
        }

    @property
    def rejected_collections(self) -> list[str]:
        """Get list of rejected collection IDs."""
        return [
            r.collection_id for r in self.collection_results if not r.accepted and not r.needs_fetch
        ]

    @property
    def conflicted_collections(self) -> list[str]:
        """Get list of collections with TOFU conflicts."""
        return [r.collection_id for r in self.collection_results if r.is_conflict]


class EnhancedAnnounceHandler:
    """
    Enhanced ANNOUNCE handler with UCI-based verification.

    Implements RFC Section 7.4: ANNOUNCE handling with manifest verification
    using scheme-specific verifiers.
    """

    def __init__(
        self,
        validator: MessageValidator,
        verification_pipeline: "ManifestVerificationPipeline | None" = None,
        manifest_cache: "dict[str, Manifest] | None" = None,
    ):
        """
        Initialize the enhanced ANNOUNCE handler.

        Args:
            validator: Message validator for basic validation
            verification_pipeline: ManifestVerificationPipeline instance
            manifest_cache: Optional cache for known manifests (cid -> manifest)
        """
        self.validator = validator
        self.verification_pipeline = verification_pipeline
        self.manifest_cache: dict[str, Manifest] = manifest_cache or {}

    async def handle_announce(
        self,
        node_id: bytes,
        timestamp: int,
        expires_at: int,
        announce_seq: int,
        collections: list[CollectionAnnouncementPayload],
    ) -> AnnounceHandleResult:
        """
        Handle an incoming ANNOUNCE message with verification.

        Args:
            node_id: Node ID of the announcing peer
            timestamp: Message timestamp
            expires_at: Message expiry timestamp
            announce_seq: Sequence number for replay detection
            collections: List of collection announcements (id, manifest_cid, coverage, shard_ids)

        Returns:
            AnnounceHandleResult with verification status for each collection
        """
        # Step 1: Basic validation (timestamp, expiry, replay)
        validation_result = self.validator.validate_announce(
            node_id, timestamp, expires_at, announce_seq
        )

        if not validation_result.is_valid:
            return AnnounceHandleResult(
                status=AnnounceHandleStatus.REJECTED,
                validation_result=validation_result,
            )

        # Step 2: Process each collection
        collection_results: list[CollectionVerificationResult] = []
        collections_to_fetch: list[str] = []
        any_accepted = False
        any_rejected = False
        allowed_bt_status = {"none", "leeching", "seeding", "paused", "error"}

        for coll in collections:
            collection_id = coll["id"]
            manifest_cid = coll["manifest_cid"]
            bt_status = coll.get("bt_status")

            if bt_status is not None and bt_status not in allowed_bt_status:
                collection_results.append(
                    CollectionVerificationResult(
                        collection_id=collection_id,
                        manifest_cid=manifest_cid,
                        accepted=False,
                        message=f"Invalid bt_status '{bt_status}'",
                    )
                )
                any_rejected = True
                continue

            # Check if we have the manifest in cache
            manifest = self.manifest_cache.get(manifest_cid)

            if manifest is None:
                # Unknown manifest - need to fetch
                collection_results.append(
                    CollectionVerificationResult(
                        collection_id=collection_id,
                        manifest_cid=manifest_cid,
                        accepted=False,
                        needs_fetch=True,
                        message="Manifest not in cache, fetch needed",
                    )
                )
                collections_to_fetch.append(collection_id)
                continue

            # Verify against UCI scheme
            if self.verification_pipeline is not None:
                try:
                    result = await self.verification_pipeline.verify(
                        collection_id=collection_id,
                        manifest=manifest,
                        manifest_cid=manifest_cid,
                    )

                    if result.is_success:
                        collection_results.append(
                            CollectionVerificationResult(
                                collection_id=collection_id,
                                manifest_cid=manifest_cid,
                                accepted=True,
                                message=result.message,
                            )
                        )
                        any_accepted = True
                    elif result.is_skipped:
                        # Per RFC: skipped verification (unverifiable scheme) is non-fatal
                        # Accept with warning - chain/dns schemes may not have adapters configured
                        collection_results.append(
                            CollectionVerificationResult(
                                collection_id=collection_id,
                                manifest_cid=manifest_cid,
                                accepted=True,
                                message=f"Verification skipped: {result.message}",
                            )
                        )
                        any_accepted = True
                        _logger.warning(
                            f"Verification skipped for {collection_id}: {result.message}"
                        )
                    elif result.is_conflict:
                        collection_results.append(
                            CollectionVerificationResult(
                                collection_id=collection_id,
                                manifest_cid=manifest_cid,
                                accepted=False,
                                is_conflict=True,
                                message=result.message,
                            )
                        )
                        any_rejected = True
                        _logger.warning(
                            f"TOFU conflict for {collection_id} from {node_id.hex()[:16]}"
                        )
                    else:
                        collection_results.append(
                            CollectionVerificationResult(
                                collection_id=collection_id,
                                manifest_cid=manifest_cid,
                                accepted=False,
                                message=result.message,
                            )
                        )
                        any_rejected = True
                except Exception as e:
                    _logger.error(f"Verification error for {collection_id}: {e}")
                    collection_results.append(
                        CollectionVerificationResult(
                            collection_id=collection_id,
                            manifest_cid=manifest_cid,
                            accepted=False,
                            message=f"Verification error: {e}",
                        )
                    )
                    any_rejected = True
            else:
                # No verification pipeline - accept all with cached manifests
                collection_results.append(
                    CollectionVerificationResult(
                        collection_id=collection_id,
                        manifest_cid=manifest_cid,
                        accepted=True,
                        message="Manifest in cache, verification skipped",
                    )
                )
                any_accepted = True

        # Determine overall status
        if collections_to_fetch:
            status = AnnounceHandleStatus.FETCH_NEEDED
        elif any_accepted and any_rejected:
            status = AnnounceHandleStatus.PARTIALLY_ACCEPTED
        elif any_accepted:
            status = AnnounceHandleStatus.ACCEPTED
        else:
            status = AnnounceHandleStatus.REJECTED

        return AnnounceHandleResult(
            status=status,
            validation_result=validation_result,
            collection_results=collection_results,
            collections_to_fetch=collections_to_fetch,
        )
