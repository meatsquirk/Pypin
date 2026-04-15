"""Helper functions and CRC defaults."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable

from .enums import (
    AccessMode,
    Capability,
    CollectionType,
    GoodbyeReason,
    ItemStatus,
    KeyRotationReason,
    MemberStatus,
    Permission,
    StorageType,
)
from .protocol import CLOCK_SKEW_TOLERANCE_SECONDS

CRC32C_POLYNOMIAL = 0x1EDC6F41  # Castagnoli
CRC32C_INIT = 0xFFFFFFFF
CRC32C_XOR_OUT = 0xFFFFFFFF


# =============================================================================
# Conformance Defaults (Section 15.1)
# =============================================================================

CONFORMANCE_DEFAULTS = {
    "quorum": 1,
    "clock_skew_tolerance_seconds": 300,
    "announce_expiry_seconds": 3600,
    "probe_interval_seconds": 86400,
    "max_connections": 200,
}


# =============================================================================
# Registry Fallback Helpers (Section 14.3)
# =============================================================================

_logger = logging.getLogger(__name__)


def goodbye_reason_fallback(reason: str) -> GoodbyeReason:
    """Handle unknown GOODBYE reason - fallback to 'shutdown'."""
    try:
        return GoodbyeReason(reason)
    except ValueError:
        _logger.warning(f"Unknown GOODBYE reason '{reason}', treating as 'shutdown'")
        return GoodbyeReason.SHUTDOWN


def member_status_fallback(status: str) -> MemberStatus:
    """Handle unknown member status - fallback to 'offline'."""
    try:
        return MemberStatus(status)
    except ValueError:
        _logger.warning(f"Unknown member status '{status}', treating as 'offline'")
        return MemberStatus.OFFLINE


def permission_fallback(permission: str) -> Permission:
    """Handle unknown permission - fallback to 'member'."""
    try:
        return Permission(permission)
    except ValueError:
        _logger.warning(f"Unknown permission '{permission}', treating as 'member'")
        return Permission.MEMBER


def item_status_fallback(status: str) -> ItemStatus:
    """Handle unknown item status - fallback to 'unknown'."""
    try:
        return ItemStatus(status)
    except ValueError:
        _logger.warning(f"Unknown item status '{status}', treating as 'unknown'")
        return ItemStatus.UNKNOWN


def storage_type_for_retrieval(storage_type: str) -> StorageType:
    """Handle unknown storage type - treat as 'http' for retrieval behavior.

    Returns StorageType for retrieval behavior. Original value should be
    preserved in storage/retransmission.
    """
    try:
        return StorageType(storage_type)
    except ValueError:
        _logger.warning(f"Unknown storage type '{storage_type}', treating as 'http' for retrieval")
        return StorageType.HTTP


def collection_type_fallback(collection_type: str) -> CollectionType:
    """Handle unknown collection type - fallback to 'custom'.

    Original value should be preserved in storage/retransmission.
    """
    try:
        return CollectionType(collection_type)
    except ValueError:
        _logger.warning(f"Unknown collection type '{collection_type}', treating as 'custom'")
        return CollectionType.CUSTOM


def validate_access_mode(mode: str) -> AccessMode:
    """Validate access_mode - REJECT unknown values (security critical).

    Raises ValueError for unknown values.
    """
    try:
        return AccessMode(mode)
    except ValueError:
        raise ValueError(
            f"Unknown access_mode '{mode}' - MUST reject (security critical)"
        ) from None


def key_rotation_reason_fallback(reason: str) -> KeyRotationReason:
    """Handle unknown KEY_ROTATE reason - fallback to 'unspecified'.

    Original value should be preserved.
    """
    try:
        return KeyRotationReason(reason)
    except ValueError:
        _logger.warning(f"Unknown KEY_ROTATE reason '{reason}', treating as 'unspecified'")
        return KeyRotationReason.UNSPECIFIED


def filter_capabilities(capabilities: list[Capability | str]) -> list[Capability]:
    """Filter capabilities list, skipping unknown entries.

    Per RFC Section 14.3: Unknown capabilities MUST be ignored (skipped).
    Returns list of known Capability values.
    """
    known = []
    for cap in capabilities:
        try:
            if isinstance(cap, Capability):
                known.append(cap)
            else:
                known.append(Capability(cap))
        except ValueError:
            _logger.warning(f"Unknown capability '{cap}', skipping")
            # Skip unknown capabilities per RFC
    return known


def validate_timestamp(message_timestamp: int, local_timestamp: "int | None" = None) -> bool:
    """Validate message timestamp is within acceptable clock skew window.

    Per RFC Section 13.2: Messages with timestamps deviating more than
    5 minutes from local time MUST be rejected.

    Args:
        message_timestamp: Unix timestamp from the message (seconds)
        local_timestamp: Current local Unix timestamp (seconds). If None, uses time.time().

    Returns:
        True if timestamp is within acceptable range, False otherwise.
    """
    import time

    if local_timestamp is None:
        local_timestamp = int(time.time())

    skew = abs(message_timestamp - local_timestamp)
    return skew <= CLOCK_SKEW_TOLERANCE_SECONDS


def is_timestamp_too_old(message_timestamp: int, local_timestamp: "int | None" = None) -> bool:
    """Check if message timestamp is too old (potential replay attack).

    Args:
        message_timestamp: Unix timestamp from the message (seconds)
        local_timestamp: Current local Unix timestamp (seconds). If None, uses time.time().

    Returns:
        True if timestamp is too old, False otherwise.
    """
    import time

    if local_timestamp is None:
        local_timestamp = int(time.time())

    return message_timestamp < local_timestamp - CLOCK_SKEW_TOLERANCE_SECONDS


def is_timestamp_too_new(message_timestamp: int, local_timestamp: "int | None" = None) -> bool:
    """Check if message timestamp is too far in the future.

    Args:
        message_timestamp: Unix timestamp from the message (seconds)
        local_timestamp: Current local Unix timestamp (seconds). If None, uses time.time().

    Returns:
        True if timestamp is too far in the future, False otherwise.
    """
    import time

    if local_timestamp is None:
        local_timestamp = int(time.time())

    return message_timestamp > local_timestamp + CLOCK_SKEW_TOLERANCE_SECONDS
