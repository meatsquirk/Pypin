"""Protocol enums."""

from __future__ import annotations

from enum import Enum, IntEnum
import sys

# Python 3.11+ has StrEnum, provide compatibility for older versions
if sys.version_info >= (3, 11):
    from enum import StrEnum
else:

    class StrEnum(str, Enum):
        """String enum for Python < 3.11 compatibility."""

        pass

class MessageType(IntEnum):
    """DCPP Message Type Codes (Section 6.1)"""

    # Core Messages (6.1.1)
    HELLO = 0x0001
    ANNOUNCE = 0x0002
    GET_MANIFEST = 0x0003
    MANIFEST = 0x0004
    GET_PEERS = 0x0005
    PEERS = 0x0006
    HEALTH_PROBE = 0x0007
    HEALTH_RESPONSE = 0x0008
    GOODBYE = 0x0009
    ERROR = 0x00FF

    # Membership Messages (6.1.2) - Private Collections
    INVITE = 0x0010
    JOIN = 0x0011
    JOIN_ACK = 0x0012
    LEAVE = 0x0013
    REVOKE = 0x0014
    GET_MEMBERS = 0x0015
    MEMBERS = 0x0016
    KEY_ROTATE = 0x0017


class ErrorCode(IntEnum):
    """DCPP Error Codes (Section 6.11, 14.5)

    Unknown codes MUST be preserved; display as "UNKNOWN (N)"

    Core error codes (RFC Section 6.11): 0-6
    Extended protocol error codes: 10-15
    Membership error codes (private collections): 16-19
    UCI/Verification error codes: 0x0100-0x0114
    """

    # Core error codes (RFC Section 6.11)
    UNKNOWN = 0
    UNKNOWN_COLLECTION = 1
    MANIFEST_NOT_FOUND = 2
    INVALID_REQUEST = 3
    RATE_LIMITED = 4
    INTERNAL_ERROR = 5
    BUSY_TRY_LATER = 6  # Node overloaded, retry after backoff (RFC Section 6.11)

    # Extended protocol error codes
    PROTOCOL_ERROR = 10
    INVALID_IDENTITY = 11
    MESSAGE_TOO_LARGE = 12
    INVALID_OFFSET = 13
    INVALID_SIGNATURE = 14

    # Membership error codes (private collections extension)
    INVALID_INVITE = 16
    NOT_AUTHORIZED = 17
    ALREADY_MEMBER = 18
    NOT_MEMBER = 19

    # UCI and Verification Error Codes (Section 4.3, 7.4, 7.5)
    INVALID_UCI = 0x0100  # Malformed UCI string
    UNKNOWN_UCI_SCHEME = 0x0101  # Unrecognized scheme
    VERIFICATION_FAILED = 0x0110  # Scheme verification failed
    SIGNATURE_REQUIRED = 0x0111  # key: scheme needs signature
    HASH_MISMATCH = 0x0112  # hash: merkle_root mismatch
    TOFU_CONFLICT = 0x0113  # uuid: conflicts with genesis
    DNS_FETCH_FAILED = 0x0114  # dns: fetch error

    # Alias for backward compatibility
    OVERLOADED = 6  # Same as BUSY_TRY_LATER

    @classmethod
    def from_value_with_fallback(cls, value: int) -> "ErrorCode":
        """Convert value to ErrorCode with fallback to UNKNOWN."""
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN

    @classmethod
    def display_name(cls, value: int) -> str:
        """Get display name for error code (handles unknown codes)."""
        try:
            return cls(value).name
        except ValueError:
            return f"UNKNOWN ({value})"


class Capability(StrEnum):
    """Node Capabilities (Section 6.2)"""

    GUARDIAN = "guardian"
    SEEDER = "seeder"
    OBSERVER = "observer"
    LIGHT = "light"
    PRIVATE = "private"
    GOSSIP = "gossip"


class StorageType(StrEnum):
    """Storage Types (Section 8.2.1, 14.5)"""

    IPFS = "ipfs"
    ARWEAVE = "arweave"
    FILECOIN = "filecoin"
    SWARM = "swarm"
    ONCHAIN = "onchain"
    HTTP = "http"
    LOCAL = "local"


class ItemStatus(StrEnum):
    """Item Status (Section 8.2.2)"""

    UNKNOWN = "unknown"
    AVAILABLE = "available"
    AT_RISK = "at_risk"
    BROKEN = "broken"
    LOCAL_ONLY = "local_only"


class CollectionType(StrEnum):
    """Collection Types (Section 8.1.1)"""

    NFT_COLLECTION = "nft-collection"
    PHOTO_LIBRARY = "photo-library"
    BACKUP_ARCHIVE = "backup-archive"
    SHARED_FOLDER = "shared-folder"
    DATASET = "dataset"
    CUSTOM = "custom"


class AccessMode(StrEnum):
    """Collection Access Modes (Section 8.1)"""

    PUBLIC = "public"
    PRIVATE = "private"


class GoodbyeReason(StrEnum):
    """Goodbye Reasons (Section 6.10)"""

    SHUTDOWN = "shutdown"
    MAINTENANCE = "maintenance"
    LEAVING_COLLECTION = "leaving_collection"


class MemberStatus(StrEnum):
    """Member Status (Section 6.18)"""

    ACTIVE = "active"
    OFFLINE = "offline"
    REVOKED = "revoked"


class Permission(StrEnum):
    """Member Permissions (Section 6.12)"""

    MEMBER = "member"
    ADMIN = "admin"


class MediaType(StrEnum):
    """Media File Types (Section 8.2)"""

    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    MODEL = "model"
    HTML = "html"
    FILE = "file"


class SourceType(StrEnum):
    """Source Types (Section 8.1)"""

    BLOCKCHAIN = "blockchain"
    USER_GENERATED = "user-generated"
    IMPORT = "import"


class ChainIdentifier(StrEnum):
    """Chain Identifiers (Section 14.6)"""

    ETH = "eth"
    POLYGON = "polygon"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    BASE = "base"
    PRIVATE = "private"


class KeyRotationReason(StrEnum):
    """Key Rotation Reasons (Section 13.7.2)

    Unknown values MUST be accepted and treated as "unspecified"
    """

    MEMBER_REVOKED = "member_revoked"
    PERIODIC = "periodic"
    SECURITY = "security"
    UNSPECIFIED = "unspecified"


# =============================================================================
# Local-Only State Types (NOT transmitted over wire)
# =============================================================================


class NodeState(StrEnum):
    """Node States (Section 7.1 - DCPP/1.0)

    These are LOCAL-ONLY and NOT transmitted over the wire.
    Finite set: OFFLINE | CONNECTING | READY | SYNCING | GUARDING | SEEDING | DEGRADED
    """

    OFFLINE = "offline"
    CONNECTING = "connecting"
    READY = "ready"
    SYNCING = "syncing"
    GUARDING = "guarding"
    SEEDING = "seeding"
    DEGRADED = "degraded"


class CollectionState(StrEnum):
    """Collection States (Section 7.3 - DCPP/1.0)

    These are LOCAL-ONLY and NOT transmitted over the wire.
    Finite set: UNKNOWN | INTERESTED | SYNCING | COMPLETE | PARTIAL | STALE
    """

    UNKNOWN = "unknown"
    INTERESTED = "interested"
    SYNCING = "syncing"
    COMPLETE = "complete"
    PARTIAL = "partial"
    STALE = "stale"


# =============================================================================
# CRC32C parameters (Section 5.2.1)
# =============================================================================
