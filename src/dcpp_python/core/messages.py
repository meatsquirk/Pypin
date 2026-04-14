"""
DCPP Message Types

Implements all message types defined in Section 6 of the DCPP/1.0 Wire Protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, TypedDict, cast
from typing_extensions import NotRequired

import cbor2

from .constants import (
    ErrorCode,
    GoodbyeReason,
    MemberStatus,
    MessageType,
    Permission,
)


class MessageBase:
    """Base class for DCPP messages."""

    MESSAGE_TYPE: MessageType

    def to_dict(self) -> Mapping[str, object]:
        """Convert message to dictionary for CBOR serialization."""
        raise NotImplementedError

    def to_cbor(self) -> bytes:
        """Serialize message to CBOR."""
        return cbor2.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "MessageBase":
        """Create message from dictionary."""
        raise NotImplementedError

    @classmethod
    def from_cbor(cls, data: bytes) -> "MessageBase":
        """Deserialize message from CBOR."""
        return cls.from_dict(cbor2.loads(data))


# =============================================================================
# TypedDict payloads (select core messages)
# =============================================================================


class HelloPayload(TypedDict):
    version: str
    node_id: bytes
    capabilities: list[str]
    collections: list[str]
    timestamp: int
    user_agent: NotRequired[str]


class CollectionAnnouncementPayload(TypedDict):
    id: str
    manifest_cid: str
    coverage: float
    bt_status: NotRequired[str]
    shard_ids: NotRequired[list[int]]


class AnnouncePayload(TypedDict):
    node_id: bytes
    announce_seq: int
    collections: list[CollectionAnnouncementPayload]
    timestamp: int
    expires_at: int
    signature: bytes


class GetManifestPayload(TypedDict):
    collection_id: str
    version: NotRequired[int]
    since_version: NotRequired[int]


class ManifestResponsePayload(TypedDict):
    collection_id: str
    manifest: dict[str, object]
    signature: NotRequired[bytes]


class GetPeersPayload(TypedDict):
    collection_id: str
    shard_id: NotRequired[int]
    max_peers: int


class PeerInfoPayload(TypedDict):
    node_id: bytes
    multiaddrs: list[str]
    coverage: float
    last_seen: int
    response_quality: float


class PeersResponsePayload(TypedDict):
    collection_id: str
    peers: list[PeerInfoPayload]


class ChallengePayload(TypedDict):
    cid: str
    offset: int
    length: int


class HealthProbePayload(TypedDict):
    collection_id: str
    challenges: list[ChallengePayload]
    nonce: bytes


class ChallengeResponsePayload(TypedDict):
    cid: str
    data: NotRequired[bytes]
    error: NotRequired[str]


class HealthResponsePayload(TypedDict):
    responses: list[ChallengeResponsePayload]
    nonce: bytes


class GoodbyePayload(TypedDict):
    reason: str
    collections: NotRequired[list[str]]


class ErrorResponsePayload(TypedDict):
    code: int
    message: str
    request_type: int


class InvitePayload(TypedDict):
    collection_id: str
    invite_token: bytes
    expires_at: int
    inviter_id: bytes
    permissions: str


class InviteTokenPayload(TypedDict):
    collection_id: str
    created_at: int
    expires_at: int
    permissions: str
    signature: bytes


class InviteTokenSignablePayload(TypedDict):
    collection_id: str
    created_at: int
    expires_at: int
    permissions: str


class JoinPayload(TypedDict):
    collection_id: str
    invite_token: bytes
    node_id: bytes
    timestamp: int


class JoinAckPayload(TypedDict):
    collection_id: str
    node_id: bytes
    collection_key: bytes
    member_since: int
    permissions: str


class LeavePayload(TypedDict):
    collection_id: str
    node_id: bytes
    reason: NotRequired[str]


class RevokePayload(TypedDict):
    collection_id: str
    revoked_node_id: bytes
    admin_id: bytes
    timestamp: int
    signature: bytes
    reason: NotRequired[str]


class RevokeSignablePayload(TypedDict):
    collection_id: str
    revoked_node_id: bytes
    admin_id: bytes
    timestamp: int
    reason: NotRequired[str]


class GetMembersPayload(TypedDict):
    collection_id: str
    requester_id: bytes


class MemberInfoPayload(TypedDict):
    node_id: bytes
    permissions: str
    joined_at: int
    last_seen: int
    status: str


class MembersResponsePayload(TypedDict):
    collection_id: str
    members: list[MemberInfoPayload]
    total_count: int


class KeyRotatePayload(TypedDict):
    collection_id: str
    new_collection_id: str
    new_key: bytes
    reason: str
    admin_signature: bytes


# =============================================================================
# Core Messages (Section 6.1.1)
# =============================================================================


@dataclass
class Hello(MessageBase):
    """
    HELLO message (0x0001) - Section 6.2

    Sent immediately after libp2p stream is established. Both peers send HELLO.
    """

    MESSAGE_TYPE = MessageType.HELLO

    # Protocol version (e.g., "1.0.0") - REQUIRED per RFC Section 6.2
    version: str
    node_id: bytes
    capabilities: list[str]
    collections: list[str]
    timestamp: int
    user_agent: str | None = None

    # Default protocol version for convenience
    DEFAULT_VERSION = "1.0.0"

    def to_dict(self) -> HelloPayload:
        result: HelloPayload = {
            "version": self.version,
            "node_id": self.node_id,
            "capabilities": self.capabilities,
            "collections": self.collections,
            "timestamp": self.timestamp,
        }
        if self.user_agent is not None:
            result["user_agent"] = self.user_agent
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Hello":
        payload = cast(HelloPayload, data)
        # Version is REQUIRED per RFC Section 6.2 - do not accept missing values
        if "version" not in payload:
            raise ValueError("HELLO message missing required 'version' field")
        return cls(
            version=payload["version"],
            node_id=payload["node_id"],
            capabilities=payload["capabilities"],
            collections=payload["collections"],
            timestamp=payload["timestamp"],
            user_agent=payload.get("user_agent"),
        )


@dataclass
class CollectionAnnouncement:
    """Collection info within an ANNOUNCE message."""

    id: str
    manifest_cid: str
    coverage: float
    bt_status: str | None = None
    shard_ids: list[int] | None = None

    def to_dict(self) -> CollectionAnnouncementPayload:
        result: CollectionAnnouncementPayload = {
            "id": self.id,
            "manifest_cid": self.manifest_cid,
            "coverage": self.coverage,
        }
        if self.bt_status is not None:
            result["bt_status"] = self.bt_status
        if self.shard_ids is not None:
            result["shard_ids"] = self.shard_ids
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "CollectionAnnouncement":
        payload = cast(CollectionAnnouncementPayload, data)
        return cls(
            id=payload["id"],
            manifest_cid=payload["manifest_cid"],
            coverage=payload["coverage"],
            bt_status=payload.get("bt_status"),
            shard_ids=payload.get("shard_ids"),
        )


@dataclass
class Announce(MessageBase):
    """
    ANNOUNCE message (0x0002) - Section 6.3

    Broadcast to pub/sub topic to announce guardianship.
    """

    MESSAGE_TYPE = MessageType.ANNOUNCE

    node_id: bytes
    announce_seq: int
    collections: list[CollectionAnnouncement]
    timestamp: int
    expires_at: int
    signature: bytes

    def to_dict(self) -> dict[str, object]:
        return {
            "node_id": self.node_id,
            "announce_seq": self.announce_seq,
            "collections": [c.to_dict() for c in self.collections],
            "timestamp": self.timestamp,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }

    def to_signable_dict(self) -> dict[str, object]:
        """Get dict without signature for signing/verification."""
        return {
            "node_id": self.node_id,
            "announce_seq": self.announce_seq,
            "collections": [c.to_dict() for c in self.collections],
            "timestamp": self.timestamp,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Announce":
        payload = cast(AnnouncePayload, data)
        return cls(
            node_id=payload["node_id"],
            announce_seq=payload["announce_seq"],
            collections=[CollectionAnnouncement.from_dict(c) for c in payload["collections"]],
            timestamp=payload["timestamp"],
            expires_at=payload["expires_at"],
            signature=payload["signature"],
        )


@dataclass
class GetManifest(MessageBase):
    """
    GET_MANIFEST message (0x0003) - Section 6.4

    Request a collection's manifest from a peer.
    """

    MESSAGE_TYPE = MessageType.GET_MANIFEST

    collection_id: str
    version: int | None = None
    since_version: int | None = None

    def to_dict(self) -> GetManifestPayload:
        result: GetManifestPayload = {"collection_id": self.collection_id}
        if self.version is not None:
            result["version"] = self.version
        if self.since_version is not None:
            result["since_version"] = self.since_version
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "GetManifest":
        payload = cast(GetManifestPayload, data)
        return cls(
            collection_id=payload["collection_id"],
            version=payload.get("version"),
            since_version=payload.get("since_version"),
        )


@dataclass
class ManifestResponse(MessageBase):
    """
    MANIFEST message (0x0004) - Section 6.5

    Response containing collection manifest.
    """

    MESSAGE_TYPE = MessageType.MANIFEST

    collection_id: str
    manifest: dict[str, object]  # Full manifest object - see manifest.py
    signature: bytes | None = None

    def to_dict(self) -> ManifestResponsePayload:
        result: ManifestResponsePayload = {
            "collection_id": self.collection_id,
            "manifest": self.manifest,
        }
        if self.signature is not None:
            result["signature"] = self.signature
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "ManifestResponse":
        payload = cast(ManifestResponsePayload, data)
        return cls(
            collection_id=payload["collection_id"],
            manifest=payload["manifest"],
            signature=payload.get("signature"),
        )


@dataclass
class GetPeers(MessageBase):
    """
    GET_PEERS message (0x0005) - Section 6.6

    Request peers who guard a specific collection.
    """

    MESSAGE_TYPE = MessageType.GET_PEERS

    collection_id: str
    shard_id: int | None = None
    max_peers: int = 20

    def to_dict(self) -> GetPeersPayload:
        result: GetPeersPayload = {
            "collection_id": self.collection_id,
            "max_peers": self.max_peers,
        }
        if self.shard_id is not None:
            result["shard_id"] = self.shard_id
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "GetPeers":
        payload = cast(GetPeersPayload, data)
        return cls(
            collection_id=payload["collection_id"],
            shard_id=payload.get("shard_id"),
            max_peers=payload.get("max_peers", 20),
        )


@dataclass
class PeerInfo:
    """Peer information within a PEERS response."""

    node_id: bytes
    multiaddrs: list[str]
    coverage: float
    last_seen: int
    response_quality: float

    def to_dict(self) -> PeerInfoPayload:
        return {
            "node_id": self.node_id,
            "multiaddrs": self.multiaddrs,
            "coverage": self.coverage,
            "last_seen": self.last_seen,
            "response_quality": self.response_quality,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "PeerInfo":
        payload = cast(PeerInfoPayload, data)
        return cls(
            node_id=payload["node_id"],
            multiaddrs=payload["multiaddrs"],
            coverage=payload["coverage"],
            last_seen=payload["last_seen"],
            response_quality=payload["response_quality"],
        )


@dataclass
class PeersResponse(MessageBase):
    """
    PEERS message (0x0006) - Section 6.7

    Response with peer information.
    """

    MESSAGE_TYPE = MessageType.PEERS

    collection_id: str
    peers: list[PeerInfo]

    def to_dict(self) -> PeersResponsePayload:
        return {
            "collection_id": self.collection_id,
            "peers": [p.to_dict() for p in self.peers],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "PeersResponse":
        payload = cast(PeersResponsePayload, data)
        return cls(
            collection_id=payload["collection_id"],
            peers=[PeerInfo.from_dict(p) for p in payload["peers"]],
        )


@dataclass
class Challenge:
    """A single challenge within a HEALTH_PROBE."""

    cid: str
    offset: int
    length: int

    # Maximum challenge length (RFC Section 6.8)
    MAX_LENGTH = 1024

    def __post_init__(self) -> None:
        """Validate and clamp offset/length values.

        Per RFC Section 6.8, offset is uint64 and length is uint32,
        so negative values are invalid. We normalize them to prevent
        Python's negative slicing behavior from bypassing bounds checks.
        """
        # Reject negative offset (RFC: uint64)
        if self.offset < 0:
            self.offset = 0
            self._invalid_offset = True
        else:
            self._invalid_offset = False

        # Reject negative length (RFC: uint32), then clamp to MAX_LENGTH
        if self.length < 0:
            self.length = 0
            self._invalid_length = True
        else:
            self._invalid_length = False
            self.length = min(self.length, self.MAX_LENGTH)

    @classmethod
    def new_validated(cls, cid: str, offset: int, length: int, item_size: int) -> "Challenge":
        """
        Create a new challenge with validation against item size.

        Raises ValueError if offset or length are negative, or if the
        requested byte range exceeds the item's size.
        Length is clamped to MAX_LENGTH (1024) before validation.
        """
        # RFC: offset is uint64, length is uint32 - reject negative values
        if offset < 0:
            raise ValueError(f"Invalid offset: {offset} (must be non-negative)")
        if length <= 0:
            raise ValueError(f"Invalid length: {length} (must be positive)")

        # Clamp length BEFORE validation to avoid rejecting valid requests
        clamped_length = min(length, cls.MAX_LENGTH)

        if offset + clamped_length > item_size:
            raise ValueError(
                f"Invalid offset: offset {offset} + length {clamped_length} "
                f"exceeds item size {item_size}"
            )

        return cls(cid=cid, offset=offset, length=clamped_length)

    def to_dict(self) -> ChallengePayload:
        return {
            "cid": self.cid,
            "offset": self.offset,
            "length": self.length,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Challenge":
        payload = cast(ChallengePayload, data)
        return cls(
            cid=payload["cid"],
            offset=payload["offset"],
            length=payload["length"],
        )


@dataclass
class HealthProbe(MessageBase):
    """
    HEALTH_PROBE message (0x0007) - Section 6.8

    Request to verify node has specific content.
    """

    MESSAGE_TYPE = MessageType.HEALTH_PROBE

    collection_id: str
    challenges: list[Challenge]
    nonce: bytes

    def to_dict(self) -> HealthProbePayload:
        return {
            "collection_id": self.collection_id,
            "challenges": [c.to_dict() for c in self.challenges],
            "nonce": self.nonce,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "HealthProbe":
        payload = cast(HealthProbePayload, data)
        return cls(
            collection_id=payload["collection_id"],
            challenges=[Challenge.from_dict(c) for c in payload["challenges"]],
            nonce=payload["nonce"],
        )


@dataclass
class ChallengeResponse:
    """Response to a single challenge."""

    cid: str
    data: bytes | None = None
    error: str | None = None

    def to_dict(self) -> ChallengeResponsePayload:
        result: ChallengeResponsePayload = {"cid": self.cid}
        if self.data is not None:
            result["data"] = self.data
        if self.error is not None:
            result["error"] = self.error
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "ChallengeResponse":
        payload = cast(ChallengeResponsePayload, data)
        return cls(
            cid=payload["cid"],
            data=payload.get("data"),
            error=payload.get("error"),
        )


@dataclass
class HealthResponse(MessageBase):
    """
    HEALTH_RESPONSE message (0x0008) - Section 6.9

    Response to health probe.
    """

    MESSAGE_TYPE = MessageType.HEALTH_RESPONSE

    nonce: bytes
    responses: list[ChallengeResponse]

    def to_dict(self) -> HealthResponsePayload:
        return {
            "nonce": self.nonce,
            "responses": [r.to_dict() for r in self.responses],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "HealthResponse":
        payload = cast(HealthResponsePayload, data)
        return cls(
            nonce=payload["nonce"],
            responses=[ChallengeResponse.from_dict(r) for r in payload["responses"]],
        )


@dataclass
class Goodbye(MessageBase):
    """
    GOODBYE message (0x0009) - Section 6.10

    Graceful disconnect notification.
    """

    MESSAGE_TYPE = MessageType.GOODBYE

    reason: str
    collections: list[str] | None = None

    def to_dict(self) -> GoodbyePayload:
        result: GoodbyePayload = {"reason": self.reason}
        if self.collections is not None:
            result["collections"] = self.collections
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Goodbye":
        payload = cast(GoodbyePayload, data)
        return cls(
            reason=payload["reason"],
            collections=payload.get("collections"),
        )


@dataclass
class ErrorResponse(MessageBase):
    """
    ERROR message (0x00FF) - Section 6.11

    Error response to any request.
    """

    MESSAGE_TYPE = MessageType.ERROR

    code: int
    message: str
    request_type: int

    def to_dict(self) -> ErrorResponsePayload:
        return {
            "code": self.code,
            "message": self.message,
            "request_type": self.request_type,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "ErrorResponse":
        payload = cast(ErrorResponsePayload, data)
        return cls(
            code=payload["code"],
            message=payload["message"],
            request_type=payload["request_type"],
        )


# =============================================================================
# Membership Messages (Section 6.1.2) - Private Collections
# =============================================================================


@dataclass
class Invite(MessageBase):
    """
    INVITE message (0x0010) - Section 6.12

    Create and send an invitation token to a potential member.
    """

    MESSAGE_TYPE = MessageType.INVITE

    collection_id: str
    invite_token: bytes
    expires_at: int
    inviter_id: bytes
    permissions: str

    def to_dict(self) -> InvitePayload:
        return {
            "collection_id": self.collection_id,
            "invite_token": self.invite_token,
            "expires_at": self.expires_at,
            "inviter_id": self.inviter_id,
            "permissions": self.permissions,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Invite":
        payload = cast(InvitePayload, data)
        return cls(
            collection_id=payload["collection_id"],
            invite_token=payload["invite_token"],
            expires_at=payload["expires_at"],
            inviter_id=payload["inviter_id"],
            permissions=payload["permissions"],
        )


@dataclass
class InviteToken:
    """
    Invitation Token Structure - Section 6.12

    Internal structure of invite_token bytes.
    """

    collection_id: str
    created_at: int
    expires_at: int
    permissions: str
    signature: bytes

    def to_dict(self) -> InviteTokenPayload:
        return {
            "collection_id": self.collection_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "permissions": self.permissions,
            "signature": self.signature,
        }

    def to_signable_dict(self) -> InviteTokenSignablePayload:
        """Get dict without signature for signing/verification."""
        return {
            "collection_id": self.collection_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "permissions": self.permissions,
        }

    def to_cbor(self) -> bytes:
        return cbor2.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "InviteToken":
        payload = cast(InviteTokenPayload, data)
        return cls(
            collection_id=payload["collection_id"],
            created_at=payload["created_at"],
            expires_at=payload["expires_at"],
            permissions=payload["permissions"],
            signature=payload["signature"],
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> "InviteToken":
        return cls.from_dict(cbor2.loads(data))


@dataclass
class Join(MessageBase):
    """
    JOIN message (0x0011) - Section 6.13

    Request to join a private collection using an invitation token.
    """

    MESSAGE_TYPE = MessageType.JOIN

    collection_id: str
    invite_token: bytes
    node_id: bytes
    timestamp: int

    def to_dict(self) -> JoinPayload:
        return {
            "collection_id": self.collection_id,
            "invite_token": self.invite_token,
            "node_id": self.node_id,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Join":
        payload = cast(JoinPayload, data)
        return cls(
            collection_id=payload["collection_id"],
            invite_token=payload["invite_token"],
            node_id=payload["node_id"],
            timestamp=payload["timestamp"],
        )


@dataclass
class JoinAck(MessageBase):
    """
    JOIN_ACK message (0x0012) - Section 6.14

    Acknowledge successful join and provide Collection Key.
    """

    MESSAGE_TYPE = MessageType.JOIN_ACK

    collection_id: str
    node_id: bytes
    collection_key: bytes  # Encrypted to joining node's public key
    member_since: int
    permissions: str

    def to_dict(self) -> JoinAckPayload:
        return {
            "collection_id": self.collection_id,
            "node_id": self.node_id,
            "collection_key": self.collection_key,
            "member_since": self.member_since,
            "permissions": self.permissions,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "JoinAck":
        payload = cast(JoinAckPayload, data)
        return cls(
            collection_id=payload["collection_id"],
            node_id=payload["node_id"],
            collection_key=payload["collection_key"],
            member_since=payload["member_since"],
            permissions=payload["permissions"],
        )


@dataclass
class Leave(MessageBase):
    """
    LEAVE message (0x0013) - Section 6.15

    Voluntarily leave a private collection.
    """

    MESSAGE_TYPE = MessageType.LEAVE

    collection_id: str
    node_id: bytes
    reason: str | None = None

    def to_dict(self) -> LeavePayload:
        result: LeavePayload = {
            "collection_id": self.collection_id,
            "node_id": self.node_id,
        }
        if self.reason is not None:
            result["reason"] = self.reason
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Leave":
        payload = cast(LeavePayload, data)
        return cls(
            collection_id=payload["collection_id"],
            node_id=payload["node_id"],
            reason=payload.get("reason"),
        )


@dataclass
class Revoke(MessageBase):
    """
    REVOKE message (0x0014) - Section 6.16

    Admin revokes a member's access. Broadcast to all members.
    """

    MESSAGE_TYPE = MessageType.REVOKE

    collection_id: str
    revoked_node_id: bytes
    admin_id: bytes
    timestamp: int
    signature: bytes
    reason: str | None = None

    def to_dict(self) -> RevokePayload:
        result: RevokePayload = {
            "collection_id": self.collection_id,
            "revoked_node_id": self.revoked_node_id,
            "admin_id": self.admin_id,
            "timestamp": self.timestamp,
            "signature": self.signature,
        }
        if self.reason is not None:
            result["reason"] = self.reason
        return result

    def to_signable_dict(self) -> RevokeSignablePayload:
        """Get dict without signature for signing/verification."""
        result: RevokeSignablePayload = {
            "collection_id": self.collection_id,
            "revoked_node_id": self.revoked_node_id,
            "admin_id": self.admin_id,
            "timestamp": self.timestamp,
        }
        if self.reason is not None:
            result["reason"] = self.reason
        return result

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "Revoke":
        payload = cast(RevokePayload, data)
        return cls(
            collection_id=payload["collection_id"],
            revoked_node_id=payload["revoked_node_id"],
            admin_id=payload["admin_id"],
            timestamp=payload["timestamp"],
            signature=payload["signature"],
            reason=payload.get("reason"),
        )


@dataclass
class GetMembers(MessageBase):
    """
    GET_MEMBERS message (0x0015) - Section 6.17

    Request member list. Only admins may request.
    """

    MESSAGE_TYPE = MessageType.GET_MEMBERS

    collection_id: str
    requester_id: bytes

    def to_dict(self) -> GetMembersPayload:
        return {
            "collection_id": self.collection_id,
            "requester_id": self.requester_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "GetMembers":
        payload = cast(GetMembersPayload, data)
        return cls(
            collection_id=payload["collection_id"],
            requester_id=payload["requester_id"],
        )


@dataclass
class MemberInfo:
    """Member information within a MEMBERS response."""

    node_id: bytes
    permissions: str
    joined_at: int
    last_seen: int
    status: str

    def to_dict(self) -> MemberInfoPayload:
        return {
            "node_id": self.node_id,
            "permissions": self.permissions,
            "joined_at": self.joined_at,
            "last_seen": self.last_seen,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "MemberInfo":
        payload = cast(MemberInfoPayload, data)
        return cls(
            node_id=payload["node_id"],
            permissions=payload["permissions"],
            joined_at=payload["joined_at"],
            last_seen=payload["last_seen"],
            status=payload["status"],
        )


@dataclass
class MembersResponse(MessageBase):
    """
    MEMBERS message (0x0016) - Section 6.18

    Response with member list.
    """

    MESSAGE_TYPE = MessageType.MEMBERS

    collection_id: str
    members: list[MemberInfo]
    total_count: int

    def to_dict(self) -> MembersResponsePayload:
        return {
            "collection_id": self.collection_id,
            "members": [m.to_dict() for m in self.members],
            "total_count": self.total_count,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "MembersResponse":
        payload = cast(MembersResponsePayload, data)
        return cls(
            collection_id=payload["collection_id"],
            members=[MemberInfo.from_dict(m) for m in payload["members"]],
            total_count=payload["total_count"],
        )


@dataclass
class KeyRotate(MessageBase):
    """
    KEY_ROTATE message - Section 13.7.2

    Sent individually to each member with the new key encrypted to their public key.
    """

    # Note: This doesn't have a defined message type code in the spec
    # It's mentioned in Section 13.7.2 but not in the message type registry

    collection_id: str
    new_collection_id: str
    new_key: bytes  # Encrypted to recipient
    reason: str
    admin_signature: bytes

    def to_dict(self) -> KeyRotatePayload:
        return {
            "collection_id": self.collection_id,
            "new_collection_id": self.new_collection_id,
            "new_key": self.new_key,
            "reason": self.reason,
            "admin_signature": self.admin_signature,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "KeyRotate":
        payload = cast(KeyRotatePayload, data)
        return cls(
            collection_id=payload["collection_id"],
            new_collection_id=payload["new_collection_id"],
            new_key=payload["new_key"],
            reason=payload["reason"],
            admin_signature=payload["admin_signature"],
        )


# Message type to class mapping
MESSAGE_CLASSES: dict[MessageType, type[MessageBase]] = {
    MessageType.HELLO: Hello,
    MessageType.ANNOUNCE: Announce,
    MessageType.GET_MANIFEST: GetManifest,
    MessageType.MANIFEST: ManifestResponse,
    MessageType.GET_PEERS: GetPeers,
    MessageType.PEERS: PeersResponse,
    MessageType.HEALTH_PROBE: HealthProbe,
    MessageType.HEALTH_RESPONSE: HealthResponse,
    MessageType.GOODBYE: Goodbye,
    MessageType.ERROR: ErrorResponse,
    MessageType.INVITE: Invite,
    MessageType.JOIN: Join,
    MessageType.JOIN_ACK: JoinAck,
    MessageType.LEAVE: Leave,
    MessageType.REVOKE: Revoke,
    MessageType.GET_MEMBERS: GetMembers,
    MessageType.MEMBERS: MembersResponse,
}

__all__ = [
    "MessageType",
    "MessageBase",
    "Hello",
    "Announce",
    "CollectionAnnouncement",
    "GetManifest",
    "ManifestResponse",
    "GetPeers",
    "PeersResponse",
    "PeerInfo",
    "HealthProbe",
    "HealthResponse",
    "Challenge",
    "ChallengeResponse",
    "Goodbye",
    "ErrorResponse",
    "InviteToken",
    "Invite",
    "Join",
    "JoinAck",
    "Leave",
    "Revoke",
    "GetMembers",
    "MembersResponse",
    "KeyRotate",
    "MemberInfo",
    "decode_message",
]


def decode_message(message_type: MessageType, payload: bytes) -> MessageBase:
    """
    Decode a message from CBOR payload based on message type.

    Args:
        message_type: The message type
        payload: CBOR-encoded message payload

    Returns:
        Decoded message object

    Raises:
        KeyError: If message type is unknown
        ValueError: If payload is invalid CBOR or missing required fields
    """
    if message_type not in MESSAGE_CLASSES:
        raise KeyError(f"Unknown message type: {message_type}")

    cls = MESSAGE_CLASSES[message_type]

    try:
        return cls.from_cbor(payload)
    except cbor2.CBORDecodeError as e:
        # Provide hint for common CBOR errors (schema enforcement is working correctly)
        hint = (
            f"CBOR decode error for {message_type.name}: {e}. "
            "This typically indicates a schema mismatch between sender and receiver. "
            "If this error repeats, check that both implementations use the same CBOR schema."
        )
        raise ValueError(hint) from e
    except KeyError as e:
        # Missing required field
        hint = (
            f"Missing required field in {message_type.name}: {e}. "
            "Message schema may have changed or sender is using an older protocol version."
        )
        raise ValueError(hint) from e
    except (TypeError, AttributeError) as e:
        # Type mismatch in fields
        hint = (
            f"Type error in {message_type.name}: {e}. "
            "Field types may differ between implementations."
        )
        raise ValueError(hint) from e
