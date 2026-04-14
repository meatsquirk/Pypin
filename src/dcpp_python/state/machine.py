"""
DCPP Node State Machine

Implements RFC Section 7 state management with automatic action triggers.

This module provides a formal state machine for DCPP nodes, replacing
ad-hoc state management in the daemon. State transitions automatically
trigger appropriate actions.

State Duration Tracking:
    The state machine tracks how long the node spends in each state, enabling
    metrics like:
    - Time to first guardian state (Offline → Guarding)
    - Time spent syncing per collection
    - Network partition durations

Host Event Conversion:
    The `convert_host_event_to_state_event()` function maps libp2p host events
    to state machine events, enabling integration with the async event loop.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from dcpp_python.manifest.manifest import Manifest

from dcpp_python.core.constants import MessageType

logger = logging.getLogger("dcpp.state_machine")


# =============================================================================
# State Enums (RFC Section 7)
# =============================================================================


class NodeState(Enum):
    """Node States (RFC Section 7.1)."""

    OFFLINE = auto()  # Node not running
    CONNECTING = auto()  # Establishing libp2p connections
    READY = auto()  # Connected to network, not yet guarding any collections
    SYNCING = auto()  # Downloading collection content
    GUARDING = auto()  # Have content, responding to probes and DCPP requests
    SEEDING = auto()  # Actively seeding via BitTorrent in addition to GUARDING
    DEGRADED = auto()  # Connectivity issues, limited functionality


class CollectionState(Enum):
    """Collection States (RFC Section 7.3)."""

    UNKNOWN = auto()  # Not tracking this collection
    INTERESTED = auto()  # Want to guard, haven't started sync
    SYNCING = auto()  # Downloading content
    COMPLETE = auto()  # Have full collection/shard
    PARTIAL = auto()  # Have partial content (resumable)
    STALE = auto()  # Have old manifest version


class LogLevel(Enum):
    """Log levels for state machine actions."""

    DEBUG = auto()
    INFO = auto()
    WARN = auto()
    ERROR = auto()


# =============================================================================
# State Events
# =============================================================================


@dataclass
class StateEvent:
    """Base class for state events."""

    pass


@dataclass
class NodeStartedEvent(StateEvent):
    """Node started and initialized."""

    pass


@dataclass
class BootstrapCompleteEvent(StateEvent):
    """Connected to bootstrap peers."""

    peer_count: int


@dataclass
class CollectionAnnounceReceivedEvent(StateEvent):
    """Received ANNOUNCE for a collection we're interested in."""

    collection_id: str
    manifest_cid: str
    source_peer: bytes
    coverage: float


@dataclass
class ManifestReceivedEvent(StateEvent):
    """Manifest fetched successfully."""

    collection_id: str
    manifest: "Manifest"  # Manifest object


@dataclass
class DownloadStartedEvent(StateEvent):
    """Torrent download started."""

    collection_id: str
    info_hash: bytes


@dataclass
class DownloadProgressEvent(StateEvent):
    """Torrent download progress update."""

    collection_id: str
    coverage: float
    have_pieces: int
    total_pieces: int


@dataclass
class DownloadCompleteEvent(StateEvent):
    """Torrent download completed."""

    collection_id: str


@dataclass
class HealthProbeResultEvent(StateEvent):
    """Health probe received response."""

    collection_id: str
    peer_id: bytes
    success: bool
    rtt_ms: Optional[float] = None


@dataclass
class PeerDisconnectedEvent(StateEvent):
    """Peer disconnected."""

    peer_id: bytes


@dataclass
class StorageErrorEvent(StateEvent):
    """Storage error occurred."""

    collection_id: str
    error: str


@dataclass
class NetworkPartitionEvent(StateEvent):
    """Network partition detected (can't reach any peers)."""

    pass


@dataclass
class NetworkRecoveredEvent(StateEvent):
    """Network recovered."""

    pass


@dataclass
class CollectionUpdatedEvent(StateEvent):
    """Collection content updated (via ingest API)."""

    collection_id: str


# =============================================================================
# State Actions
# =============================================================================


@dataclass
class StateAction:
    """Base class for state actions."""

    pass


@dataclass
class SendAnnounceAction(StateAction):
    """Send ANNOUNCE for collections."""

    collections: List[str]


@dataclass
class FetchManifestAction(StateAction):
    """Fetch manifest from peer."""

    collection_id: str
    peer_id: bytes


@dataclass
class StartDownloadAction(StateAction):
    """Start torrent download."""

    manifest: "Manifest"  # Manifest object


@dataclass
class UpdateCoverageAction(StateAction):
    """Update announced coverage value."""

    collection_id: str
    coverage: float


@dataclass
class RecordProbeResultAction(StateAction):
    """Record probe result for peer."""

    collection_id: str
    peer_id: bytes
    success: bool
    rtt_ms: Optional[int] = None


@dataclass
class LogAction(StateAction):
    """Log a message."""

    level: LogLevel
    message: str


@dataclass
class EmitMetricAction(StateAction):
    """Emit metric."""

    name: str
    value: float
    labels: Dict[str, str]


# =============================================================================
# Host Event Conversion
# =============================================================================


@dataclass
class HostEventInfo:
    """
    Information extracted from a libp2p host event for state machine processing.

    This struct provides a transport-agnostic representation of host events
    that can be converted to StateEvent variants.
    """

    pass


@dataclass
class PeerConnectedInfo(HostEventInfo):
    """A peer connected to us."""

    peer_id: bytes


@dataclass
class PeerDisconnectedInfo(HostEventInfo):
    """A peer disconnected from us."""

    peer_id: bytes


@dataclass
class MessageReceivedInfo(HostEventInfo):
    """Received a DCPP message that may trigger state changes."""

    peer_id: bytes
    message_type: MessageType
    collection_id: Optional[str] = None
    manifest_cid: Optional[str] = None
    coverage: Optional[float] = None


@dataclass
class ProviderFoundInfo(HostEventInfo):
    """DHT provider found for a collection we're interested in."""

    collection_id: str
    provider_peer_id: bytes


@dataclass
class NetworkLostInfo(HostEventInfo):
    """Network connectivity lost (no peers, DHT queries failing)."""

    pass


@dataclass
class NetworkRestoredInfo(HostEventInfo):
    """Network connectivity restored."""

    pass


def convert_host_event_to_state_event(host_event: HostEventInfo) -> Optional[StateEvent]:
    """
    Convert a host event to a state event if applicable.

    This function maps libp2p host events to state machine events, enabling
    integration between the async event loop and the state machine.

    Returns None if the host event doesn't correspond to a state transition.
    """
    if isinstance(host_event, PeerDisconnectedInfo):
        return PeerDisconnectedEvent(peer_id=host_event.peer_id)

    elif isinstance(host_event, MessageReceivedInfo):
        if (
            host_event.message_type == MessageType.ANNOUNCE
            and host_event.collection_id is not None
            and host_event.manifest_cid is not None
        ):
            return CollectionAnnounceReceivedEvent(
                collection_id=host_event.collection_id,
                manifest_cid=host_event.manifest_cid,
                source_peer=host_event.peer_id,
                coverage=host_event.coverage or 0.0,
            )

    elif isinstance(host_event, NetworkLostInfo):
        return NetworkPartitionEvent()

    elif isinstance(host_event, NetworkRestoredInfo):
        return NetworkRecoveredEvent()

    # PeerConnected doesn't directly map to a state event - peer count
    # is tracked separately and triggers BootstrapComplete
    # ProviderFound is informational - the actual state change happens
    # when we receive an ANNOUNCE or MANIFEST from the provider
    return None


# =============================================================================
# State Duration Tracking
# =============================================================================


@dataclass
class StateDurations:
    """State duration tracking for metrics."""

    # Time when the current node state was entered
    node_state_entered_at: float = field(default_factory=time.monotonic)
    # Accumulated duration in each node state
    node_state_durations: Dict[NodeState, float] = field(default_factory=dict)
    # Time when each collection state was entered
    collection_state_entered_at: Dict[str, float] = field(default_factory=dict)
    # Accumulated duration per collection per state
    collection_state_durations: Dict[str, Dict[CollectionState, float]] = field(
        default_factory=dict
    )

    def record_node_state_transition(
        self,
        old_state: NodeState,
        new_state: NodeState,
    ) -> float:
        """
        Record transition from one node state to another.
        Returns the duration spent in the old state (this stint only, not cumulative).
        """
        if old_state != new_state:
            stint_duration = time.monotonic() - self.node_state_entered_at
            self.node_state_durations[old_state] = (
                self.node_state_durations.get(old_state, 0.0) + stint_duration
            )
            self.node_state_entered_at = time.monotonic()
            return stint_duration
        return 0.0

    def record_collection_state_transition(
        self,
        collection_id: str,
        old_state: CollectionState,
        new_state: CollectionState,
    ) -> float:
        """
        Record transition from one collection state to another.
        Returns the duration spent in the old state (this stint only, not cumulative).
        """
        if old_state != new_state:
            if collection_id in self.collection_state_entered_at:
                stint_duration = time.monotonic() - self.collection_state_entered_at[collection_id]
                if collection_id not in self.collection_state_durations:
                    self.collection_state_durations[collection_id] = {}
                coll_durations = self.collection_state_durations[collection_id]
                coll_durations[old_state] = coll_durations.get(old_state, 0.0) + stint_duration
            else:
                stint_duration = 0.0
            self.collection_state_entered_at[collection_id] = time.monotonic()
            return stint_duration
        return 0.0

    def time_in_node_state(self, state: NodeState) -> float:
        """Get total time spent in a node state."""
        return self.node_state_durations.get(state, 0.0)

    def time_in_collection_state(self, collection_id: str, state: CollectionState) -> float:
        """Get total time spent in a collection state."""
        coll_durations = self.collection_state_durations.get(collection_id, {})
        return coll_durations.get(state, 0.0)


# =============================================================================
# Node State Machine
# =============================================================================


class NodeStateMachine:
    """
    Node state machine.

    Tracks node state and collection states, processing events
    and returning actions to execute.

    State Duration Metrics:
        The state machine tracks duration in each state and emits metrics
        on state transitions via EmitMetricAction.
    """

    def __init__(self) -> None:
        self._current_state = NodeState.OFFLINE
        self._collection_states: Dict[str, CollectionState] = {}
        self._pending_manifest_requests: Dict[str, bytes] = {}  # collection_id -> peer_id
        self.durations = StateDurations()

    def _transition_node_state(
        self,
        new_state: NodeState,
        actions: List[StateAction],
    ) -> None:
        """
        Helper to transition node state with duration tracking and metrics.
        Emits a metric with the duration of the stint we're leaving (not cumulative).
        """
        if self._current_state != new_state:
            old_state = self._current_state
            # Record transition and get the stint duration (time spent in old_state)
            stint_duration = self.durations.record_node_state_transition(old_state, new_state)
            self._current_state = new_state

            # Emit stint duration metric (not cumulative)
            actions.append(
                EmitMetricAction(
                    name="dcpp_node_state_duration_seconds",
                    value=stint_duration,
                    labels={
                        "from_state": old_state.name,
                        "to_state": new_state.name,
                    },
                )
            )

    def _transition_collection_state(
        self,
        collection_id: str,
        new_state: CollectionState,
        actions: List[StateAction],
    ) -> None:
        """
        Helper to transition collection state with duration tracking and metrics.
        Emits a metric with the duration of the stint we're leaving (not cumulative).
        """
        old_state = self._collection_states.get(collection_id, CollectionState.UNKNOWN)

        if old_state != new_state:
            # Record transition and get the stint duration
            stint_duration = self.durations.record_collection_state_transition(
                collection_id,
                old_state,
                new_state,
            )
            self._collection_states[collection_id] = new_state

            # Emit stint duration metric (not cumulative)
            actions.append(
                EmitMetricAction(
                    name="dcpp_collection_state_duration_seconds",
                    value=stint_duration,
                    labels={
                        "collection_id": collection_id,
                        "from_state": old_state.name,
                        "to_state": new_state.name,
                    },
                )
            )

    def register_interest(self, collection_id: str) -> None:
        """Register interest in a collection."""
        self._collection_states[collection_id] = CollectionState.INTERESTED
        # Start tracking duration for this collection
        self.durations.collection_state_entered_at[collection_id] = time.monotonic()

    def process_event(self, event: StateEvent) -> List[StateAction]:
        """Process an event and return actions to execute."""
        actions: List[StateAction] = []

        if isinstance(event, NodeStartedEvent):
            self._transition_node_state(NodeState.CONNECTING, actions)
            actions.append(
                LogAction(
                    level=LogLevel.INFO,
                    message="Node starting, connecting to network",
                )
            )

        elif isinstance(event, BootstrapCompleteEvent):
            if event.peer_count > 0:
                self._transition_node_state(NodeState.READY, actions)
                collections = list(self._collection_states.keys())
                actions.append(
                    LogAction(
                        level=LogLevel.INFO,
                        message=f"Bootstrap complete with {event.peer_count} peers",
                    )
                )
                actions.append(SendAnnounceAction(collections=collections))
            else:
                self._transition_node_state(NodeState.DEGRADED, actions)
                actions.append(
                    LogAction(
                        level=LogLevel.WARN,
                        message="No bootstrap peers available, entering degraded mode",
                    )
                )

        elif isinstance(event, CollectionAnnounceReceivedEvent):
            state = self._collection_states.get(event.collection_id)
            if state == CollectionState.INTERESTED:
                # We want this collection - fetch manifest
                self._pending_manifest_requests[event.collection_id] = event.source_peer
                actions.append(
                    FetchManifestAction(
                        collection_id=event.collection_id,
                        peer_id=event.source_peer,
                    )
                )

        elif isinstance(event, ManifestReceivedEvent):
            self._pending_manifest_requests.pop(event.collection_id, None)

            self._transition_collection_state(
                event.collection_id,
                CollectionState.SYNCING,
                actions,
            )
            self._transition_node_state(NodeState.SYNCING, actions)

            actions.append(
                LogAction(
                    level=LogLevel.INFO,
                    message=f"Received manifest for {event.collection_id}, starting download",
                )
            )
            actions.append(StartDownloadAction(manifest=event.manifest))

        elif isinstance(event, DownloadStartedEvent):
            self._transition_collection_state(
                event.collection_id,
                CollectionState.SYNCING,
                actions,
            )
            self._transition_node_state(NodeState.SYNCING, actions)
            actions.append(
                LogAction(
                    level=LogLevel.INFO,
                    message=f"Download started for {event.collection_id}",
                )
            )

        elif isinstance(event, DownloadProgressEvent):
            actions.append(
                UpdateCoverageAction(
                    collection_id=event.collection_id,
                    coverage=event.coverage,
                )
            )

        elif isinstance(event, DownloadCompleteEvent):
            self._transition_collection_state(
                event.collection_id,
                CollectionState.COMPLETE,
                actions,
            )

            # Check if all collections are complete
            all_complete = all(
                s == CollectionState.COMPLETE for s in self._collection_states.values()
            )

            if all_complete:
                self._transition_node_state(NodeState.GUARDING, actions)

            actions.append(
                LogAction(
                    level=LogLevel.INFO,
                    message=f"Download complete for {event.collection_id}",
                )
            )
            actions.append(
                UpdateCoverageAction(
                    collection_id=event.collection_id,
                    coverage=1.0,
                )
            )

        elif isinstance(event, HealthProbeResultEvent):
            actions.append(
                RecordProbeResultAction(
                    collection_id=event.collection_id,
                    peer_id=event.peer_id,
                    success=event.success,
                    rtt_ms=int(event.rtt_ms) if event.rtt_ms is not None else None,
                )
            )

        elif isinstance(event, PeerDisconnectedEvent):
            # Remove any pending manifest requests from this peer
            self._pending_manifest_requests = {
                k: v for k, v in self._pending_manifest_requests.items() if v != event.peer_id
            }
            actions.append(
                LogAction(
                    level=LogLevel.DEBUG,
                    message=f"Peer disconnected: {event.peer_id.hex()[:16]}...",
                )
            )

        elif isinstance(event, StorageErrorEvent):
            self._transition_collection_state(
                event.collection_id,
                CollectionState.PARTIAL,
                actions,
            )
            actions.append(
                LogAction(
                    level=LogLevel.ERROR,
                    message=f"Storage error for {event.collection_id}: {event.error}",
                )
            )

        elif isinstance(event, NetworkPartitionEvent):
            self._transition_node_state(NodeState.DEGRADED, actions)
            actions.append(
                LogAction(
                    level=LogLevel.WARN,
                    message="Network partition detected, entering degraded mode",
                )
            )

        elif isinstance(event, NetworkRecoveredEvent):
            # Determine appropriate state based on collection states
            has_syncing = any(
                s == CollectionState.SYNCING for s in self._collection_states.values()
            )
            all_complete = bool(self._collection_states) and all(
                s == CollectionState.COMPLETE for s in self._collection_states.values()
            )

            if all_complete:
                new_state = NodeState.GUARDING
            elif has_syncing:
                new_state = NodeState.SYNCING
            else:
                new_state = NodeState.READY

            self._transition_node_state(new_state, actions)
            actions.append(
                LogAction(
                    level=LogLevel.INFO,
                    message="Network recovered",
                )
            )

        elif isinstance(event, CollectionUpdatedEvent):
            # Content updated via ingest - announce the update
            actions.append(
                LogAction(
                    level=LogLevel.INFO,
                    message=f"Collection {event.collection_id} updated, announcing",
                )
            )
            actions.append(
                SendAnnounceAction(
                    collections=[event.collection_id],
                )
            )

        return actions

    @property
    def node_state(self) -> NodeState:
        """Get current node state."""
        return self._current_state

    def collection_state(self, collection_id: str) -> Optional[CollectionState]:
        """Get collection state."""
        return self._collection_states.get(collection_id)

    def all_collection_states(self) -> Dict[str, CollectionState]:
        """Get all collection states."""
        return dict(self._collection_states)

    def set_collection_state(self, collection_id: str, state: CollectionState) -> None:
        """
        Set collection state directly (for initialization from existing data).

        Note: This bypasses the normal state machine flow and does not emit metrics.
        Use this only for initialization from persisted state.
        """
        self._collection_states[collection_id] = state
        # Start tracking duration for this collection
        self.durations.collection_state_entered_at[collection_id] = time.monotonic()

    def has_pending_manifest_request(self, collection_id: str) -> bool:
        """Check if we have a pending manifest request for a collection."""
        return collection_id in self._pending_manifest_requests

    def is_ready_for_announce(self) -> bool:
        """
        Check if the node is in a state where ANNOUNCE messages should be sent.

        Per RFC Section 7.1, nodes should only send ANNOUNCE when in
        READY, SYNCING, GUARDING, or SEEDING states.
        """
        return self._current_state in (
            NodeState.READY,
            NodeState.SYNCING,
            NodeState.GUARDING,
            NodeState.SEEDING,
        )
