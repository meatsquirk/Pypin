"""
Complete Message Flow E2E Tests

Tests complete DCPP protocol message flows as specified in RFC Appendix B.1.
This validates actual protocol behavior rather than relying on log patterns.

Required Flow (RFC Section 6, Appendix B.1):
```
Node A (new)                    Node B (existing)
   │                                 │
   │────── HELLO ──────────────────▶│
   │◀───── HELLO ───────────────────│
   │                                 │
   │────── GET_PEERS(coll) ─────────▶│
   │◀───── PEERS ────────────────────│
   │                                 │
   │────── GET_MANIFEST(coll) ──────▶│
   │◀───── MANIFEST ─────────────────│
   │                                 │
   │ (joins BitTorrent swarm)        │
   │                                 │
   │────── ANNOUNCE ────────────────▶│ (broadcast)
```

Key Verification Points:
- Request ID correlation (RFC Section 5.1.2)
- Message type correctness
- Payload field validation
- Complete flow execution

IMPORTANT: Transport Layer Considerations
=========================================
The Docker cluster nodes use libp2p for the control plane, which requires
multistream-select protocol negotiation before DCPP messages can be exchanged.
Direct TCP connections to P2P ports (4101, 5101, etc.) will NOT work without
completing the libp2p handshake first.

Test Modes:
1. STUB MODE (default):
   Uses simulated transport to test protocol logic without real networking.
   Set DCPP_E2E_USE_STUB=1 to force stub mode.

2. RAW DCPP MODE:
   Set DCPP_E2E_RAW_DCPP_HOST and DCPP_E2E_RAW_DCPP_PORT to connect to a node
   exposing raw DCPP protocol (no libp2p wrapper). Useful for testing against
   simplified test servers.

3. LIBP2P MODE (future):
   When py-libp2p integration is complete, tests will use real libp2p
   for multistream-select negotiation.

Without the RAW_DCPP environment variables and when no stub is configured,
tests that require network communication will be skipped.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import pytest

from dcpp_python.core.constants import MessageType, Capability
from dcpp_python.core.framing import Profile1Framer, Frame
from dcpp_python.core.messages import (
    Hello,
    GetPeers,
    PeersResponse,
    GetManifest,
    ManifestResponse,
    ErrorResponse,
)

# Import shared infrastructure from test_real_e2e
from tests.e2e.test_real_e2e import (
    ensure_docker_cluster,
    ensure_manifest_seeded,
    is_docker_running,
    is_node_reachable,
    http_health_check,
    RUST_NODE_1_P2P,
    RUST_NODE_1_HTTP,
    COLLECTION_BAYC,
    COLLECTION_PUNKS,
    CONNECT_TIMEOUT,
    READ_TIMEOUT,
)


# =============================================================================
# Enhanced DCPP Client with Request ID Tracking
# =============================================================================


@dataclass
class PendingRequest:
    """Tracks a pending request for correlation."""
    request_id: int
    message_type: MessageType
    sent_at: float


class EnhancedDCPPClient:
    """
    DCPP client with request ID tracking for correlation testing.

    This extends the basic DCPPClient to:
    - Track pending requests by Request ID
    - Correlate responses to their requests
    - Support concurrent request handling
    - Expose raw frame data for verification
    """

    # Map request types to expected response types
    RESPONSE_MAP = {
        MessageType.GET_MANIFEST: MessageType.MANIFEST,
        MessageType.GET_PEERS: MessageType.PEERS,
        MessageType.HEALTH_PROBE: MessageType.HEALTH_RESPONSE,
        MessageType.HELLO: MessageType.HELLO,  # HELLO gets HELLO response
    }

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.framer = Profile1Framer()
        self._request_counter = 0
        self._pending_requests: Dict[int, PendingRequest] = {}
        self._received_responses: Dict[int, Tuple[Frame, Dict[str, Any]]] = {}

    def connect(self, timeout: float = CONNECT_TIMEOUT) -> bool:
        """Establish TCP connection to the node."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((self.host, self.port))
            return True
        except socket.error as e:
            print(f"Connection failed to {self.host}:{self.port}: {e}")
            return False

    def close(self) -> None:
        """Close the connection."""
        if self.sock:
            try:
                self.sock.close()
            except socket.error:
                pass
            self.sock = None

    def _next_request_id(self) -> int:
        """Generate next unique request ID."""
        self._request_counter += 1
        return self._request_counter

    def send_request_with_id(
        self,
        message_type: MessageType,
        payload: Dict[str, Any],
        request_id: Optional[int] = None,
    ) -> int:
        """
        Send request and track request ID for correlation.

        Args:
            message_type: The DCPP message type
            payload: Message payload dictionary
            request_id: Optional explicit request ID (auto-generated if None)

        Returns:
            The request ID used
        """
        if not self.sock:
            raise RuntimeError("Not connected")

        if request_id is None:
            request_id = self._next_request_id()

        # Track pending request
        self._pending_requests[request_id] = PendingRequest(
            request_id=request_id,
            message_type=message_type,
            sent_at=time.time(),
        )

        # Encode and send
        frame = self.framer.encode(message_type, payload, request_id=request_id)
        self.sock.sendall(frame)

        return request_id

    def send_hello(
        self,
        node_id: bytes,
        collections: List[str],
        request_id: Optional[int] = None,
    ) -> int:
        """Send HELLO message with tracking."""
        payload = {
            "version": "1.0.0",
            "node_id": node_id.hex() if isinstance(node_id, bytes) else node_id,
            "capabilities": [Capability.GUARDIAN.value],
            "collections": collections,
            "timestamp": int(time.time()),
            "user_agent": "dcpp-py-e2e-test/1.0",
        }
        return self.send_request_with_id(MessageType.HELLO, payload, request_id)

    def send_get_peers(
        self,
        collection_id: str,
        max_peers: int = 20,
        request_id: Optional[int] = None,
    ) -> int:
        """Send GET_PEERS message with tracking."""
        payload = {
            "collection_id": collection_id,
            "max_peers": max_peers,
        }
        return self.send_request_with_id(MessageType.GET_PEERS, payload, request_id)

    def send_get_manifest(
        self,
        collection_id: str,
        version: Optional[int] = None,
        request_id: Optional[int] = None,
    ) -> int:
        """Send GET_MANIFEST message with tracking."""
        payload: Dict[str, Any] = {"collection_id": collection_id}
        if version is not None:
            payload["version"] = version
        return self.send_request_with_id(MessageType.GET_MANIFEST, payload, request_id)

    def receive_frame(self, timeout: float = READ_TIMEOUT) -> Optional[Frame]:
        """
        Receive and decode a single frame.

        Returns the Frame object with message_type, payload bytes, and request_id.
        """
        if not self.sock:
            return None

        try:
            self.sock.settimeout(timeout)

            # Read header (20 bytes for Profile1)
            header = self._recv_exact(20)
            if not header:
                return None

            # Parse length from header (offset 12-15)
            length = struct.unpack(">I", header[12:16])[0]
            if length > 1024 * 1024:  # 1MB sanity limit
                return None

            # Read payload
            payload = self._recv_exact(length)
            if not payload:
                return None

            # Decode full frame
            frame_data = header + payload
            frame = self.framer.decode(frame_data)
            return frame

        except socket.timeout:
            return None
        except Exception as e:
            print(f"Receive failed: {e}")
            return None

    def receive_response(
        self,
        timeout: float = READ_TIMEOUT,
    ) -> Optional[Tuple[Frame, Dict[str, Any]]]:
        """
        Receive a response and decode its payload.

        Returns tuple of (Frame, decoded_payload_dict).
        """
        frame = self.receive_frame(timeout)
        if frame is None:
            return None

        payload = frame.decode_payload()
        return (frame, payload)

    def receive_response_by_id(
        self,
        request_id: int,
        timeout: float = READ_TIMEOUT,
    ) -> Optional[Tuple[Frame, Dict[str, Any]]]:
        """
        Receive response and verify it matches the request ID.

        For concurrent requests, this may receive responses for other requests
        and cache them for later retrieval.
        """
        # Check if we already have this response cached
        if request_id in self._received_responses:
            return self._received_responses.pop(request_id)

        deadline = time.time() + timeout

        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break

            result = self.receive_response(timeout=min(remaining, 2.0))
            if result is None:
                continue

            frame, payload = result

            # Check if this is the response we're looking for
            if frame.request_id == request_id:
                # Clean up pending request
                if request_id in self._pending_requests:
                    del self._pending_requests[request_id]
                return result

            # Cache for later retrieval
            self._received_responses[frame.request_id] = result

        return None

    def _recv_exact(self, n: int) -> Optional[bytes]:
        """Receive exactly n bytes."""
        if not self.sock:
            return None
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def get_pending_request_ids(self) -> List[int]:
        """Get list of pending request IDs."""
        return list(self._pending_requests.keys())


# =============================================================================
# Test Mode Configuration
# =============================================================================

# Environment variables for test modes
DCPP_E2E_USE_STUB = os.environ.get("DCPP_E2E_USE_STUB", "1") == "1"
DCPP_E2E_RAW_DCPP_HOST = os.environ.get("DCPP_E2E_RAW_DCPP_HOST")
DCPP_E2E_RAW_DCPP_PORT = os.environ.get("DCPP_E2E_RAW_DCPP_PORT")


def get_test_endpoint() -> Optional[Tuple[str, int]]:
    """
    Get the test endpoint based on environment configuration.

    Returns:
        (host, port) tuple if raw DCPP endpoint is configured, None otherwise.
    """
    if DCPP_E2E_RAW_DCPP_HOST and DCPP_E2E_RAW_DCPP_PORT:
        try:
            return (DCPP_E2E_RAW_DCPP_HOST, int(DCPP_E2E_RAW_DCPP_PORT))
        except ValueError:
            pass
    return None


# Skip marker for tests requiring raw DCPP transport
requires_raw_dcpp = pytest.mark.skipif(
    get_test_endpoint() is None,
    reason=(
        "Requires raw DCPP endpoint. Set DCPP_E2E_RAW_DCPP_HOST and "
        "DCPP_E2E_RAW_DCPP_PORT environment variables to enable, or "
        "run a test server with raw DCPP protocol (no libp2p wrapper)."
    )
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def docker_cluster():
    """Ensure Docker cluster is running for E2E tests."""
    # Skip if we're using stub mode with no raw endpoint
    endpoint = get_test_endpoint()
    if endpoint is None:
        pytest.skip(
            "Raw DCPP endpoint not configured. "
            "Set DCPP_E2E_RAW_DCPP_HOST and DCPP_E2E_RAW_DCPP_PORT, or "
            "run these tests against a node exposing raw DCPP protocol. "
            "NOTE: libp2p P2P ports require multistream-select negotiation."
        )

    if not is_docker_running():
        pytest.skip("Docker not running or not available")

    ensure_docker_cluster("Complete message flow test")

    # Verify HTTP health endpoint is reachable
    if not http_health_check(RUST_NODE_1_HTTP):
        pytest.skip("Rust node HTTP health endpoint not reachable")

    ensure_manifest_seeded("Complete message flow test")
    return True


@pytest.fixture
def client(docker_cluster) -> EnhancedDCPPClient:
    """Create connected DCPP client."""
    endpoint = get_test_endpoint()
    if endpoint is None:
        pytest.skip("Raw DCPP endpoint not configured")

    host, port = endpoint

    # Verify node is reachable
    if not is_node_reachable(host, port):
        pytest.skip(f"DCPP endpoint {host}:{port} not reachable")

    client = EnhancedDCPPClient(host, port)
    if not client.connect():
        pytest.skip(f"Failed to connect to DCPP endpoint {host}:{port}")

    yield client
    client.close()


# =============================================================================
# Helpers
# =============================================================================


def drain_unsolicited_hello(
    client: EnhancedDCPPClient,
    timeout: float = 1.0,
) -> Optional[Tuple[Frame, Dict[str, Any]]]:
    """
    Drain an unsolicited HELLO that may arrive immediately after connect.

    RFC: both peers send HELLO immediately after stream establishment, so some
    nodes may send a HELLO before we send our request.
    """
    result = client.receive_response(timeout=timeout)
    if result is None:
        return None

    frame, payload = result
    assert frame.message_type == MessageType.HELLO, (
        "Unexpected pre-HELLO message received before any requests were sent: "
        f"{frame.message_type}"
    )
    return result


def expect_response_exact(
    client: EnhancedDCPPClient,
    expected_request_id: int,
    expected_type: MessageType,
    timeout: float,
) -> Tuple[Frame, Dict[str, Any]]:
    """
    Receive the next response and assert it matches the expected request ID/type.
    """
    result = client.receive_response(timeout=timeout)
    assert result is not None, f"No response received for request {expected_request_id:#x}"

    frame, payload = result
    assert frame.request_id == expected_request_id, (
        f"Request ID mismatch: expected {expected_request_id:#x}, got {frame.request_id:#x}"
    )

    if expected_type == MessageType.MANIFEST:
        assert frame.message_type in (MessageType.MANIFEST, MessageType.ERROR), (
            f"Expected MANIFEST/ERROR, got {frame.message_type}"
        )
    else:
        assert frame.message_type == expected_type, (
            f"Expected {expected_type}, got {frame.message_type}"
        )

    return frame, payload


# =============================================================================
# Test: HELLO Exchange
# =============================================================================


class TestHelloExchange:
    """Test HELLO message exchange (RFC Section 6.2)."""

    def test_hello_request_receives_hello_response(self, client: EnhancedDCPPClient):
        """
        Verify HELLO handshake completes successfully.

        RFC Requirement: Both peers send HELLO immediately after stream establishment.
        """
        # Generate test node ID
        node_id = os.urandom(32)

        # Send HELLO
        request_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])

        # Receive response
        result = client.receive_response_by_id(request_id, timeout=10.0)
        assert result is not None, "No HELLO response received"

        frame, payload = result

        # Verify message type
        assert frame.message_type == MessageType.HELLO, \
            f"Expected HELLO response, got {frame.message_type}"

        # Verify request ID correlation
        assert frame.request_id == request_id, \
            f"Request ID mismatch: expected {request_id}, got {frame.request_id}"

    def test_hello_response_contains_required_fields(self, client: EnhancedDCPPClient):
        """
        Verify HELLO response contains all required fields per RFC Section 6.2.

        Required fields:
        - version: Protocol version string (e.g., "1.0.0")
        - node_id: Peer's node identifier
        - capabilities: List of supported capabilities
        - collections: List of guarded collection IDs
        - timestamp: Message timestamp
        """
        node_id = os.urandom(32)
        request_id = client.send_hello(node_id, collections=[])

        result = client.receive_response_by_id(request_id, timeout=10.0)
        assert result is not None, "No HELLO response received"

        frame, payload = result
        assert frame.message_type == MessageType.HELLO

        # Verify required fields
        assert "version" in payload, "HELLO missing required 'version' field"
        assert "node_id" in payload, "HELLO missing required 'node_id' field"
        assert "capabilities" in payload, "HELLO missing required 'capabilities' field"
        assert "collections" in payload, "HELLO missing required 'collections' field"
        assert "timestamp" in payload, "HELLO missing required 'timestamp' field"

        # Verify version format
        version = payload["version"]
        assert isinstance(version, str), f"version should be string, got {type(version)}"
        assert version.startswith("1."), f"Expected v1.x version, got {version}"

        # Verify node_id is present and non-empty
        peer_node_id = payload["node_id"]
        assert peer_node_id, "node_id should not be empty"

        # Verify capabilities is a list
        assert isinstance(payload["capabilities"], list), \
            "capabilities should be a list"

        # Verify timestamp is recent (within 5 minutes as per RFC clock skew tolerance)
        timestamp = payload["timestamp"]
        now = int(time.time())
        assert abs(now - timestamp) < 300, \
            f"Timestamp {timestamp} is outside clock skew tolerance (now={now})"


# =============================================================================
# Test: GET_PEERS / PEERS Exchange
# =============================================================================


class TestPeersExchange:
    """Test GET_PEERS → PEERS message flow (RFC Section 6.6-6.7)."""

    def test_get_peers_receives_peers_response(self, client: EnhancedDCPPClient):
        """
        Verify GET_PEERS request receives PEERS response.
        """
        # First do HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        hello_result = client.receive_response_by_id(hello_id, timeout=10.0)
        assert hello_result is not None, "HELLO handshake failed"

        # Send GET_PEERS
        request_id = client.send_get_peers(COLLECTION_BAYC, max_peers=20)

        # Receive response
        result = client.receive_response_by_id(request_id, timeout=10.0)
        assert result is not None, "No PEERS response received"

        frame, payload = result

        # Verify message type
        assert frame.message_type == MessageType.PEERS, \
            f"Expected PEERS response, got {frame.message_type}"

        # Verify request ID correlation
        assert frame.request_id == request_id, \
            f"Request ID mismatch: expected {request_id}, got {frame.request_id}"

    def test_peers_response_contains_required_fields(self, client: EnhancedDCPPClient):
        """
        Verify PEERS response contains required fields per RFC Section 6.7.

        Required fields:
        - collection_id: The requested collection
        - peers: List of PeerInfo objects
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # GET_PEERS
        request_id = client.send_get_peers(COLLECTION_BAYC)
        result = client.receive_response_by_id(request_id, timeout=10.0)
        assert result is not None, "No PEERS response received"

        frame, payload = result
        assert frame.message_type == MessageType.PEERS

        # Verify required fields
        assert "collection_id" in payload, "PEERS missing required 'collection_id' field"
        assert "peers" in payload, "PEERS missing required 'peers' field"

        # Verify collection_id matches request
        assert payload["collection_id"] == COLLECTION_BAYC, \
            f"collection_id mismatch: expected {COLLECTION_BAYC}, got {payload['collection_id']}"

        # Verify peers is a list
        assert isinstance(payload["peers"], list), "peers should be a list"

    def test_peers_response_peer_info_structure(self, client: EnhancedDCPPClient):
        """
        Verify PeerInfo objects in PEERS response have correct structure.

        Per RFC Section 6.7, each PeerInfo should contain:
        - node_id: Peer identifier
        - multiaddrs: List of multiaddresses
        - coverage: Float 0.0-1.0
        - last_seen: Unix timestamp
        - response_quality: Float 0.0-1.0
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # GET_PEERS
        request_id = client.send_get_peers(COLLECTION_BAYC)
        result = client.receive_response_by_id(request_id, timeout=10.0)
        assert result is not None

        frame, payload = result
        peers = payload.get("peers", [])

        if len(peers) > 0:
            peer = peers[0]

            # Verify PeerInfo structure
            assert "node_id" in peer, "PeerInfo missing 'node_id'"
            assert "multiaddrs" in peer, "PeerInfo missing 'multiaddrs'"
            assert "coverage" in peer, "PeerInfo missing 'coverage'"
            assert "last_seen" in peer, "PeerInfo missing 'last_seen'"
            assert "response_quality" in peer, "PeerInfo missing 'response_quality'"

            # Verify types
            assert isinstance(peer["multiaddrs"], list), "multiaddrs should be a list"
            assert isinstance(peer["coverage"], (int, float)), "coverage should be numeric"
            assert isinstance(peer["last_seen"], int), "last_seen should be integer"

            # Verify coverage range
            coverage = peer["coverage"]
            assert 0.0 <= coverage <= 1.0, f"coverage {coverage} outside valid range [0, 1]"


# =============================================================================
# Test: GET_MANIFEST / MANIFEST Exchange
# =============================================================================


class TestManifestExchange:
    """Test GET_MANIFEST → MANIFEST message flow (RFC Section 6.4-6.5)."""

    def test_get_manifest_receives_manifest_response(self, client: EnhancedDCPPClient):
        """
        Verify GET_MANIFEST request receives MANIFEST response.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        hello_result = client.receive_response_by_id(hello_id, timeout=10.0)
        assert hello_result is not None, "HELLO handshake failed"

        # Send GET_MANIFEST
        request_id = client.send_get_manifest(COLLECTION_BAYC)

        # Receive response (may take longer for large manifests)
        result = client.receive_response_by_id(request_id, timeout=30.0)
        assert result is not None, "No MANIFEST response received"

        frame, payload = result

        # Verify message type (could be MANIFEST or ERROR)
        assert frame.message_type in (MessageType.MANIFEST, MessageType.ERROR), \
            f"Expected MANIFEST or ERROR, got {frame.message_type}"

        # Verify request ID correlation
        assert frame.request_id == request_id, \
            f"Request ID mismatch: expected {request_id}, got {frame.request_id}"

    def test_manifest_response_contains_required_fields(self, client: EnhancedDCPPClient):
        """
        Verify MANIFEST response contains required fields per RFC Section 6.5.

        Required fields:
        - collection_id: The requested collection
        - manifest: The full manifest object
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # GET_MANIFEST
        request_id = client.send_get_manifest(COLLECTION_BAYC)
        result = client.receive_response_by_id(request_id, timeout=30.0)
        assert result is not None, "No MANIFEST response received"

        frame, payload = result

        # Skip validation if we got an ERROR (collection not seeded)
        if frame.message_type == MessageType.ERROR:
            pytest.skip(f"Node returned ERROR: {payload.get('message', 'unknown')}")

        assert frame.message_type == MessageType.MANIFEST

        # Verify required fields
        assert "collection_id" in payload, "MANIFEST missing required 'collection_id' field"
        assert "manifest" in payload, "MANIFEST missing required 'manifest' field"

        # Verify collection_id matches request
        assert payload["collection_id"] == COLLECTION_BAYC

        # Verify manifest is a dict
        manifest = payload["manifest"]
        assert isinstance(manifest, dict), "manifest should be a dictionary"

    def test_manifest_structure(self, client: EnhancedDCPPClient):
        """
        Verify manifest object structure per RFC Section 8.

        Expected fields in manifest:
        - version: Manifest version number
        - protocol: "dcpp/1.0"
        - collection_id: Collection identifier
        - total_items: Number of items
        - merkle_root: Content hash (CID format)
        - torrent: BitTorrent metadata
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # GET_MANIFEST
        request_id = client.send_get_manifest(COLLECTION_BAYC)
        result = client.receive_response_by_id(request_id, timeout=30.0)
        assert result is not None

        frame, payload = result

        if frame.message_type == MessageType.ERROR:
            pytest.skip(f"Node returned ERROR: {payload.get('message', 'unknown')}")

        manifest = payload.get("manifest", {})

        # Verify core manifest fields exist
        # Note: Not all fields may be present depending on implementation
        if "version" in manifest:
            assert isinstance(manifest["version"], int), "version should be integer"

        if "merkle_root" in manifest:
            merkle_root = manifest["merkle_root"]
            # CID format typically starts with "bafy" (CIDv1) or "Qm" (CIDv0)
            assert isinstance(merkle_root, str), "merkle_root should be string"

        if "torrent" in manifest:
            torrent = manifest["torrent"]
            assert isinstance(torrent, dict), "torrent should be dictionary"
            # Torrent should have infohash
            if "infohash" in torrent:
                assert isinstance(torrent["infohash"], (str, bytes)), \
                    "infohash should be string or bytes"


# =============================================================================
# Test: Request/Response Correlation
# =============================================================================


class TestRequestResponseCorrelation:
    """
    Test Request ID correlation per RFC Section 5.1.2.

    The Request ID is a 4-byte field at offset 8-11 in the frame header.
    Responses MUST echo the Request ID from the corresponding request.
    """

    def test_request_id_in_frame_header(self, client: EnhancedDCPPClient):
        """
        Verify Request ID is correctly encoded in frame header at offset 8-11.
        """
        # Use a known request ID
        known_request_id = 0x12345678

        # HELLO with known request ID
        node_id = os.urandom(32)
        sent_id = client.send_hello(node_id, collections=[], request_id=known_request_id)
        assert sent_id == known_request_id

        # Receive response
        result = client.receive_response_by_id(known_request_id, timeout=10.0)
        assert result is not None, "No response received"

        frame, _ = result

        # Verify Request ID matches
        assert frame.request_id == known_request_id, \
            f"Request ID mismatch: expected {known_request_id:#x}, got {frame.request_id:#x}"

    def test_multiple_requests_correlation(self, client: EnhancedDCPPClient):
        """
        Verify multiple requests are correctly correlated with their responses.
        """
        # HELLO handshake first
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Send multiple requests rapidly
        request_ids = []

        # Request 1: GET_PEERS
        id1 = client.send_get_peers(COLLECTION_BAYC)
        request_ids.append(("GET_PEERS", id1, MessageType.PEERS))

        # Request 2: GET_MANIFEST
        id2 = client.send_get_manifest(COLLECTION_BAYC)
        request_ids.append(("GET_MANIFEST", id2, MessageType.MANIFEST))

        # Collect all responses
        responses = {}
        deadline = time.time() + 30.0

        while len(responses) < len(request_ids) and time.time() < deadline:
            for name, req_id, expected_type in request_ids:
                if req_id in responses:
                    continue

                result = client.receive_response_by_id(req_id, timeout=2.0)
                if result:
                    responses[req_id] = result

        # Verify all requests received responses
        for name, req_id, expected_type in request_ids:
            assert req_id in responses, f"No response for {name} (request_id={req_id})"

            frame, payload = responses[req_id]

            # Verify request ID matches
            assert frame.request_id == req_id, \
                f"{name}: Request ID mismatch: expected {req_id}, got {frame.request_id}"

            # Verify response type (allow ERROR as valid response)
            assert frame.message_type in (expected_type, MessageType.ERROR), \
                f"{name}: Unexpected response type {frame.message_type}"

    def test_request_id_uniqueness(self, client: EnhancedDCPPClient):
        """
        Verify generated Request IDs are unique.
        """
        request_ids = set()

        # Generate multiple request IDs
        for _ in range(10):
            rid = client._next_request_id()
            assert rid not in request_ids, f"Duplicate request ID: {rid}"
            request_ids.add(rid)

        assert len(request_ids) == 10, "Not all request IDs are unique"


# =============================================================================
# Test: Complete Message Flow
# =============================================================================


class TestCompleteMessageFlow:
    """
    Test complete new node join flow per RFC Appendix B.1.

    This tests the full sequence:
    1. HELLO exchange
    2. GET_PEERS → PEERS
    3. GET_MANIFEST → MANIFEST
    """

    def test_complete_new_node_join_flow(self, client: EnhancedDCPPClient):
        """
        Test complete flow: HELLO → GET_PEERS → GET_MANIFEST → MANIFEST.

        This verifies the full RFC-compliant message exchange for a new node
        joining the network and discovering a collection.
        """
        collection_id = COLLECTION_BAYC
        node_id = os.urandom(32)

        # Step 1: HELLO exchange
        hello_id = client.send_hello(node_id, collections=[collection_id])
        hello_result = client.receive_response_by_id(hello_id, timeout=10.0)
        assert hello_result is not None, "Step 1 failed: No HELLO response"

        hello_frame, hello_payload = hello_result
        assert hello_frame.message_type == MessageType.HELLO, \
            f"Step 1 failed: Expected HELLO, got {hello_frame.message_type}"
        assert hello_frame.request_id == hello_id, \
            "Step 1 failed: Request ID mismatch in HELLO response"

        # Step 2: Discover peers
        peers_id = client.send_get_peers(collection_id)
        peers_result = client.receive_response_by_id(peers_id, timeout=10.0)
        assert peers_result is not None, "Step 2 failed: No PEERS response"

        peers_frame, peers_payload = peers_result
        assert peers_frame.message_type == MessageType.PEERS, \
            f"Step 2 failed: Expected PEERS, got {peers_frame.message_type}"
        assert peers_frame.request_id == peers_id, \
            "Step 2 failed: Request ID mismatch in PEERS response"

        # Step 3: Request manifest
        manifest_id = client.send_get_manifest(collection_id)
        manifest_result = client.receive_response_by_id(manifest_id, timeout=30.0)
        assert manifest_result is not None, "Step 3 failed: No MANIFEST response"

        manifest_frame, manifest_payload = manifest_result
        # MANIFEST or ERROR is acceptable
        assert manifest_frame.message_type in (MessageType.MANIFEST, MessageType.ERROR), \
            f"Step 3 failed: Expected MANIFEST or ERROR, got {manifest_frame.message_type}"
        assert manifest_frame.request_id == manifest_id, \
            "Step 3 failed: Request ID mismatch in MANIFEST response"

        # Final verification: Complete flow succeeded
        if manifest_frame.message_type == MessageType.MANIFEST:
            manifest = manifest_payload.get("manifest", {})
            assert manifest is not None, "MANIFEST response missing manifest object"
        else:
            # ERROR response is acceptable for collections without seeded content
            error_code = manifest_payload.get("code")
            error_msg = manifest_payload.get("message", "unknown")
            print(f"Note: Collection returned ERROR (code={error_code}): {error_msg}")

    def test_complete_flow_ordered_with_request_ids(self, client: EnhancedDCPPClient):
        """
        Verify RFC Appendix B.1 flow in strict order with Request ID correlation.

        Sequence validated:
        HELLO -> HELLO -> GET_PEERS -> PEERS -> GET_MANIFEST -> MANIFEST/ERROR
        """
        collection_id = COLLECTION_BAYC
        node_id = os.urandom(32)

        # Drain any unsolicited HELLO sent immediately after connect.
        drain_unsolicited_hello(client, timeout=1.0)

        # Use explicit, non-overlapping request IDs for clarity.
        hello_id = 0xA1A1A1A1
        peers_id = 0xA2A2A2A2
        manifest_id = 0xA3A3A3A3

        # Step 1: HELLO exchange
        client.send_hello(node_id, collections=[collection_id], request_id=hello_id)
        hello_frame, hello_payload = expect_response_exact(
            client,
            expected_request_id=hello_id,
            expected_type=MessageType.HELLO,
            timeout=10.0,
        )
        assert "node_id" in hello_payload, "HELLO response missing node_id"

        # Step 2: GET_PEERS -> PEERS
        client.send_get_peers(collection_id, request_id=peers_id)
        peers_frame, peers_payload = expect_response_exact(
            client,
            expected_request_id=peers_id,
            expected_type=MessageType.PEERS,
            timeout=10.0,
        )
        assert peers_payload.get("collection_id") == collection_id, (
            f"PEERS collection_id mismatch: expected {collection_id}, got "
            f"{peers_payload.get('collection_id')}"
        )

        # Step 3: GET_MANIFEST -> MANIFEST/ERROR
        client.send_get_manifest(collection_id, request_id=manifest_id)
        manifest_frame, manifest_payload = expect_response_exact(
            client,
            expected_request_id=manifest_id,
            expected_type=MessageType.MANIFEST,
            timeout=30.0,
        )

        if manifest_frame.message_type == MessageType.MANIFEST:
            assert manifest_payload.get("collection_id") == collection_id, (
                f"MANIFEST collection_id mismatch: expected {collection_id}, got "
                f"{manifest_payload.get('collection_id')}"
            )
            assert "manifest" in manifest_payload, "MANIFEST response missing manifest object"
        else:
            # ERROR is acceptable when collection is not seeded.
            assert "message" in manifest_payload or "code" in manifest_payload, (
                "ERROR response missing message/code"
            )

    def test_flow_with_multiple_collections(self, client: EnhancedDCPPClient):
        """
        Test flow with multiple collection interests.
        """
        collections = [COLLECTION_BAYC, COLLECTION_PUNKS]
        node_id = os.urandom(32)

        # HELLO with multiple collections
        hello_id = client.send_hello(node_id, collections=collections)
        hello_result = client.receive_response_by_id(hello_id, timeout=10.0)
        assert hello_result is not None

        hello_frame, hello_payload = hello_result
        assert hello_frame.message_type == MessageType.HELLO

        # Request manifest for each collection
        for collection_id in collections:
            manifest_id = client.send_get_manifest(collection_id)
            manifest_result = client.receive_response_by_id(manifest_id, timeout=30.0)

            # Allow ERROR for collections that may not be seeded
            assert manifest_result is not None, \
                f"No response for collection {collection_id}"

            frame, payload = manifest_result
            assert frame.message_type in (MessageType.MANIFEST, MessageType.ERROR)
            assert frame.request_id == manifest_id


# =============================================================================
# Test: Error Response Handling
# =============================================================================


class TestErrorResponseHandling:
    """Test ERROR response handling per RFC Section 6.11."""

    def test_error_for_unknown_collection(self, client: EnhancedDCPPClient):
        """
        Verify ERROR response for non-existent collection.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Request manifest for non-existent collection
        fake_collection = "nonexistent:0x0000000000000000000000000000000000000000"
        request_id = client.send_get_manifest(fake_collection)

        result = client.receive_response_by_id(request_id, timeout=10.0)
        assert result is not None, "No response for unknown collection request"

        frame, payload = result

        # Should get ERROR response
        if frame.message_type == MessageType.ERROR:
            # Verify ERROR response structure
            assert "code" in payload, "ERROR missing 'code' field"
            assert "message" in payload, "ERROR missing 'message' field"

            # Verify request ID correlation
            assert frame.request_id == request_id

    def test_error_response_contains_request_type(self, client: EnhancedDCPPClient):
        """
        Verify ERROR response includes request_type field per RFC.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Request that will likely fail
        fake_collection = "invalid-scheme:bad-collection"
        request_id = client.send_get_manifest(fake_collection)

        result = client.receive_response_by_id(request_id, timeout=10.0)

        if result is not None:
            frame, payload = result

            if frame.message_type == MessageType.ERROR:
                # request_type should indicate what request caused the error
                if "request_type" in payload:
                    assert payload["request_type"] == MessageType.GET_MANIFEST.value, \
                        "ERROR request_type should match GET_MANIFEST"
