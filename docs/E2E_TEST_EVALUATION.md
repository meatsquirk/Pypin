# E2E Test Evaluation Against DCPP RFC Specification

## Executive Summary

After reviewing the test harnesses (`e2e_tests.py`, `test_real_e2e.py`, `test_interop.py`, `test_uci_interop.py`) against the DCPP RFC Wire Protocol specification, **the tests are NOT truly testing end-to-end scenarios**. They are primarily:

1. **Integration tests with mocked components** (`e2e_tests.py`)
2. **Log pattern verification tests** (`test_real_e2e.py`)
3. **Wire format compatibility tests** (`test_interop.py`)
4. **Unit tests for parsing logic** (`test_uci_interop.py`)

## RFC Specification Requirements for E2E Tests

According to `docs/DCPP-RFC-Wire-Protocol.md`, a true E2E test should verify:

### 1. Complete Message Flows (RFC Section 6, Appendix B.1)

**Required Flow:**
```
Node A (new)                    Node B (existing)
   │                                 │
   │────── HELLO ──────────────────▶│
   │◀───── HELLO ───────────────────│
   │                                 │
   │────── GET_PEERS(bayc) ─────────▶│
   │◀───── PEERS ────────────────────│
   │                                 │
   │────── GET_MANIFEST(bayc) ──────▶│
   │◀───── MANIFEST ─────────────────│
   │                                 │
   │ (joins BitTorrent swarm)        │
   │                                 │
   │────── ANNOUNCE ────────────────▶│ (broadcast)
```

**Current Test Coverage:**
- ❌ **NOT TESTED**: Complete message flow verification
- ⚠️ **PARTIALLY TESTED**: Individual message types checked via log patterns
- ❌ **NOT TESTED**: Request/response correlation via Request ID (RFC Section 5.1.2)

### 2. State Machine Transitions (RFC Section 7)

**Required States:**
- OFFLINE → CONNECTING → READY → SYNCING → GUARDING → SEEDING
- Collection states: UNKNOWN → INTERESTED → SYNCING → COMPLETE/PARTIAL/STALE

**Current Test Coverage:**
- ❌ **NOT TESTED**: State transitions verified through actual behavior
- ⚠️ **PARTIALLY TESTED**: Log patterns checked for state indicators
- ❌ **NOT TESTED**: State machine actions (FetchManifest, SendAnnounce) verified end-to-end

### 3. Protocol Stack Integration (RFC Section 3)

**Required Components:**
- **libp2p** (control plane): Real streams, Noise encryption, protocol negotiation
- **BitTorrent** (data plane): Actual torrent creation, seeding, downloading
- **IPFS** (content addressing): CID verification, content retrieval

**Current Test Coverage:**
- ⚠️ **PARTIALLY TESTED**: libp2p connectivity verified via log patterns
- ❌ **NOT TESTED**: BitTorrent operations (torrent creation, seeding, downloading)
- ❌ **NOT TESTED**: IPFS CID verification and content retrieval

### 4. Peer Discovery (RFC Section 9)

**Required Mechanisms:**
- DHT-based discovery: `sha256("dcpp/1.0:" + collection_id)` key derivation
- Pub/Sub discovery: `/dcpp/1.0/collection/{collection_id}` topic format
- Bootstrap nodes: DNS/IPNS discovery

**Current Test Coverage:**
- ⚠️ **PARTIALLY TESTED**: DHT key derivation verified (unit test)
- ⚠️ **PARTIALLY TESTED**: DHT provider announcements checked via logs
- ❌ **NOT TESTED**: Actual DHT lookups returning peer information
- ❌ **NOT TESTED**: GossipSub message delivery verified through actual message receipt

### 5. Health Probing (RFC Section 10)

**Required Flow:**
- HEALTH_PROBE with challenges (CID, offset, length)
- HEALTH_RESPONSE with actual content bytes
- Response time tracking for anti-leech detection

**Current Test Coverage:**
- ⚠️ **PARTIALLY TESTED**: Health probe receipt checked via logs
- ❌ **NOT TESTED**: Actual challenge/response with content verification
- ❌ **NOT TESTED**: Response time tracking and anti-leech logic

## Detailed Analysis by Test File

### 1. `src/dcpp_python/e2e_tests.py`

**Type:** Integration test harness with mocked components

**Issues:**
- Uses `SimulatedHost` instead of real libp2p
- Uses `LocalDHT` instead of real Kademlia DHT
- Uses `MemoryStorage` (acceptable for some tests)
- Message sending is synchronous and in-memory
- No real network communication
- No BitTorrent integration
- No actual state machine execution

**What it tests:**
- Message serialization/deserialization
- Basic message routing logic
- Network simulation (packet loss, latency)

**What it should test (per RFC):**
- Real libp2p stream establishment
- Real DHT provider lookups
- Real GossipSub pub/sub
- Complete message flows with Request ID correlation
- State machine transitions triggered by real events

**Verdict:** ❌ **NOT E2E** - This is an integration test with mocked network components.

### 2. `tests/e2e/test_real_e2e.py`

**Type:** Log pattern verification tests against Docker containers

**Issues:**
- Tests check **log patterns** rather than **actual protocol behavior**
- No verification of message content or correctness
- No verification of Request ID correlation (RFC Section 5.1.2)
- No verification of actual message delivery
- No verification of state machine transitions through behavior
- No BitTorrent operations tested
- No actual content verification (CID checks, health probe responses)

**What it tests:**
- Docker containers are running
- Log messages contain expected patterns
- HTTP health endpoints respond
- Ports are reachable

**What it should test (per RFC):**
- Actual DCPP protocol messages exchanged
- Request/response correlation via Request ID
- State machine transitions verified through behavior (not logs)
- BitTorrent torrent creation and seeding
- Actual DHT lookups returning peer information
- GossipSub message delivery verified through message receipt
- Health probe challenges returning actual content bytes

**Example of problematic test:**
```python
def test_announce_received_by_peer(self):
    logs_2 = get_container_logs("dcpp-rust-2", lines=500)
    received_pattern = r"Received ANNOUNCE via GossipSub from"
    match = re.search(received_pattern, logs_2)
    assert match, "Expected pattern in logs"
```

**Problem:** This only checks if a log message exists, not if:
- The ANNOUNCE message was actually received
- The message content is correct
- The message triggered the expected state machine action
- The peer table was actually updated

**Verdict:** ⚠️ **PARTIALLY E2E** - Tests real infrastructure but verifies via logs, not protocol behavior.

### 3. `tests/e2e/test_interop.py`

**Type:** Wire format compatibility tests

**What it tests:**
- Framing (Profile 1 envelope format)
- CBOR serialization compatibility
- Signature verification
- CRC-32C checksum computation
- Test vector roundtrips

**Verdict:** ✅ **APPROPRIATE** - These are unit/integration tests for wire format compatibility, not E2E tests.

### 4. `tests/e2e/test_uci_interop.py`

**Type:** UCI parsing and verification logic tests

**What it tests:**
- UCI string parsing
- Collection ID scheme validation
- Genesis storage logic
- Manifest verification pipeline

**Verdict:** ✅ **APPROPRIATE** - These are unit tests for parsing/verification logic, not E2E tests.

## Missing E2E Test Scenarios

Based on RFC Appendix B and the protocol specification, the following E2E scenarios are **NOT tested**:

### 1. Complete New Node Join Flow

**Should test:**
1. Node A starts, connects to bootstrap node B
2. Node A sends HELLO, receives HELLO
3. Node A queries DHT for collection providers
4. Node A receives GET_PEERS response with peer list
5. Node A sends GET_MANIFEST to Node B
6. Node A receives MANIFEST response
7. Node A verifies manifest CID
8. Node A joins BitTorrent swarm
9. Node A downloads content via BitTorrent
10. Node A verifies downloaded content against CIDs
11. Node A transitions to GUARDING state
12. Node A sends ANNOUNCE via GossipSub
13. Node B receives ANNOUNCE and updates peer table

**Current coverage:** ❌ Not tested end-to-end

#### Implementation Guide: Complete Message Flow Verification

**File:** `tests/e2e/test_complete_message_flow.py`

**Step-by-Step Implementation:**

1. **Setup Test Environment**
   ```python
   @pytest.fixture(scope="module")
   def docker_cluster():
       ensure_docker_cluster("Complete message flow test")
       ensure_manifest_seeded("Message flow test")
       return True

   @pytest.fixture
   def client_node_a():
       """Create DCPP client for Node A (new node)."""
       client = DCPPClient("localhost", 5101)  # Python node
       assert client.connect(), "Failed to connect to Node A"
       return client

   @pytest.fixture
   def client_node_b():
       """Create DCPP client for Node B (existing guardian)."""
       client = DCPPClient("localhost", 4101)  # Rust node
       assert client.connect(), "Failed to connect to Node B"
       return client
   ```

2. **Step 1: HELLO Exchange**
   ```python
   def test_hello_exchange(client_node_a, client_node_b):
       """Verify HELLO handshake completes successfully."""
       # Node A sends HELLO
       node_a_id = b"\x01" * 32  # Test node ID
       assert client_node_a.send_hello(node_a_id, collections=[])

       # Node B should respond with HELLO
       response = client_node_a.receive_message(timeout=5.0)
       assert response is not None, "No HELLO response received"
       msg_type, payload = response
       assert msg_type == MessageType.HELLO, f"Expected HELLO, got {msg_type}"

       # Verify HELLO content
       hello = Hello.from_dict(payload)
       assert hello.version == "1.0.0"
       assert len(hello.node_id) > 0
       assert Capability.GUARDIAN in hello.capabilities
   ```
   **Expected Outcome:**
   - ✅ Both nodes exchange HELLO messages
   - ✅ HELLO contains correct version, node_id, capabilities
   - ✅ Connection established and ready for further messages

3. **Step 2: DHT Provider Discovery**
   ```python
   def test_dht_provider_discovery(client_node_a):
       """Verify Node A discovers Node B as provider via DHT."""
       collection_id = COLLECTION_BAYC

       # Node A queries DHT for providers
       # Note: This may require DHT API endpoint or direct DHT client
       # For now, verify via GET_PEERS which uses discovered providers
       assert client_node_a.send_get_peers(collection_id)

       response = client_node_a.receive_message(timeout=10.0)
       assert response is not None, "No PEERS response received"
       msg_type, payload = response
       assert msg_type == MessageType.PEERS, f"Expected PEERS, got {msg_type}"

       peers = PeersResponse.from_dict(payload)
       assert len(peers.peers) > 0, "No peers discovered"
       assert any(p.coverage > 0.0 for p in peers.peers), "No guardians found"
   ```
   **Expected Outcome:**
   - ✅ GET_PEERS request sent successfully
   - ✅ PEERS response received with at least one provider
   - ✅ Provider information includes coverage, multiaddrs, last_seen

4. **Step 3: Manifest Request**
   ```python
   def test_manifest_request_response(client_node_a, client_node_b):
       """Verify Node A can request and receive manifest from Node B."""
       collection_id = COLLECTION_BAYC

       # Node A requests manifest
       assert client_node_a.send_get_manifest(collection_id)

       # Node B should respond with MANIFEST
       response = client_node_a.receive_message(timeout=10.0)
       assert response is not None, "No MANIFEST response received"
       msg_type, payload = response
       assert msg_type == MessageType.MANIFEST, f"Expected MANIFEST, got {msg_type}"

       manifest_response = ManifestResponse.from_dict(payload)
       assert manifest_response.collection_id == collection_id
       assert manifest_response.manifest is not None
       assert manifest_response.manifest.merkle_root is not None
       assert manifest_response.manifest.torrent is not None
   ```
   **Expected Outcome:**
   - ✅ GET_MANIFEST request sent successfully
   - ✅ MANIFEST response received with valid manifest
   - ✅ Manifest contains required fields (collection_id, merkle_root, torrent)
   - ✅ Manifest CID matches expected value

5. **Step 4: Manifest Verification**
   ```python
   def test_manifest_cid_verification(client_node_a):
       """Verify manifest CID is valid and matches collection."""
       collection_id = COLLECTION_BAYC

       # Request manifest
       assert client_node_a.send_get_manifest(collection_id)
       response = client_node_a.receive_message(timeout=10.0)
       msg_type, payload = response
       manifest_response = ManifestResponse.from_dict(payload)
       manifest = manifest_response.manifest

       # Verify CID format (IPFS CIDv1)
       assert manifest.merkle_root.startswith("bafy"), "Invalid CID format"

       # Verify manifest structure
       assert manifest.collection_id == collection_id
       assert manifest.protocol == "dcpp/1.0"
       assert manifest.total_items > 0
       assert manifest.torrent.infohash is not None
   ```
   **Expected Outcome:**
   - ✅ Manifest CID is valid IPFS CIDv1 format
   - ✅ Manifest structure matches RFC Section 8.1
   - ✅ Torrent infohash present and valid

6. **Step 5: Complete Flow Integration Test**
   ```python
   def test_complete_new_node_join_flow(client_node_a, client_node_b):
       """Test complete flow: HELLO → GET_PEERS → GET_MANIFEST → MANIFEST."""
       collection_id = COLLECTION_BAYC

       # Step 1: HELLO exchange
       node_a_id = b"\x01" * 32
       assert client_node_a.send_hello(node_a_id, collections=[collection_id])
       hello_response = client_node_a.receive_message(timeout=5.0)
       assert hello_response[0] == MessageType.HELLO

       # Step 2: Discover peers
       assert client_node_a.send_get_peers(collection_id)
       peers_response = client_node_a.receive_message(timeout=10.0)
       assert peers_response[0] == MessageType.PEERS
       peers = PeersResponse.from_dict(peers_response[1])
       assert len(peers.peers) > 0

       # Step 3: Request manifest
       assert client_node_a.send_get_manifest(collection_id)
       manifest_response = client_node_a.receive_message(timeout=10.0)
       assert manifest_response[0] == MessageType.MANIFEST
       manifest = ManifestResponse.from_dict(manifest_response[1])
       assert manifest.collection_id == collection_id

       # Step 4: Verify complete flow succeeded
       assert manifest.manifest is not None
       assert manifest.manifest.torrent is not None
   ```
   **Expected Outcome:**
   - ✅ Complete message flow executes successfully
   - ✅ All message types exchanged correctly
   - ✅ No errors or timeouts during flow
   - ✅ Final state: Node A has manifest and can proceed to download

**Test File Structure:**
```python
"""
Complete Message Flow E2E Tests

Tests complete DCPP protocol message flows as specified in RFC Appendix B.1.
"""
import pytest
from dcpp_python.core.constants import MessageType
from dcpp_python.messages import Hello, PeersResponse, ManifestResponse
from tests.e2e.test_real_e2e import DCPPClient, ensure_docker_cluster, COLLECTION_BAYC

# ... (implementation above)
```

### 2. Request/Response Correlation

**Should test:**
- Request ID generation and correlation
- Multiple concurrent requests with different Request IDs
- Response matching to correct request
- Out-of-order response handling

**Current coverage:** ❌ Not tested

#### Implementation Guide: Request/Response Correlation via Request ID

**File:** `tests/e2e/test_request_response_correlation.py`

**Step-by-Step Implementation:**

1. **Setup Enhanced DCPP Client with Request ID Tracking**
   ```python
   class EnhancedDCPPClient(DCPPClient):
       """DCPP client with request ID tracking for correlation testing."""

       def __init__(self, host: str, port: int):
           super().__init__(host, port)
           self._pending_requests: Dict[int, MessageType] = {}
           self._received_responses: Dict[int, Tuple[MessageType, Dict]] = {}

       def send_request_with_id(
           self,
           message_type: MessageType,
           payload: Dict,
           request_id: Optional[int] = None
       ) -> int:
           """Send request and track request ID."""
           if request_id is None:
               request_id = self._next_request_id()

           self._pending_requests[request_id] = message_type

           # Encode with specific request ID
           frame = self.framer.encode(
               message_type,
               payload,
               request_id=request_id
           )
           self.sock.sendall(frame)
           return request_id

       def receive_response_by_id(self, request_id: int, timeout: float = 10.0) -> Optional[Tuple[MessageType, Dict]]:
           """Receive response and verify it matches request ID."""
           deadline = time.time() + timeout

           while time.time() < deadline:
               response = self.receive_message(timeout=1.0)
               if response is None:
                   continue

               msg_type, payload = response

               # Extract request_id from frame (requires refactoring framer to expose it)
               # For now, check if we have a pending request
               if request_id in self._pending_requests:
                   expected_type = self._pending_requests[request_id]
                   # Verify response type matches request
                   if self._is_response_type(msg_type, expected_type):
                       del self._pending_requests[request_id]
                       self._received_responses[request_id] = (msg_type, payload)
                       return (msg_type, payload)

           return None

       def _is_response_type(self, response_type: MessageType, request_type: MessageType) -> bool:
           """Check if response type matches request type."""
           response_map = {
               MessageType.GET_MANIFEST: MessageType.MANIFEST,
               MessageType.GET_PEERS: MessageType.PEERS,
               MessageType.HEALTH_PROBE: MessageType.HEALTH_RESPONSE,
           }
           return response_map.get(request_type) == response_type
   ```

2. **Step 1: Single Request/Response Correlation**
   ```python
   def test_single_request_response_correlation(client):
       """Verify single request receives response with matching Request ID."""
       collection_id = COLLECTION_BAYC

       # Send GET_MANIFEST with tracked request ID
       request_id = client.send_request_with_id(
           MessageType.GET_MANIFEST,
           {"collection_id": collection_id}
       )

       # Receive response and verify Request ID matches
       response = client.receive_response_by_id(request_id, timeout=10.0)
       assert response is not None, f"No response for request ID {request_id}"

       msg_type, payload = response
       assert msg_type == MessageType.MANIFEST, f"Expected MANIFEST, got {msg_type}"

       # Verify response content
       manifest = ManifestResponse.from_dict(payload)
       assert manifest.collection_id == collection_id
   ```
   **Expected Outcome:**
   - ✅ Request sent with unique Request ID
   - ✅ Response received with matching Request ID
   - ✅ Response type matches request type (GET_MANIFEST → MANIFEST)
   - ✅ Response content is correct

3. **Step 2: Multiple Concurrent Requests**
   ```python
   def test_multiple_concurrent_requests(client):
       """Verify multiple concurrent requests are correctly correlated."""
       collection_ids = [
           COLLECTION_BAYC,
           COLLECTION_PUNKS,
       ]

       # Send multiple GET_MANIFEST requests concurrently
       request_ids = []
       for collection_id in collection_ids:
           request_id = client.send_request_with_id(
               MessageType.GET_MANIFEST,
               {"collection_id": collection_id}
           )
           request_ids.append((request_id, collection_id))

       # Receive responses and verify each matches its request
       received_responses = {}
       deadline = time.time() + 30.0  # Allow time for all responses

       while time.time() < deadline and len(received_responses) < len(request_ids):
           for request_id, collection_id in request_ids:
               if request_id in received_responses:
                   continue

               response = client.receive_response_by_id(request_id, timeout=2.0)
               if response:
                   received_responses[request_id] = response

       # Verify all requests received responses
       assert len(received_responses) == len(request_ids), \
           f"Expected {len(request_ids)} responses, got {len(received_responses)}"

       # Verify each response matches its request
       for request_id, collection_id in request_ids:
           assert request_id in received_responses, \
               f"No response for request ID {request_id}"

           msg_type, payload = received_responses[request_id]
           manifest = ManifestResponse.from_dict(payload)
           assert manifest.collection_id == collection_id, \
               f"Response for {request_id} has wrong collection_id"
   ```
   **Expected Outcome:**
   - ✅ Multiple requests sent with different Request IDs
   - ✅ All responses received and correctly matched to requests
   - ✅ No request/response mismatches
   - ✅ Responses arrive potentially out of order but are correctly correlated

4. **Step 3: Out-of-Order Response Handling**
   ```python
   def test_out_of_order_responses(client):
       """Verify responses arriving out of order are correctly matched."""
       # Send requests in sequence
       request_1_id = client.send_request_with_id(
           MessageType.GET_MANIFEST,
           {"collection_id": COLLECTION_BAYC}
       )

       time.sleep(0.1)  # Small delay

       request_2_id = client.send_request_with_id(
           MessageType.GET_PEERS,
           {"collection_id": COLLECTION_BAYC}
       )

       # Responses may arrive in any order
       # Collect responses without assuming order
       responses = {}
       deadline = time.time() + 15.0

       while time.time() < deadline and len(responses) < 2:
           # Try to receive response for request 1
           response_1 = client.receive_response_by_id(request_1_id, timeout=1.0)
           if response_1:
               responses[request_1_id] = response_1

           # Try to receive response for request 2
           response_2 = client.receive_response_by_id(request_2_id, timeout=1.0)
           if response_2:
               responses[request_2_id] = response_2

       # Verify both responses received
       assert len(responses) == 2, "Not all responses received"

       # Verify responses match their requests regardless of arrival order
       assert request_1_id in responses
       assert request_2_id in responses

       msg_type_1, _ = responses[request_1_id]
       msg_type_2, _ = responses[request_2_id]

       assert msg_type_1 == MessageType.MANIFEST
       assert msg_type_2 == MessageType.PEERS
   ```
   **Expected Outcome:**
   - ✅ Responses arrive potentially out of order
   - ✅ Each response correctly matched to its request via Request ID
   - ✅ No cross-contamination between requests
   - ✅ All requests receive correct responses

5. **Step 4: Request ID Uniqueness Verification**
   ```python
   def test_request_id_uniqueness(client):
       """Verify Request IDs are unique across multiple requests."""
       request_ids = set()

       # Send 10 requests
       for i in range(10):
           request_id = client.send_request_with_id(
               MessageType.GET_PEERS,
               {"collection_id": COLLECTION_BAYC}
           )
           request_ids.add(request_id)

       # All Request IDs should be unique
       assert len(request_ids) == 10, \
           f"Expected 10 unique Request IDs, got {len(request_ids)}"
   ```
   **Expected Outcome:**
   - ✅ Each request has a unique Request ID
   - ✅ No Request ID collisions
   - ✅ Request IDs are 4-byte integers (per RFC Section 5.1.2)

6. **Step 5: Error Response Correlation**
   ```python
   def test_error_response_correlation(client):
       """Verify ERROR responses include correct Request ID."""
       # Send request for non-existent collection
       request_id = client.send_request_with_id(
           MessageType.GET_MANIFEST,
           {"collection_id": "nonexistent:collection"}
       )

       response = client.receive_response_by_id(request_id, timeout=10.0)
       assert response is not None, "No response received"

       msg_type, payload = response
       assert msg_type == MessageType.ERROR, "Expected ERROR response"

       error = ErrorResponse.from_dict(payload)
       assert error.code == ErrorCode.UNKNOWN_COLLECTION
       assert error.request_type == MessageType.GET_MANIFEST.value
   ```
   **Expected Outcome:**
   - ✅ ERROR response received with matching Request ID
   - ✅ ERROR response includes request_type field
   - ✅ Error code indicates correct failure reason

7. **Step 6: Request ID in Frame Header Verification**
   ```python
   def test_request_id_in_frame_header(client):
       """Verify Request ID is correctly encoded in frame header."""
       from dcpp_python.framing import Profile1Framer
       import struct

       collection_id = COLLECTION_BAYC
       request_id = 0x12345678  # Known Request ID

       # Send request with known Request ID
       payload = {"collection_id": collection_id}
       frame = client.framer.encode(
           MessageType.GET_MANIFEST,
           payload,
           request_id=request_id
       )

       # Verify Request ID in frame header (offset 8-11 per RFC Section 5.1)
       frame_request_id = struct.unpack(">I", frame[8:12])[0]
       assert frame_request_id == request_id, \
           f"Request ID mismatch: expected {request_id:#x}, got {frame_request_id:#x}"

       # Send frame
       client.sock.sendall(frame)

       # Receive response and verify Request ID matches
       response_frame = client._recv_exact(20)  # Header
       response_request_id = struct.unpack(">I", response_frame[8:12])[0]
       assert response_request_id == request_id, \
           f"Response Request ID mismatch: expected {request_id:#x}, got {response_request_id:#x}"
   ```
   **Expected Outcome:**
   - ✅ Request ID correctly encoded in frame header at offset 8-11
   - ✅ Response frame echoes Request ID from request
   - ✅ Request ID is 4-byte big-endian integer (per RFC Section 5.1.2)

**Test File Structure:**
```python
"""
Request/Response Correlation E2E Tests

Tests Request ID correlation for async multiplexing as specified in RFC Section 5.1.2.
"""
import pytest
import time
from typing import Dict, Tuple, Optional
from dcpp_python.core.constants import MessageType, ErrorCode
from dcpp_python.messages import ManifestResponse, PeersResponse, ErrorResponse
from tests.e2e.test_real_e2e import DCPPClient, ensure_docker_cluster, COLLECTION_BAYC, COLLECTION_PUNKS

# ... (implementation above)
```

**Key Testing Points:**
- ✅ Request ID generation is unique
- ✅ Request ID encoded correctly in frame header (offset 8-11)
- ✅ Response echoes Request ID from request
- ✅ Multiple concurrent requests correctly correlated
- ✅ Out-of-order responses correctly matched
- ✅ ERROR responses include Request ID and request_type

### 3. State Machine Integration

**Should test:**
- State transitions triggered by real protocol events
- Actions (FetchManifest, SendAnnounce) executed and verified
- Collection state transitions (UNKNOWN → INTERESTED → SYNCING → COMPLETE)

**Current coverage:** ⚠️ Log patterns checked, but not behavior verified

### 4. BitTorrent Integration

**Should test:**
- Torrent file generation from manifest
- Infohash derivation matches manifest
- Seeding status advertised in ANNOUNCE
- Actual BitTorrent download/upload
- Content verification after download

**Current coverage:** ❌ Not tested

### 5. Health Probing End-to-End

**Should test:**
- HEALTH_PROBE sent with challenges
- HEALTH_RESPONSE with actual content bytes
- Content verification (bytes match CID)
- Response time tracking
- Anti-leech detection logic

**Current coverage:** ⚠️ Log patterns checked, but not content verified

### 6. DHT Provider Discovery

**Should test:**
- DHT key derivation: `sha256("dcpp/1.0:" + collection_id)`
- Provider announcement to DHT
- Provider lookup via DHT
- Peer information returned matches actual providers

**Current coverage:** ⚠️ Key derivation tested (unit), but actual lookups not verified

### 7. GossipSub Message Delivery

**Should test:**
- Topic subscription: `/dcpp/1.0/collection/{collection_id}`
- ANNOUNCE published to topic
- ANNOUNCE received by subscribed peers
- Message content verified (not just log pattern)

**Current coverage:** ⚠️ Log patterns checked, but message content not verified

## Recommendations

### 1. Create True E2E Test Suite

Create `tests/e2e/test_protocol_e2e.py` that:

- **Uses real DCPP protocol client** (`DCPPClient` from `test_real_e2e.py` is a start, but needs enhancement)
- **Verifies actual message exchanges** (not just log patterns)
- **Tests complete flows** (HELLO → ANNOUNCE → GET_MANIFEST → MANIFEST)
- **Verifies Request ID correlation**
- **Tests state machine transitions** through behavior verification
- **Tests BitTorrent operations** (torrent creation, seeding, downloading)
- **Tests health probing** with actual content verification

### 2. Enhance `test_real_e2e.py`

Instead of checking log patterns, verify:

- **Actual protocol messages**: Send messages via `DCPPClient`, verify responses
- **State transitions**: Query node state via API, verify transitions
- **Peer table updates**: Query peer table via API, verify updates
- **Content verification**: Download content, verify against CIDs

### 3. Add Protocol-Level Assertions

Replace log pattern checks with protocol-level assertions:

```python
# BAD (current):
logs = get_container_logs("dcpp-rust-2", lines=500)
assert re.search(r"Received ANNOUNCE", logs)

# GOOD (proposed):
client = DCPPClient("localhost", 4102)
client.connect()
announce = client.receive_message(timeout=10.0)
assert announce.message_type == MessageType.ANNOUNCE
assert announce.collections[0].id == COLLECTION_BAYC
```

### 4. Add BitTorrent E2E Tests

Create `tests/e2e/test_bittorrent_e2e.py`:

- Generate torrent from manifest
- Verify infohash matches manifest
- Test actual download/upload
- Verify content integrity

### 5. Add State Machine E2E Tests

Create `tests/e2e/test_state_machine_e2e.py`:

- Trigger state transitions via protocol events
- Verify actions executed (FetchManifest, SendAnnounce)
- Verify collection state transitions
- Test error handling and recovery

## Conclusion

The current test suite has **good coverage of wire format compatibility and parsing logic**, but **lacks true end-to-end protocol testing**. The tests verify:

- ✅ Wire format compatibility (framing, CBOR, signatures)
- ✅ UCI parsing and validation
- ⚠️ Infrastructure availability (Docker containers, ports)
- ⚠️ Log message patterns

But do **NOT** verify:

- ❌ Complete protocol message flows
- ❌ Request/response correlation
- ❌ State machine transitions through behavior
- ❌ BitTorrent integration
- ❌ Actual content verification
- ❌ Real DHT/GossipSub operations

**Recommendation:** Create a new E2E test suite that uses the actual DCPP protocol client to verify complete message flows and state transitions, rather than relying on log pattern matching.
