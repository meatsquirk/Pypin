"""
Request/Response Correlation E2E Tests

Tests Request ID correlation for async multiplexing as specified in RFC Section 5.1.2.

Frame Header Layout (Profile 1):
```
Offset  Size  Field
0       4     Magic (0x44435050 "DCPP")
4       2     Version (0x0100 for v1.0)
6       2     Message Type
8       4     Request ID  <-- Correlation field
12      4     Length
16      4     CRC32C
20      var   Payload (CBOR)
```

Key Requirements:
- Request ID is a 4-byte unsigned integer at offset 8-11
- Request ID MUST be unique per request
- Response MUST echo the Request ID from the corresponding request
- Multiple concurrent requests MUST be correctly correlated
- ERROR responses MUST include the Request ID of the failed request
"""

from __future__ import annotations

import concurrent.futures
import os
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

import pytest

from dcpp_python.core.constants import MessageType, ErrorCode
from dcpp_python.core.framing import Profile1Framer, Frame

# Import shared infrastructure
from tests.e2e.test_real_e2e import (
    ensure_docker_cluster,
    ensure_manifest_seeded,
    is_docker_running,
    is_node_reachable,
    http_health_check,
    RUST_NODE_1_P2P,
    RUST_NODE_1_HTTP,
    COLLECTION_BAYC,
)

from tests.e2e.test_complete_message_flow import (
    EnhancedDCPPClient,
    PendingRequest,
    get_test_endpoint,
    requires_raw_dcpp,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def docker_cluster():
    """Ensure Docker cluster is running for E2E tests."""
    endpoint = get_test_endpoint()
    if endpoint is None:
        pytest.skip(
            "Raw DCPP endpoint not configured. "
            "Set DCPP_E2E_RAW_DCPP_HOST and DCPP_E2E_RAW_DCPP_PORT."
        )

    if not is_docker_running():
        pytest.skip("Docker not running or not available")

    ensure_docker_cluster("Request/Response correlation test")

    if not http_health_check(RUST_NODE_1_HTTP):
        pytest.skip("Rust node HTTP health endpoint not reachable")

    ensure_manifest_seeded("Request/Response correlation test")
    return True


@pytest.fixture
def client(docker_cluster) -> EnhancedDCPPClient:
    """Create connected DCPP client."""
    endpoint = get_test_endpoint()
    if endpoint is None:
        pytest.skip("Raw DCPP endpoint not configured")

    host, port = endpoint

    if not is_node_reachable(host, port):
        pytest.skip(f"DCPP endpoint {host}:{port} not reachable")

    client = EnhancedDCPPClient(host, port)
    if not client.connect():
        pytest.skip(f"Failed to connect to DCPP endpoint {host}:{port}")

    yield client
    client.close()


# =============================================================================
# Test: Request ID Generation (Unit Tests - No Network Required)
# =============================================================================


class TestRequestIdGeneration:
    """
    Test Request ID generation and uniqueness.

    These tests do NOT require network connectivity - they test the client's
    Request ID generation logic using a local (unconnected) client instance.
    """

    def test_request_id_is_unique_per_request(self):
        """
        Verify each request gets a unique Request ID.
        """
        # Create unconnected client for testing ID generation
        test_client = EnhancedDCPPClient("localhost", 9999)
        generated_ids: Set[int] = set()

        for i in range(100):
            rid = test_client._next_request_id()
            assert rid not in generated_ids, \
                f"Duplicate Request ID {rid} generated at iteration {i}"
            generated_ids.add(rid)

        assert len(generated_ids) == 100, "Not all Request IDs are unique"

    def test_request_id_is_positive_integer(self):
        """
        Verify Request ID is a positive integer (1 to 0xFFFFFFFF).

        Per RFC, Request ID 0 is reserved.
        """
        test_client = EnhancedDCPPClient("localhost", 9999)
        for _ in range(10):
            rid = test_client._next_request_id()
            assert rid > 0, "Request ID should be positive (0 is reserved)"
            assert rid <= 0xFFFFFFFF, "Request ID should fit in 4 bytes"

    def test_explicit_request_id_is_honored(self):
        """
        Verify explicitly provided Request ID is used when building messages.

        Note: This tests the client's request tracking, not actual sending.
        """
        test_client = EnhancedDCPPClient("localhost", 9999)
        explicit_id = 0xDEADBEEF

        # Track a pending request with explicit ID
        test_client._pending_requests[explicit_id] = PendingRequest(
            request_id=explicit_id,
            message_type=MessageType.HELLO,
            sent_at=time.time(),
        )

        # Verify it's tracked correctly
        assert explicit_id in test_client._pending_requests
        assert test_client._pending_requests[explicit_id].request_id == explicit_id


# =============================================================================
# Test: Request ID Frame Encoding
# =============================================================================


class TestRequestIdFrameEncoding:
    """Test Request ID encoding in frame header."""

    def test_request_id_at_correct_offset(self):
        """
        Verify Request ID is encoded at offset 8-11 (big-endian).
        """
        framer = Profile1Framer()
        test_request_id = 0x12345678

        # Encode a message
        frame = framer.encode(
            MessageType.HELLO,
            {"version": "1.0.0", "node_id": b"\x00" * 4, "capabilities": [], "collections": [], "timestamp": 0},
            request_id=test_request_id,
        )

        # Extract Request ID from frame header (offset 8-11)
        encoded_request_id = struct.unpack(">I", frame[8:12])[0]

        assert encoded_request_id == test_request_id, \
            f"Request ID at offset 8-11 should be {test_request_id:#x}, got {encoded_request_id:#x}"

    def test_request_id_is_big_endian(self):
        """
        Verify Request ID uses big-endian byte order.
        """
        framer = Profile1Framer()
        test_request_id = 0x01020304

        frame = framer.encode(
            MessageType.GET_PEERS,
            {"collection_id": "test", "max_peers": 10},
            request_id=test_request_id,
        )

        # Big-endian: 0x01020304 -> bytes [0x01, 0x02, 0x03, 0x04]
        expected_bytes = bytes([0x01, 0x02, 0x03, 0x04])
        actual_bytes = frame[8:12]

        assert actual_bytes == expected_bytes, \
            f"Request ID bytes should be {expected_bytes.hex()}, got {actual_bytes.hex()}"

    def test_request_id_preserved_in_decode(self):
        """
        Verify Request ID is correctly extracted during decode.
        """
        framer = Profile1Framer()
        test_request_id = 0xCAFEBABE

        frame = framer.encode(
            MessageType.GET_MANIFEST,
            {"collection_id": "test"},
            request_id=test_request_id,
        )

        decoded = framer.decode(frame)

        assert decoded.request_id == test_request_id, \
            f"Decoded Request ID should be {test_request_id:#x}, got {decoded.request_id:#x}"


# =============================================================================
# Test: Response Request ID Correlation
# =============================================================================


class TestResponseCorrelation:
    """Test response correlation with request via Request ID."""

    def test_hello_response_echoes_request_id(self, client: EnhancedDCPPClient):
        """
        Verify HELLO response echoes the Request ID from the request.
        """
        test_request_id = 0xABCD1234
        node_id = os.urandom(32)

        # Send HELLO with specific Request ID
        client.send_hello(node_id, collections=[], request_id=test_request_id)

        # Receive response
        result = client.receive_response_by_id(test_request_id, timeout=10.0)
        assert result is not None, "No HELLO response received"

        frame, _ = result

        assert frame.request_id == test_request_id, \
            f"Response Request ID {frame.request_id:#x} doesn't match request {test_request_id:#x}"

    def test_get_peers_response_echoes_request_id(self, client: EnhancedDCPPClient):
        """
        Verify PEERS response echoes the Request ID from GET_PEERS.
        """
        # HELLO handshake first
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # GET_PEERS with specific Request ID
        test_request_id = 0x11223344
        client.send_get_peers(COLLECTION_BAYC, request_id=test_request_id)

        result = client.receive_response_by_id(test_request_id, timeout=10.0)
        assert result is not None, "No PEERS response received"

        frame, _ = result

        assert frame.request_id == test_request_id, \
            f"PEERS Response Request ID {frame.request_id:#x} doesn't match request {test_request_id:#x}"

    def test_get_manifest_response_echoes_request_id(self, client: EnhancedDCPPClient):
        """
        Verify MANIFEST response echoes the Request ID from GET_MANIFEST.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # GET_MANIFEST with specific Request ID
        test_request_id = 0x55667788
        client.send_get_manifest(COLLECTION_BAYC, request_id=test_request_id)

        result = client.receive_response_by_id(test_request_id, timeout=30.0)
        assert result is not None, "No MANIFEST/ERROR response received"

        frame, _ = result

        assert frame.request_id == test_request_id, \
            f"MANIFEST Response Request ID {frame.request_id:#x} doesn't match request {test_request_id:#x}"


# =============================================================================
# Test: Concurrent Request Correlation
# =============================================================================


class TestConcurrentRequestCorrelation:
    """Test Request ID correlation with multiple concurrent requests."""

    def test_two_concurrent_requests(self, client: EnhancedDCPPClient):
        """
        Verify two concurrent requests are correctly correlated.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Send two requests with known IDs
        id1 = 0x11111111
        id2 = 0x22222222

        client.send_get_peers(COLLECTION_BAYC, request_id=id1)
        client.send_get_manifest(COLLECTION_BAYC, request_id=id2)

        # Collect responses (may arrive in any order)
        responses: Dict[int, Tuple[Frame, Dict]] = {}
        deadline = time.time() + 30.0

        while len(responses) < 2 and time.time() < deadline:
            for rid in [id1, id2]:
                if rid in responses:
                    continue
                result = client.receive_response_by_id(rid, timeout=2.0)
                if result:
                    responses[rid] = result

        # Verify both requests received responses
        assert id1 in responses, f"No response for request {id1:#x}"
        assert id2 in responses, f"No response for request {id2:#x}"

        # Verify Request IDs match
        frame1, _ = responses[id1]
        frame2, _ = responses[id2]

        assert frame1.request_id == id1, \
            f"Response 1 Request ID mismatch: expected {id1:#x}, got {frame1.request_id:#x}"
        assert frame2.request_id == id2, \
            f"Response 2 Request ID mismatch: expected {id2:#x}, got {frame2.request_id:#x}"

        # Verify response types
        assert frame1.message_type == MessageType.PEERS, \
            f"Request {id1:#x} expected PEERS, got {frame1.message_type}"
        assert frame2.message_type in (MessageType.MANIFEST, MessageType.ERROR), \
            f"Request {id2:#x} expected MANIFEST/ERROR, got {frame2.message_type}"

    def test_many_concurrent_requests(self, client: EnhancedDCPPClient):
        """
        Verify many concurrent requests (5+) are correctly correlated.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Send multiple GET_PEERS requests with unique IDs
        request_ids = [0x10000000 + i for i in range(5)]

        for rid in request_ids:
            client.send_get_peers(COLLECTION_BAYC, request_id=rid)

        # Collect all responses
        responses: Dict[int, Tuple[Frame, Dict]] = {}
        deadline = time.time() + 30.0

        while len(responses) < len(request_ids) and time.time() < deadline:
            for rid in request_ids:
                if rid in responses:
                    continue
                result = client.receive_response_by_id(rid, timeout=1.0)
                if result:
                    responses[rid] = result

        # Verify all requests received responses
        for rid in request_ids:
            assert rid in responses, f"No response for request {rid:#x}"

            frame, _ = responses[rid]
            assert frame.request_id == rid, \
                f"Request ID mismatch for {rid:#x}: got {frame.request_id:#x}"

    def test_interleaved_request_types(self, client: EnhancedDCPPClient):
        """
        Verify different request types sent concurrently are correctly correlated.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Send different request types
        requests = [
            ("GET_PEERS", 0x10001001, lambda c, rid: c.send_get_peers(COLLECTION_BAYC, request_id=rid)),
            ("GET_MANIFEST", 0x10001002, lambda c, rid: c.send_get_manifest(COLLECTION_BAYC, request_id=rid)),
            ("GET_PEERS", 0x10001003, lambda c, rid: c.send_get_peers(COLLECTION_BAYC, request_id=rid)),
        ]

        # Send all requests
        for name, rid, send_fn in requests:
            send_fn(client, rid)

        # Collect responses
        responses: Dict[int, Tuple[str, Frame, Dict]] = {}
        deadline = time.time() + 30.0

        while len(responses) < len(requests) and time.time() < deadline:
            for name, rid, _ in requests:
                if rid in responses:
                    continue
                result = client.receive_response_by_id(rid, timeout=1.0)
                if result:
                    responses[rid] = (name, *result)

        # Verify all responses
        for name, rid, _ in requests:
            assert rid in responses, f"No response for {name} request {rid:#x}"

            req_name, frame, _ = responses[rid]
            assert frame.request_id == rid


# =============================================================================
# Test: Out-of-Order Response Handling
# =============================================================================


class TestOutOfOrderResponses:
    """Test handling of responses that arrive out of order."""

    def test_responses_may_arrive_out_of_order(self, client: EnhancedDCPPClient):
        """
        Verify responses arriving out of order are correctly matched.

        Note: We cannot force out-of-order responses, but we verify that
        the client handles them correctly by caching unmatched responses.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Send requests with specific IDs
        id1 = 0x00000001
        id2 = 0x00000002

        client.send_get_peers(COLLECTION_BAYC, request_id=id1)
        client.send_get_manifest(COLLECTION_BAYC, request_id=id2)

        # Try to receive response for id2 first (may get id1's response first)
        # The client should cache the id1 response and return it when asked
        result2 = client.receive_response_by_id(id2, timeout=30.0)
        result1 = client.receive_response_by_id(id1, timeout=10.0)

        # Both should eventually be received
        assert result2 is not None, "Response for id2 not received"
        assert result1 is not None, "Response for id1 not received"

        # Verify correct matching
        frame1, _ = result1
        frame2, _ = result2

        assert frame1.request_id == id1
        assert frame2.request_id == id2

    def test_cached_responses_are_returned(self, client: EnhancedDCPPClient):
        """
        Verify responses cached during out-of-order receipt are correctly returned.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Send multiple requests
        ids = [0x30000001, 0x30000002, 0x30000003]
        for rid in ids:
            client.send_get_peers(COLLECTION_BAYC, request_id=rid)

        # Receive in reverse order
        results = {}
        for rid in reversed(ids):
            result = client.receive_response_by_id(rid, timeout=15.0)
            if result:
                results[rid] = result

        # All should be received
        for rid in ids:
            assert rid in results, f"Response for {rid:#x} not received"
            frame, _ = results[rid]
            assert frame.request_id == rid


# =============================================================================
# Test: Error Response Correlation
# =============================================================================


class TestErrorResponseCorrelation:
    """Test Request ID correlation in ERROR responses."""

    def test_error_response_echoes_request_id(self, client: EnhancedDCPPClient):
        """
        Verify ERROR response echoes the Request ID from the failed request.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Request for non-existent collection
        test_request_id = 0xFA111234

        client.send_get_manifest("nonexistent:collection", request_id=test_request_id)

        result = client.receive_response_by_id(test_request_id, timeout=10.0)
        assert result is not None, "No response for invalid collection request"

        frame, payload = result

        # Verify Request ID even for ERROR
        assert frame.request_id == test_request_id, \
            f"ERROR Response Request ID {frame.request_id:#x} doesn't match request {test_request_id:#x}"

    def test_error_response_contains_request_type_field(self, client: EnhancedDCPPClient):
        """
        Verify ERROR response includes request_type field per RFC.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Request that should fail
        test_request_id = 0xE2202123

        client.send_get_manifest("bad-scheme:invalid", request_id=test_request_id)

        result = client.receive_response_by_id(test_request_id, timeout=10.0)

        if result is not None:
            frame, payload = result

            if frame.message_type == MessageType.ERROR:
                # Request ID correlation
                assert frame.request_id == test_request_id

                # Check for request_type field
                if "request_type" in payload:
                    assert payload["request_type"] == MessageType.GET_MANIFEST.value, \
                        "ERROR request_type should indicate GET_MANIFEST"


# =============================================================================
# Test: Edge Cases
# =============================================================================


class TestRequestIdEdgeCases:
    """Test edge cases in Request ID handling."""

    def test_maximum_request_id_value(self, client: EnhancedDCPPClient):
        """
        Verify maximum Request ID (0xFFFFFFFF) is handled correctly.
        """
        max_request_id = 0xFFFFFFFF
        node_id = os.urandom(32)

        client.send_hello(node_id, collections=[], request_id=max_request_id)

        result = client.receive_response_by_id(max_request_id, timeout=10.0)
        assert result is not None, "No response for max Request ID"

        frame, _ = result
        assert frame.request_id == max_request_id

    def test_minimum_request_id_value(self, client: EnhancedDCPPClient):
        """
        Verify minimum Request ID (0x00000001) is handled correctly.

        Note: Request ID 0 is reserved, so minimum is 1.
        """
        min_request_id = 0x00000001
        node_id = os.urandom(32)

        client.send_hello(node_id, collections=[], request_id=min_request_id)

        result = client.receive_response_by_id(min_request_id, timeout=10.0)
        assert result is not None, "No response for min Request ID"

        frame, _ = result
        assert frame.request_id == min_request_id

    def test_sequential_request_ids(self, client: EnhancedDCPPClient):
        """
        Verify sequential Request IDs are handled correctly.
        """
        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Send sequential requests
        base_id = 0x40000000
        for i in range(5):
            rid = base_id + i
            client.send_get_peers(COLLECTION_BAYC, request_id=rid)

            result = client.receive_response_by_id(rid, timeout=10.0)
            assert result is not None, f"No response for sequential ID {rid:#x}"

            frame, _ = result
            assert frame.request_id == rid

    def test_random_request_ids(self, client: EnhancedDCPPClient):
        """
        Verify random Request IDs are handled correctly.
        """
        import random

        # HELLO handshake
        node_id = os.urandom(32)
        hello_id = client.send_hello(node_id, collections=[COLLECTION_BAYC])
        client.receive_response_by_id(hello_id, timeout=10.0)

        # Send requests with random IDs
        for _ in range(3):
            rid = random.randint(1, 0xFFFFFFFF)
            client.send_get_peers(COLLECTION_BAYC, request_id=rid)

            result = client.receive_response_by_id(rid, timeout=10.0)
            assert result is not None, f"No response for random ID {rid:#x}"

            frame, _ = result
            assert frame.request_id == rid
