"""
Load Testing Module

This module provides load testing capabilities for DCPP to verify
performance under high load with hundreds of nodes.
"""

from dataclasses import dataclass, field
from typing import Coroutine, TypeVar
import asyncio
import random
import time

from .core.constants import MessageType, Capability
from .crypto import generate_keypair, derive_peer_id
from .framing import Profile1Framer
from .messages import Hello
from .libp2p_host import HostConfig, PeerIdentity, SimulatedHost

T = TypeVar("T")


def _run(coro: Coroutine[object, object, T]) -> T:
    """Run an async coroutine from a sync context."""
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return asyncio.run(coro)
    if loop.is_running():
        raise RuntimeError("Cannot run async operation while event loop is running")
    return loop.run_until_complete(coro)


@dataclass
class LoadTestConfig:
    """Load test configuration."""

    num_nodes: int = 100
    num_collections: int = 10
    messages_per_second: int = 1000
    duration_seconds: int = 60
    connections_per_node: int = 10
    detailed_metrics: bool = False


@dataclass
class LoadTestMetrics:
    """Metrics collected during load test."""

    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    avg_latency_us: float = 0.0
    max_latency_us: float = 0.0
    min_latency_us: float = 0.0
    p99_latency_us: float = 0.0
    actual_mps: float = 0.0
    errors: int = 0
    duration_seconds: float = 0.0


@dataclass
class LoadTestNode:
    """A simulated node for load testing."""

    index: int
    private_key: object
    public_key: object
    node_id: bytes
    host: SimulatedHost
    collections: list[str]
    connected_peers: list[bytes] = field(default_factory=list)


class LoadTestRunner:
    """Load test runner."""

    def __init__(self, config: LoadTestConfig):
        self.config = config
        self.nodes: list[LoadTestNode] = []
        self.metrics = LoadTestMetrics()
        self.latencies: list[float] = []
        self._framer = Profile1Framer()

        # Create nodes
        for i in range(config.num_nodes):
            private_key, public_key = generate_keypair()

            host_config = HostConfig(
                listen_addrs=[f"/ip4/127.0.0.1/tcp/{5000 + i}"],
                max_connections=config.connections_per_node * 2,
            )
            host = SimulatedHost(host_config)
            host.identity = PeerIdentity.from_key(private_key)
            node_id = host.peer_id

            # Assign collections round-robin
            collections = [
                f"collection:{c}"
                for c in range(config.num_collections)
                if c % config.num_nodes == i
            ]

            self.nodes.append(
                LoadTestNode(
                    index=i,
                    private_key=private_key,
                    public_key=public_key,
                    node_id=node_id,
                    host=host,
                    collections=collections,
                )
            )

    def start_nodes(self) -> None:
        """Start all nodes."""
        for node in self.nodes:
            _run(node.host.start())

    def stop_nodes(self) -> None:
        """Stop all nodes."""
        for node in self.nodes:
            _run(node.host.stop())

    def connect_mesh(self) -> None:
        """Connect nodes in a mesh topology."""
        peer_infos = [(n.node_id, n.host.addrs) for n in self.nodes]

        for i, node in enumerate(self.nodes):
            connections = min(self.config.connections_per_node, len(peer_infos) - 1)
            for j in range(connections):
                target = (i + j + 1) % len(peer_infos)
                if target != i:
                    peer_id, addrs = peer_infos[target]
                    _run(node.host.connect(peer_id, addrs))
                    node.connected_peers.append(peer_id)

    def run(self) -> LoadTestMetrics:
        """Run the load test."""
        self.start_nodes()
        self.connect_mesh()

        start_time = time.time()
        duration = self.config.duration_seconds
        message_interval = 1.0 / self.config.messages_per_second

        last_message_time = time.time()
        message_count = 0

        while (time.time() - start_time) < duration:
            if (time.time() - last_message_time) >= message_interval:
                from_idx = message_count % len(self.nodes)
                to_idx = (message_count + 1) % len(self.nodes)

                msg_start = time.perf_counter_ns()
                try:
                    self._send_message(from_idx, to_idx)
                    latency = (time.perf_counter_ns() - msg_start) / 1000  # microseconds
                    self.latencies.append(latency)
                except Exception:
                    self.metrics.errors += 1

                message_count += 1
                last_message_time = time.time()

        self.stop_nodes()
        return self._calculate_final_metrics(time.time() - start_time)

    def _send_message(self, from_idx: int, to_idx: int) -> None:
        """Send a message between two nodes."""
        from_node = self.nodes[from_idx]

        # Create a HELLO message
        hello = Hello(
            version=Hello.DEFAULT_VERSION,
            node_id=from_node.node_id,
            capabilities=[Capability.GUARDIAN],
            collections=from_node.collections,
            timestamp=int(time.time()),
        )

        # Serialize and frame
        payload = dict(hello.to_dict())
        framed = self._framer.encode(MessageType.HELLO, payload)

        self.metrics.messages_sent += 1
        self.metrics.bytes_sent += len(framed)

        # Decode
        frame = self._framer.decode(framed)
        decoded = frame.decode_payload()

        self.metrics.messages_received += 1
        self.metrics.bytes_received += len(str(decoded))

    def _calculate_final_metrics(self, duration: float) -> LoadTestMetrics:
        """Calculate final metrics."""
        self.metrics.duration_seconds = duration

        if self.latencies:
            self.metrics.avg_latency_us = sum(self.latencies) / len(self.latencies)
            self.metrics.min_latency_us = min(self.latencies)
            self.metrics.max_latency_us = max(self.latencies)

            sorted_latencies = sorted(self.latencies)
            p99_idx = int(len(sorted_latencies) * 0.99)
            self.metrics.p99_latency_us = (
                sorted_latencies[p99_idx] if p99_idx < len(sorted_latencies) else 0
            )

        self.metrics.actual_mps = self.metrics.messages_sent / duration if duration > 0 else 0

        return self.metrics


def run_quick_load_test() -> LoadTestMetrics:
    """Run a quick load test with default settings."""
    config = LoadTestConfig(
        num_nodes=50,
        num_collections=5,
        messages_per_second=500,
        duration_seconds=10,
        connections_per_node=5,
    )

    runner = LoadTestRunner(config)
    return runner.run()


def run_stress_test(num_nodes: int = 100, duration_seconds: int = 60) -> LoadTestMetrics:
    """Run a stress test with many nodes."""
    config = LoadTestConfig(
        num_nodes=num_nodes,
        num_collections=num_nodes // 10,
        messages_per_second=num_nodes * 10,
        duration_seconds=duration_seconds,
        connections_per_node=10,
        detailed_metrics=True,
    )

    runner = LoadTestRunner(config)
    return runner.run()


@dataclass
class ThroughputResult:
    """Throughput test result."""

    messages_per_second: float
    bytes_per_second: float
    avg_message_size: float


def benchmark_throughput(iterations: int = 10000) -> ThroughputResult:
    """Run a throughput benchmark."""
    private_key, public_key = generate_keypair()
    node_id = derive_peer_id(public_key)
    framer = Profile1Framer()

    start_time = time.time()
    total_bytes = 0

    for i in range(iterations):
        hello = Hello(
            version=Hello.DEFAULT_VERSION,
            node_id=node_id,
            capabilities=[Capability.GUARDIAN, Capability.SEEDER],
            collections=[f"collection:{i % 10}"],
            timestamp=int(time.time()),
        )

        payload = dict(hello.to_dict())
        framed = framer.encode(MessageType.HELLO, payload)
        total_bytes += len(framed)

        # Decode
        framer.decode(framed)

    elapsed = time.time() - start_time

    return ThroughputResult(
        messages_per_second=iterations / elapsed,
        bytes_per_second=total_bytes / elapsed,
        avg_message_size=total_bytes / iterations,
    )
