"""
End-to-End P2P Test Harness

This module provides a test harness for running multi-node P2P tests
to verify the complete DCPP protocol flow.
"""

from dataclasses import dataclass, field
from typing import Callable, Coroutine, Optional, TypeVar, cast
import asyncio
import random
import time

from .core.constants import MessageType, Capability
from .framing import Profile1Framer
from .messages import (
    Hello,
    Announce,
    CollectionAnnouncement,
    decode_message,
    MessageBase,
)
from .crypto import generate_keypair, sign_message
from .libp2p_host import HostConfig, PeerIdentity, SimulatedHost
from .storage import MemoryStorage
from .dht import LocalDHT
from .network.bittorrent.base import bt_status_from_torrent_status

from nacl.signing import SigningKey, VerifyKey

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
class TestNetworkConfig:
    """Configuration for a test network."""

    num_nodes: int = 5
    num_collections: int = 2
    guardians_per_collection: int = 3
    network_latency_ms: int = 0
    packet_loss_rate: float = 0.0


@dataclass
class MessageLogEntry:
    """Log entry for message exchange."""

    timestamp: float
    from_node: int
    to_node: int
    message_type: MessageType
    success: bool


@dataclass
class TestNode:
    """A node in the test network."""

    index: int
    private_key: SigningKey
    public_key: VerifyKey
    node_id: bytes
    host: SimulatedHost
    storage: MemoryStorage
    dht: LocalDHT
    collections: list[str]
    connected_peers: list[bytes] = field(default_factory=list)
    received_messages: list[MessageBase] = field(default_factory=list)


class TestNetwork:
    """A simulated P2P network for testing."""

    def __init__(self, config: TestNetworkConfig):
        self.config = config
        self.nodes: list[TestNode] = []
        self.message_log: list[MessageLogEntry] = []
        self._framer = Profile1Framer()

        # Create nodes
        for i in range(config.num_nodes):
            private_key, public_key = generate_keypair()

            host_config = HostConfig(listen_addrs=[f"/ip4/127.0.0.1/tcp/{4001 + i}"])
            host = SimulatedHost(host_config)
            host.identity = PeerIdentity.from_key(private_key)
            node_id = host.peer_id

            # Assign collections to nodes
            collections = []
            for c in range(config.num_collections):
                if i < config.guardians_per_collection:
                    collections.append(f"collection:{c}")

            self.nodes.append(
                TestNode(
                    index=i,
                    private_key=private_key,
                    public_key=public_key,
                    node_id=node_id,
                    host=host,
                    storage=MemoryStorage(),
                    dht=LocalDHT(),
                    collections=collections,
                )
            )

    def start(self) -> None:
        """Start all nodes in the network."""
        for node in self.nodes:
            _run(node.host.start())

    def stop(self) -> None:
        """Stop all nodes in the network."""
        for node in self.nodes:
            _run(node.host.stop())

    def connect_all(self) -> None:
        """Connect all nodes to each other (full mesh)."""
        peer_infos = [(n.node_id, n.host.addrs) for n in self.nodes]

        for i, node in enumerate(self.nodes):
            for j, (peer_id, addrs) in enumerate(peer_infos):
                if i != j:
                    _run(node.host.connect(peer_id, addrs))
                    node.connected_peers.append(peer_id)

    def num_nodes(self) -> int:
        """Get the number of nodes."""
        return len(self.nodes)

    def node(self, index: int) -> Optional[TestNode]:
        """Get a reference to a node."""
        if 0 <= index < len(self.nodes):
            return self.nodes[index]
        return None

    def send_message(
        self,
        from_idx: int,
        to_idx: int,
        message: MessageBase,
    ) -> Optional[MessageBase]:
        """Simulate sending a message from one node to another."""
        if from_idx >= len(self.nodes) or to_idx >= len(self.nodes):
            return None

        # Simulate packet loss
        if self.config.packet_loss_rate > 0.0:
            if random.random() < self.config.packet_loss_rate:
                return None

        # Serialize message
        msg_dict = dict(message.to_dict())
        msg_type = message.MESSAGE_TYPE

        # Frame the message
        framed = self._framer.encode(msg_type, msg_dict)

        # Log the message
        self.message_log.append(
            MessageLogEntry(
                timestamp=time.time(),
                from_node=from_idx,
                to_node=to_idx,
                message_type=msg_type,
                success=True,
            )
        )

        # Decode at destination
        frame = self._framer.decode(framed)
        decoded_message = decode_message(frame.message_type, frame.payload)

        # Store in receiver's message list
        self.nodes[to_idx].received_messages.append(decoded_message)

        return decoded_message

    def handshake(self, node_a: int, node_b: int) -> bool:
        """Run HELLO handshake between two nodes."""
        # Node A sends HELLO
        hello_a = Hello(
            version=Hello.DEFAULT_VERSION,
            node_id=self.nodes[node_a].node_id,
            capabilities=[Capability.GUARDIAN],
            collections=self.nodes[node_a].collections,
            timestamp=int(time.time()),
        )
        self.send_message(node_a, node_b, hello_a)

        # Node B sends HELLO
        hello_b = Hello(
            version=Hello.DEFAULT_VERSION,
            node_id=self.nodes[node_b].node_id,
            capabilities=[Capability.GUARDIAN],
            collections=self.nodes[node_b].collections,
            timestamp=int(time.time()),
        )
        self.send_message(node_b, node_a, hello_b)

        return True

    def announce_collection(self, node_index: int) -> None:
        """Simulate collection announcement."""
        node = self.nodes[node_index]

        collections = [
            CollectionAnnouncement(
                id=coll_id,
                manifest_cid=f"Qm{coll_id}",
                coverage=1.0,
                bt_status=bt_status_from_torrent_status(None),
                shard_ids=[0],
            )
            for coll_id in node.collections
        ]

        if not collections:
            return

        timestamp = int(time.time())
        announce = Announce(
            node_id=node.node_id,
            announce_seq=1,
            collections=collections,
            timestamp=timestamp,
            expires_at=timestamp + 3600,
            signature=b"",
        )
        announce.signature = sign_message(announce.to_signable_dict(), node.private_key)

        # Broadcast to all connected peers
        for peer_id in node.connected_peers:
            target_idx = self._find_node_by_peer_id(peer_id)
            if target_idx is not None:
                self.send_message(node_index, target_idx, announce)

    def _find_node_by_peer_id(self, peer_id: bytes) -> Optional[int]:
        """Find node index by peer ID."""
        for i, node in enumerate(self.nodes):
            if node.node_id == peer_id:
                return i
        return None

    def get_message_log(self) -> list[MessageLogEntry]:
        """Get the message log."""
        return self.message_log.copy()

    def stats(self) -> dict[str, object]:
        """Get statistics about the test run."""
        total_messages = len(self.message_log)
        successful_messages = sum(1 for e in self.message_log if e.success)

        message_type_counts: dict[MessageType, int] = {}
        for entry in self.message_log:
            message_type_counts[entry.message_type] = (
                message_type_counts.get(entry.message_type, 0) + 1
            )

        return {
            "total_messages": total_messages,
            "successful_messages": successful_messages,
            "message_type_counts": message_type_counts,
        }


@dataclass
class StepResult:
    """Result of a single step."""

    step_index: int
    success: bool
    duration: float
    error: Optional[str] = None


@dataclass
class TestScenarioResult:
    """Result of running a test scenario."""

    name: str
    step_results: list[StepResult]
    stats: dict[str, object]

    def all_passed(self) -> bool:
        """Check if all steps passed."""
        return all(s.success for s in self.step_results)


class TestScenario:
    """Test scenario runner."""

    def __init__(self, name: str, config: TestNetworkConfig):
        self.name = name
        self.network = TestNetwork(config)
        self.steps: list[Callable[[TestNetwork], None]] = []

    def step(self, func: Callable[[TestNetwork], None]) -> "TestScenario":
        """Add a step to the scenario."""
        self.steps.append(func)
        return self

    def run(self) -> TestScenarioResult:
        """Run the scenario."""
        print(f"Running scenario: {self.name}")

        self.network.start()
        self.network.connect_all()

        step_results = []
        for i, step_func in enumerate(self.steps):
            start_time = time.time()
            error = None
            success = True

            try:
                step_func(self.network)
            except Exception as e:
                success = False
                error = str(e)

            duration = time.time() - start_time
            step_results.append(
                StepResult(
                    step_index=i,
                    success=success,
                    duration=duration,
                    error=error,
                )
            )

        self.network.stop()

        return TestScenarioResult(
            name=self.name,
            step_results=step_results,
            stats=self.network.stats(),
        )


def run_basic_p2p_test(num_nodes: int = 5) -> TestScenarioResult:
    """Run a basic P2P test scenario."""
    config = TestNetworkConfig(
        num_nodes=num_nodes,
        num_collections=2,
        guardians_per_collection=3,
    )

    scenario = TestScenario("basic_p2p_test", config)

    def handshake_all(network: TestNetwork) -> None:
        for i in range(network.num_nodes()):
            for j in range(i + 1, network.num_nodes()):
                network.handshake(i, j)

    def announce_all(network: TestNetwork) -> None:
        for i in range(network.num_nodes()):
            network.announce_collection(i)

    def verify_message_delivery(network: TestNetwork) -> None:
        for node in network.nodes:
            # Each node should have received messages from all others
            assert len(node.received_messages) > 0, (
                f"Node {node.index} did not receive any messages"
            )

    scenario.step(handshake_all)
    scenario.step(announce_all)
    scenario.step(verify_message_delivery)

    return scenario.run()


def run_stress_test(
    num_nodes: int = 10,
    num_messages: int = 100,
) -> TestScenarioResult:
    """Run a stress test with many messages."""
    config = TestNetworkConfig(
        num_nodes=num_nodes,
        num_collections=5,
        guardians_per_collection=num_nodes,
    )

    scenario = TestScenario("stress_test", config)

    def connect_and_handshake(network: TestNetwork) -> None:
        for i in range(network.num_nodes()):
            for j in range(i + 1, network.num_nodes()):
                network.handshake(i, j)

    def send_many_messages(network: TestNetwork) -> None:
        for _ in range(num_messages):
            from_idx = random.randint(0, network.num_nodes() - 1)
            to_idx = random.randint(0, network.num_nodes() - 1)
            while to_idx == from_idx:
                to_idx = random.randint(0, network.num_nodes() - 1)

            hello = Hello(
                version=Hello.DEFAULT_VERSION,
                node_id=network.nodes[from_idx].node_id,
                capabilities=[Capability.GUARDIAN],
                collections=[],
                timestamp=int(time.time()),
            )
            network.send_message(from_idx, to_idx, hello)

    def verify_throughput(network: TestNetwork) -> None:
        stats = network.stats()
        total_messages = cast(int, stats.get("total_messages", 0))
        assert total_messages >= num_messages, (
            f"Expected at least {num_messages} messages, got {total_messages}"
        )

    scenario.step(connect_and_handshake)
    scenario.step(send_many_messages)
    scenario.step(verify_throughput)

    return scenario.run()


def run_partition_test(num_nodes: int = 6) -> TestScenarioResult:
    """Run a network partition test."""
    config = TestNetworkConfig(
        num_nodes=num_nodes,
        num_collections=1,
        guardians_per_collection=num_nodes,
        packet_loss_rate=0.5,  # 50% packet loss
    )

    scenario = TestScenario("partition_test", config)

    def attempt_communication(network: TestNetwork) -> None:
        # Try to communicate despite packet loss
        for i in range(network.num_nodes()):
            for j in range(i + 1, network.num_nodes()):
                network.handshake(i, j)

    def verify_partial_delivery(network: TestNetwork) -> None:
        stats = network.stats()
        # With 50% packet loss, we expect roughly half the messages to get through
        # But due to randomness, we just check that some got through
        successful_messages = cast(int, stats.get("successful_messages", 0))
        assert successful_messages > 0, "Expected at least some messages to be delivered"

    scenario.step(attempt_communication)
    scenario.step(verify_partial_delivery)

    return scenario.run()
