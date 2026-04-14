"""
DCPP Test Client

A simple client for testing DCPP daemons and validating
interoperability between implementations.

Usage:
    python -m dcpp_python.client --host 127.0.0.1 --port 4001 hello
    python -m dcpp_python.client get-peers eth:0xBC4CA0
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys
import time

import cbor2

from dcpp_python.core.constants import MAGIC_BYTES, MessageType, Capability, PROTOCOL_ID
from dcpp_python.crypto.signing import generate_keypair, derive_peer_id
from dcpp_python.core.framing import Profile1Framer
from dcpp_python.core.messages import (
    Hello,
    GetManifest,
    GetPeers,
    Goodbye,
    HealthProbe,
    Challenge,
    decode_message,
    MessageBase,
    ErrorResponse,
)


class DCPPClient:
    """Simple DCPP client for testing."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 4001,
        timeout: float = 10.0,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket: socket.socket | None = None
        self.signing_key, self.verify_key = generate_keypair()

    def connect(self) -> None:
        """Connect to the DCPP daemon."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)
        self.socket.connect((self.host, self.port))
        print(f"Connected to {self.host}:{self.port}")

    def close(self) -> None:
        """Close the connection."""
        if self.socket:
            self.socket.close()
            self.socket = None

    def send_message(self, message_type: MessageType, payload: dict[str, object]) -> None:
        """Send a framed message."""
        if not self.socket:
            raise RuntimeError("Not connected")

        frame = Profile1Framer.encode(message_type, payload)

        print(f">> Sending {message_type.name} ({len(frame)} bytes)")
        self.socket.sendall(frame)

    def receive_message(self) -> tuple[MessageType, MessageBase] | None:
        """Receive and decode a framed message."""
        if not self.socket:
            raise RuntimeError("Not connected")

        # Read enough data for the header
        # Profile 1: 20 byte header (magic + version + type + request_id + length + crc)
        header = self._recv_exactly(Profile1Framer.HEADER_SIZE)  # 20 bytes
        if not header:
            return None

        # Verify magic
        if header[:4] != MAGIC_BYTES:
            raise ValueError(f"Invalid magic bytes: {header[:4]!r}")

        # Verify version (only accept v1.0 exactly)
        version = struct.unpack(">H", header[4:6])[0]
        if version != 0x0100:
            raise ValueError(f"Unsupported protocol version: 0x{version:04X}")

        # Extract length (at offset 12, not 8)
        length = struct.unpack(">I", header[12:16])[0]

        # Read payload
        payload_bytes = self._recv_exactly(length)

        # Decode frame
        frame = Profile1Framer.decode(header + payload_bytes)

        print(f"<< Received {frame.message_type.name} ({len(frame.payload)} bytes payload)")

        # Decode the message
        message = decode_message(frame.message_type, frame.payload)
        return (frame.message_type, message)

    def _recv_exactly(self, n: int) -> bytes:
        """Receive exactly n bytes."""
        sock = self.socket
        if sock is None:
            raise ConnectionError("Not connected")

        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def send_hello(self, collections: list[str] | None = None) -> tuple[MessageType, MessageBase] | None:
        """Send HELLO and receive response."""
        hello = Hello(
            version=Hello.DEFAULT_VERSION,
            node_id=derive_peer_id(self.verify_key),
            capabilities=[Capability.GUARDIAN, Capability.SEEDER],
            collections=collections or [],
            timestamp=int(time.time()),
            user_agent="dcpp-py-client/0.1.0",
        )

        self.send_message(MessageType.HELLO, dict(hello.to_dict()))
        result = self.receive_message()

        if result:
            msg_type, message = result
            print(f"   Response: {msg_type.name}")
            if hasattr(message, "node_id"):
                print(f"     Node ID: {message.node_id[:8].hex()}")
            if hasattr(message, "capabilities"):
                print(f"     Capabilities: {message.capabilities}")
            if hasattr(message, "user_agent") and message.user_agent:
                print(f"     User Agent: {message.user_agent}")

        return result

    def send_get_peers(self, collection_id: str, max_peers: int = 20) -> tuple[MessageType, MessageBase] | None:
        """Send GET_PEERS and receive response."""
        get_peers = GetPeers(
            collection_id=collection_id,
            max_peers=max_peers,
        )

        self.send_message(MessageType.GET_PEERS, dict(get_peers.to_dict()))
        result = self.receive_message()

        if result:
            msg_type, message = result
            print(f"   Response: {msg_type.name}")
            if hasattr(message, "peers"):
                print(f"     Peers: {len(message.peers)}")
                for i, peer in enumerate(message.peers):
                    print(f"       [{i}] {peer.node_id[:8].hex()} - {peer.coverage * 100:.0f}%")

        return result

    def send_get_manifest(self, collection_id: str) -> tuple[MessageType, MessageBase] | None:
        """Send GET_MANIFEST and receive response."""
        get_manifest = GetManifest(collection_id=collection_id)

        self.send_message(MessageType.GET_MANIFEST, dict(get_manifest.to_dict()))
        result = self.receive_message()

        if result:
            msg_type, message = result
            print(f"   Response: {msg_type.name}")
            if msg_type == MessageType.ERROR and isinstance(message, ErrorResponse):
                print(f"     Error: {message.code} - {message.message}")

        return result

    def send_health_probe(self, collection_id: str) -> tuple[MessageType, MessageBase] | None:
        """Send HEALTH_PROBE and receive response."""
        import os

        challenges = [
            Challenge(cid="QmTest1", offset=0, length=256),
            Challenge(cid="QmTest2", offset=1024, length=512),
        ]

        probe = HealthProbe(
            collection_id=collection_id,
            challenges=challenges,
            nonce=os.urandom(16),
        )

        self.send_message(MessageType.HEALTH_PROBE, dict(probe.to_dict()))
        result = self.receive_message()

        if result:
            msg_type, message = result
            print(f"   Response: {msg_type.name}")
            if hasattr(message, "responses"):
                print(f"     Challenges answered: {len(message.responses)}")
                for r in message.responses:
                    if r.data:
                        print(f"       {r.cid}: {len(r.data)} bytes")
                    elif r.error:
                        print(f"       {r.cid}: ERROR - {r.error}")

        return result

    def send_goodbye(self) -> None:
        """Send GOODBYE (no response expected)."""
        goodbye = Goodbye(reason="shutdown")
        self.send_message(MessageType.GOODBYE, dict(goodbye.to_dict()))


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="dcpp-client",
        description="DCPP Test Client",
    )
    parser.add_argument("--host", "-H", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", "-p", type=int, default=4001, help="Server port")
    parser.add_argument(
        "command",
        choices=["hello", "get-peers", "get-manifest", "health-probe", "goodbye", "benchmark"],
    )
    parser.add_argument("args", nargs="*", help="Command arguments")

    args = parser.parse_args()

    client = DCPPClient(
        host=args.host,
        port=args.port,
    )

    print(f"DCPP Client ({PROTOCOL_ID})")
    print(f"Connecting to {args.host}:{args.port}...")
    print("Using framing: Profile 1")
    print()

    try:
        client.connect()

        if args.command == "hello":
            collections = args.args if args.args else []
            client.send_hello(collections)

        elif args.command == "get-peers":
            if not args.args:
                print("Usage: get-peers <collection_id>")
                return 1
            # Send HELLO first
            client.send_hello()
            client.send_get_peers(args.args[0])

        elif args.command == "get-manifest":
            if not args.args:
                print("Usage: get-manifest <collection_id>")
                return 1
            # Send HELLO first
            client.send_hello()
            client.send_get_manifest(args.args[0])

        elif args.command == "health-probe":
            if not args.args:
                print("Usage: health-probe <collection_id>")
                return 1
            # Send HELLO first
            client.send_hello()
            client.send_health_probe(args.args[0])

        elif args.command == "goodbye":
            client.send_hello()
            client.send_goodbye()
            print("Sent GOODBYE")

        elif args.command == "benchmark":
            iterations = int(args.args[0]) if args.args else 100
            print(f"Benchmarking {iterations} HELLO roundtrips...")

            start = time.time()
            for i in range(iterations):
                client.send_hello([f"test:{i}"])
            elapsed = time.time() - start

            print(f"Completed {iterations} roundtrips in {elapsed:.3f}s")
            print(f"Average: {elapsed / iterations * 1000:.2f}ms per roundtrip")

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1

    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
