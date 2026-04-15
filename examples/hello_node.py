#!/usr/bin/env python3
"""
DCPP Hello Node Example

This example demonstrates how to create a basic DCPP node that connects
to another node and exchanges HELLO messages.

Usage:
    python examples/hello_node.py

Requirements:
    pip install -e .
"""

import time

from dcpp_python.core.framing import Profile1Framer
from dcpp_python.core.messages import Capability, Hello, MessageType
from dcpp_python.crypto.signing import derive_peer_id, generate_keypair


def create_hello_message() -> tuple[bytes, Hello]:
    """Create a HELLO message with a fresh identity."""
    # Generate a new keypair for this node
    signing_key, verify_key = generate_keypair()
    node_id = derive_peer_id(verify_key)

    print(f"Node ID: {node_id.hex()[:16]}...")

    # Create the HELLO message
    hello = Hello(
        version="1.0.0",
        node_id=node_id,
        capabilities=[Capability.GUARDIAN, Capability.SEEDER],
        collections=[
            "eth:0xBC4CA0EdC45dEA4Fc3cF2cE12a7a31E2A1E84631",  # BAYC
        ],
        timestamp=int(time.time()),
        user_agent="dcpp-example/0.1.0",
    )

    return node_id, hello


def encode_hello(hello: Hello) -> bytes:
    """Encode a HELLO message with Profile 1 framing."""
    # Convert message to CBOR payload
    payload = hello.to_dict()

    # Encode with full framing (magic bytes, CRC, etc.)
    framed = Profile1Framer.encode(MessageType.HELLO, payload)

    print(f"Encoded message: {len(framed)} bytes")
    print(f"  Header: {framed[:20].hex()}")
    print(f"  Magic: {framed[:4]}")

    return framed


def decode_hello(data: bytes) -> Hello:
    """Decode a framed HELLO message."""
    # Decode the frame (verifies CRC, magic bytes, etc.)
    frame = Profile1Framer.decode(data)

    print("Decoded frame:")
    print(f"  Message type: {frame.message_type.name}")
    print(f"  Request ID: {frame.request_id}")
    print(f"  Payload: {len(frame.payload)} bytes")

    # Parse the HELLO message
    hello = Hello.from_dict(frame.decode_payload())

    print(f"  Node ID: {hello.node_id.hex()[:16]}...")
    print(f"  Capabilities: {hello.capabilities}")
    print(f"  Collections: {hello.collections}")

    return hello


def main():
    """Main entry point."""
    print("=" * 60)
    print("DCPP Hello Node Example")
    print("=" * 60)
    print()

    # Create a HELLO message
    print("Creating HELLO message...")
    node_id, hello = create_hello_message()
    print()

    # Encode it
    print("Encoding with Profile 1 framing...")
    framed = encode_hello(hello)
    print()

    # Decode it back (round-trip test)
    print("Decoding (round-trip verification)...")
    decoded = decode_hello(framed)
    print()

    # Verify round-trip
    assert decoded.node_id == hello.node_id
    assert decoded.version == hello.version
    assert decoded.capabilities == hello.capabilities
    print("Round-trip successful!")
    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
