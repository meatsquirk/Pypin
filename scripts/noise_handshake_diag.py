#!/usr/bin/env python3
"""
Noise Handshake Wire Diagnostic

Connects to a libp2p peer (Python or Rust) and performs the multistream-select
+ Noise XX handshake manually, dumping every byte on the wire.

Usage:
    # As initiator connecting to a rust-libp2p node:
    python scripts/noise_handshake_diag.py --connect /ip4/127.0.0.1/tcp/9000

    # As responder waiting for a connection:
    python scripts/noise_handshake_diag.py --listen /ip4/0.0.0.0/tcp/9000

    # With extra verbosity (dump full hex of every message):
    python scripts/noise_handshake_diag.py --connect /ip4/127.0.0.1/tcp/9000 -v
"""

import argparse
import asyncio
import os
import struct
import sys
import traceback
from typing import Tuple


# Ensure project is on path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ---------------------------------------------------------------------------
# colour helpers (no dependency)
# ---------------------------------------------------------------------------
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _tx(msg: str) -> str:
    return f"{_GREEN}>> TX{_RESET} {msg}"


def _rx(msg: str) -> str:
    return f"{_CYAN}<< RX{_RESET} {msg}"


def _info(msg: str) -> str:
    return f"{_DIM}-- {msg}{_RESET}"


def _err(msg: str) -> str:
    return f"{_RED}!! {msg}{_RESET}"


def _ok(msg: str) -> str:
    return f"{_GREEN}OK {msg}{_RESET}"


def _fail(msg: str) -> str:
    return f"{_RED}FAIL {msg}{_RESET}"


def hexdump(data: bytes, prefix: str = "   ") -> str:
    """Pretty hex dump with ASCII sidebar."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:04x}  {hex_part:<48s}  |{ascii_part}|")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Raw TCP I/O wrappers
# ---------------------------------------------------------------------------
class WireConn:
    """Thin wrapper around asyncio streams with byte-counting."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        verbose: bool = False,
    ):
        self.reader = reader
        self.writer = writer
        self.verbose = verbose
        self.tx_bytes = 0
        self.rx_bytes = 0

    async def read_exactly(self, n: int) -> bytes:
        data = await self.reader.readexactly(n)
        self.rx_bytes += len(data)
        return data

    async def write(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()
        self.tx_bytes += len(data)

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()


# ---------------------------------------------------------------------------
# Multistream-select 1.0
# ---------------------------------------------------------------------------
MULTISTREAM_PROTO = b"/multistream/1.0.0\n"
NOISE_PROTO = b"/noise\n"


def encode_multistream_msg(proto: bytes) -> bytes:
    """varint-length-prefixed multistream message."""
    length = len(proto)
    # simple varint encode (works for < 128)
    if length < 128:
        return bytes([length]) + proto
    # full varint for larger
    parts = []
    while length > 0:
        byte = length & 0x7F
        length >>= 7
        if length > 0:
            byte |= 0x80
        parts.append(byte)
    return bytes(parts) + proto


async def read_varint(conn: WireConn) -> int:
    """Read an unsigned varint from the stream."""
    result = 0
    shift = 0
    while True:
        b = (await conn.read_exactly(1))[0]
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")
    return result


async def read_multistream_msg(conn: WireConn) -> bytes:
    length = await read_varint(conn)
    data = await conn.read_exactly(length)
    return data


async def do_multistream_select(conn: WireConn, is_initiator: bool) -> bool:
    """Perform multistream-select and negotiate /noise. Returns True on success."""
    print(_info("=== Multistream-Select ==="))

    if is_initiator:
        # Send our multistream header
        msg = encode_multistream_msg(MULTISTREAM_PROTO)
        print(_tx(f"multistream header ({len(msg)} bytes)"))
        if conn.verbose:
            print(hexdump(msg))
        await conn.write(msg)

        # Read their multistream header
        resp = await read_multistream_msg(conn)
        print(_rx(f"multistream header: {resp!r} ({len(resp)} bytes)"))
        if resp != MULTISTREAM_PROTO.rstrip(b"\n") and resp != MULTISTREAM_PROTO:
            # Some implementations include the newline, some don't
            if resp.rstrip(b"\n") != MULTISTREAM_PROTO.rstrip(b"\n"):
                print(_err(f"Unexpected multistream header: {resp!r}"))
                print(
                    _err(f"Expected: {MULTISTREAM_PROTO!r} or {MULTISTREAM_PROTO.rstrip(b'n')!r}")
                )
                return False

        # Propose /noise
        msg = encode_multistream_msg(NOISE_PROTO)
        print(_tx(f"/noise proposal ({len(msg)} bytes)"))
        if conn.verbose:
            print(hexdump(msg))
        await conn.write(msg)

        # Read their response
        resp = await read_multistream_msg(conn)
        print(_rx(f"response: {resp!r}"))
        if resp.rstrip(b"\n") != b"/noise":
            print(_err("Remote rejected /noise!"))
            return False
        print(_ok("/noise negotiated"))
    else:
        # Responder: read their header first
        resp = await read_multistream_msg(conn)
        print(_rx(f"multistream header: {resp!r}"))

        # Send our header
        msg = encode_multistream_msg(MULTISTREAM_PROTO)
        print(_tx(f"multistream header ({len(msg)} bytes)"))
        await conn.write(msg)

        # Read their protocol proposal
        resp = await read_multistream_msg(conn)
        print(_rx(f"proposal: {resp!r}"))

        if resp.rstrip(b"\n") == b"/noise":
            # Accept
            msg = encode_multistream_msg(NOISE_PROTO)
            print(_tx(f"accepting /noise ({len(msg)} bytes)"))
            await conn.write(msg)
            print(_ok("/noise negotiated"))
        else:
            print(_err(f"Unexpected proposal: {resp!r}"))
            return False

    return True


# ---------------------------------------------------------------------------
# Noise XX Handshake
# ---------------------------------------------------------------------------


def read_noise_frame_length(data: bytes) -> int:
    """2-byte big-endian noise frame length."""
    return struct.unpack("!H", data)[0]


async def read_noise_msg(conn: WireConn) -> bytes:
    """Read a 2-byte-BE-length-prefixed noise message."""
    len_bytes = await conn.read_exactly(2)
    length = struct.unpack("!H", len_bytes)[0]
    payload = await conn.read_exactly(length)
    return payload


async def write_noise_msg(conn: WireConn, data: bytes) -> None:
    """Write a 2-byte-BE-length-prefixed noise message."""
    frame = struct.pack("!H", len(data)) + data
    await conn.write(frame)


def parse_handshake_payload(decrypted: bytes) -> dict:
    """Parse the NoiseHandshakePayload protobuf (best-effort)."""
    result = {}
    try:
        from libp2p.security.noise.pb import noise_pb2

        msg = noise_pb2.NoiseHandshakePayload.FromString(decrypted)

        if msg.identity_key:
            result["identity_key_raw"] = msg.identity_key
            # Parse the inner PublicKey protobuf
            try:
                from libp2p.crypto.pb import crypto_pb2

                pk = crypto_pb2.PublicKey.FromString(msg.identity_key)
                result["identity_key_type"] = pk.key_type
                result["identity_key_data"] = pk.data
                result["identity_key_data_len"] = len(pk.data)

                # key_type: 0=RSA, 1=Ed25519, 2=Secp256k1, 3=ECDSA
                type_names = {0: "RSA", 1: "Ed25519", 2: "Secp256k1", 3: "ECDSA"}
                result["identity_key_type_name"] = type_names.get(
                    pk.key_type, f"Unknown({pk.key_type})"
                )
            except Exception as e:
                result["identity_key_parse_error"] = str(e)

        if msg.identity_sig:
            result["identity_sig"] = msg.identity_sig
            result["identity_sig_len"] = len(msg.identity_sig)

        if hasattr(msg, "data") and msg.data:
            result["early_data"] = msg.data
            result["early_data_len"] = len(msg.data)

    except Exception as e:
        result["parse_error"] = str(e)
        result["raw_decrypted"] = decrypted

    return result


async def do_noise_handshake(conn: WireConn, is_initiator: bool, verbose: bool = False) -> bool:
    """
    Perform the Noise XX handshake, logging every message.

    Returns True if the handshake completes successfully.
    """
    print()
    print(_info("=== Noise XX Handshake ==="))
    print(_info("Pattern: Noise_XX_25519_ChaChaPoly_SHA256"))
    print(_info(f"Role: {'initiator' if is_initiator else 'responder'}"))

    try:
        from cryptography.hazmat.primitives import serialization as crypto_ser
        from cryptography.hazmat.primitives.asymmetric import x25519
        from noise.connection import Keypair as NoiseKeypairEnum
        from noise.connection import NoiseConnection
    except ImportError as e:
        print(_err(f"Missing dependency: {e}"))
        return False

    # Generate our noise static key
    noise_privkey = x25519.X25519PrivateKey.generate()
    noise_pubkey = noise_privkey.public_key()
    noise_pub_bytes = noise_pubkey.public_bytes(
        crypto_ser.Encoding.Raw, crypto_ser.PublicFormat.Raw
    )
    noise_priv_bytes = noise_privkey.private_bytes(
        crypto_ser.Encoding.Raw,
        crypto_ser.PrivateFormat.Raw,
        crypto_ser.NoEncryption(),
    )
    print(_info(f"Local noise static pubkey: {noise_pub_bytes.hex()}"))

    # Generate Ed25519 identity key
    try:
        from nacl.signing import SigningKey

        id_sk = SigningKey.generate()
        id_pk_bytes = bytes(id_sk.verify_key)
        print(_info(f"Local Ed25519 identity pubkey: {id_pk_bytes.hex()}"))
    except ImportError:
        print(_err("PyNaCl not available"))
        return False

    # Build the handshake payload
    def make_payload_bytes() -> bytes:
        """Build the NoiseHandshakePayload protobuf."""
        # Sign: "noise-libp2p-static-key:" + X25519_noise_pubkey
        prefix = b"noise-libp2p-static-key:"
        data_to_sign = prefix + noise_pub_bytes
        sig = id_sk.sign(data_to_sign).signature  # 64 bytes

        # Build inner PublicKey protobuf
        from libp2p.crypto.pb import crypto_pb2

        inner_pk = crypto_pb2.PublicKey(key_type=1, data=id_pk_bytes)  # 1 = Ed25519
        inner_pk_bytes = inner_pk.SerializeToString()

        # Build NoiseHandshakePayload
        from libp2p.security.noise.pb import noise_pb2

        payload = noise_pb2.NoiseHandshakePayload(identity_key=inner_pk_bytes, identity_sig=sig)
        return payload.SerializeToString()

    our_payload = make_payload_bytes()
    print(_info(f"Local handshake payload: {len(our_payload)} bytes"))

    # Initialize Noise state
    ns = NoiseConnection.from_name(b"Noise_XX_25519_ChaChaPoly_SHA256")
    ns.set_keypair_from_private_bytes(NoiseKeypairEnum.STATIC, noise_priv_bytes)

    if is_initiator:
        ns.set_as_initiator()
    else:
        ns.set_as_responder()
    ns.start_handshake()

    handshake_state = ns.noise_protocol.handshake_state
    print(_info("Noise state initialized, handshake started"))

    try:
        if is_initiator:
            # === MSG #1: initiator -> responder (ephemeral key, no payload) ===
            print()
            print(_info("--- msg#1 (initiator -> responder) ---"))
            msg1_ct = ns.write_message(b"")
            print(_tx(f"noise message: {len(msg1_ct)} bytes"))
            if verbose:
                print(hexdump(msg1_ct))
            await write_noise_msg(conn, msg1_ct)

            # === MSG #2: responder -> initiator (e, ee, s, es + payload) ===
            print()
            print(_info("--- msg#2 (responder -> initiator) ---"))
            msg2_raw = await read_noise_msg(conn)
            print(_rx(f"noise message: {len(msg2_raw)} bytes"))
            if verbose:
                print(hexdump(msg2_raw))

            try:
                msg2_pt = bytes(ns.read_message(msg2_raw))
                print(_ok(f"decrypted payload: {len(msg2_pt)} bytes"))
                if verbose:
                    print(hexdump(msg2_pt))

                # Parse the handshake payload
                payload_info = parse_handshake_payload(msg2_pt)
                print_payload_info("Remote", payload_info, verbose)

                # Verify the signature
                verify_remote_payload(payload_info, handshake_state, verbose)

            except Exception as e:
                print(_fail(f"msg#2 decrypt/parse failed: {e}"))
                print(_err(traceback.format_exc()))
                return False

            # === MSG #3: initiator -> responder (s, se + payload) ===
            print()
            print(_info("--- msg#3 (initiator -> responder) ---"))
            msg3_ct = ns.write_message(our_payload)
            print(_tx(f"noise message: {len(msg3_ct)} bytes (payload={len(our_payload)})"))
            if verbose:
                print(hexdump(msg3_ct))
            await write_noise_msg(conn, msg3_ct)

        else:
            # Responder flow
            # === MSG #1: initiator -> responder ===
            print()
            print(_info("--- msg#1 (initiator -> responder) ---"))
            msg1_raw = await read_noise_msg(conn)
            print(_rx(f"noise message: {len(msg1_raw)} bytes"))
            if verbose:
                print(hexdump(msg1_raw))

            try:
                msg1_pt = bytes(ns.read_message(msg1_raw))
                print(
                    _ok(f"decrypted (should be empty): {len(msg1_pt)} bytes, content={msg1_pt!r}")
                )
            except Exception as e:
                print(_fail(f"msg#1 decrypt failed: {e}"))
                print(_err(traceback.format_exc()))
                return False

            # === MSG #2: responder -> initiator ===
            print()
            print(_info("--- msg#2 (responder -> initiator) ---"))
            msg2_ct = ns.write_message(our_payload)
            print(_tx(f"noise message: {len(msg2_ct)} bytes (payload={len(our_payload)})"))
            if verbose:
                print(hexdump(msg2_ct))
            await write_noise_msg(conn, msg2_ct)

            # === MSG #3: initiator -> responder ===
            print()
            print(_info("--- msg#3 (initiator -> responder) ---"))
            msg3_raw = await read_noise_msg(conn)
            print(_rx(f"noise message: {len(msg3_raw)} bytes"))
            if verbose:
                print(hexdump(msg3_raw))

            try:
                msg3_pt = bytes(ns.read_message(msg3_raw))
                print(_ok(f"decrypted payload: {len(msg3_pt)} bytes"))
                if verbose:
                    print(hexdump(msg3_pt))

                payload_info = parse_handshake_payload(msg3_pt)
                print_payload_info("Remote", payload_info, verbose)
                verify_remote_payload(payload_info, handshake_state, verbose)

            except Exception as e:
                print(_fail(f"msg#3 decrypt/parse failed: {e}"))
                print(_err(traceback.format_exc()))
                return False

    except asyncio.IncompleteReadError as e:
        print(_fail(f"Connection closed mid-handshake (read {len(e.partial)} of expected bytes)"))
        if e.partial:
            print(_err("Partial data received:"))
            print(hexdump(e.partial))
        return False
    except Exception as e:
        print(_fail(f"Handshake error: {e}"))
        print(_err(traceback.format_exc()))
        return False

    if ns.handshake_finished:
        print()
        print(_ok("Noise handshake completed successfully!"))
        return True
    else:
        print()
        print(_fail("Noise state says handshake NOT finished"))
        return False


def print_payload_info(label: str, info: dict, verbose: bool) -> None:
    """Pretty-print parsed handshake payload."""
    print(_info(f"{label} handshake payload:"))
    if "parse_error" in info:
        print(_err(f"  Parse error: {info['parse_error']}"))
        if "raw_decrypted" in info and verbose:
            print(hexdump(info["raw_decrypted"], prefix="    "))
        return

    if "identity_key_type_name" in info:
        print(
            f"  identity key type: {info['identity_key_type_name']} (value={info['identity_key_type']})"
        )
        print(f"  identity key data: {info['identity_key_data_len']} bytes")
        if verbose and "identity_key_data" in info:
            print(f"  identity key hex:  {info['identity_key_data'].hex()}")
    if "identity_key_raw" in info:
        print(f"  identity key (serialized PublicKey pb): {len(info['identity_key_raw'])} bytes")
        if verbose:
            print(hexdump(info["identity_key_raw"], prefix="    "))

    if "identity_sig_len" in info:
        print(f"  identity sig: {info['identity_sig_len']} bytes")
        if info["identity_sig_len"] != 64:
            print(
                _err(f"  EXPECTED 64 bytes for Ed25519 signature, got {info['identity_sig_len']}!")
            )
        if verbose and "identity_sig" in info:
            print(f"  sig hex: {info['identity_sig'].hex()}")

    if "early_data_len" in info:
        print(f"  early data: {info['early_data_len']} bytes")


def verify_remote_payload(info: dict, handshake_state: object, verbose: bool) -> None:
    """Attempt to verify the remote's handshake payload signature."""
    print(_info("Verifying remote signature:"))

    if "identity_key_data" not in info or "identity_sig" not in info:
        print(_err("  Cannot verify: missing identity key or signature"))
        return

    # Get the remote's noise static key from the handshake state
    rs = getattr(handshake_state, "rs", None)
    if rs is None:
        print(_err("  Cannot verify: remote static key not yet available in handshake state"))
        return

    try:
        from cryptography.hazmat.primitives import serialization as crypto_ser

        remote_noise_pub_bytes = rs.public.public_bytes(
            crypto_ser.Encoding.Raw, crypto_ser.PublicFormat.Raw
        )
        print(f"  remote noise static key (X25519): {remote_noise_pub_bytes.hex()}")
    except Exception as e:
        # Fallback: try public_bytes attribute directly
        remote_noise_pub_bytes = getattr(rs, "public_bytes", None)
        if remote_noise_pub_bytes:
            print(f"  remote noise static key (X25519): {remote_noise_pub_bytes.hex()}")
        else:
            print(_err(f"  Cannot extract remote noise static key: {e}"))
            return

    # Reconstruct the signed data
    prefix = b"noise-libp2p-static-key:"
    expected_data = prefix + remote_noise_pub_bytes
    print(f"  signed data: {prefix.decode()}<{len(remote_noise_pub_bytes)} bytes>")
    if verbose:
        print(f"  full signed data hex: {expected_data.hex()}")

    # Verify with Ed25519
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        vk = VerifyKey(info["identity_key_data"])
        sig = info["identity_sig"]

        try:
            vk.verify(expected_data, sig)
            print(_ok("  Signature VALID"))
        except BadSignatureError:
            print(_fail("  Signature INVALID"))
            print(_err("  The remote's signature does not verify against the expected data."))
            print(_err("  This means either:"))
            print(_err("    1. The signing key doesn't match the identity key in the payload"))
            print(_err("    2. The signed data differs (different noise static key bytes?)"))
            print(_err("    3. The signature format is wrong (e.g., SHA256 pre-hashed)"))
        except Exception as e:
            print(_fail(f"  Verify raised: {e}"))
    except ImportError:
        print(_err("  PyNaCl not available for signature verification"))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def parse_multiaddr(ma_str: str) -> Tuple[str, int]:
    """Extract host and port from a multiaddr string."""
    parts = ma_str.strip("/").split("/")
    host = None
    port = None
    i = 0
    while i < len(parts):
        if parts[i] in ("ip4", "ip6"):
            host = parts[i + 1]
            i += 2
        elif parts[i] == "tcp":
            port = int(parts[i + 1])
            i += 2
        else:
            i += 1
    if host is None or port is None:
        raise ValueError(f"Cannot parse multiaddr: {ma_str} (need /ip4/HOST/tcp/PORT)")
    return host, port


async def run_initiator(host: str, port: int, verbose: bool) -> None:
    print(_info(f"Connecting to {host}:{port} ..."))
    reader, writer = await asyncio.open_connection(host, port)
    conn = WireConn(reader, writer, verbose)
    print(_ok(f"TCP connected to {host}:{port}"))

    try:
        if not await do_multistream_select(conn, is_initiator=True):
            return
        await do_noise_handshake(conn, is_initiator=True, verbose=verbose)
    finally:
        print()
        print(_info(f"Total bytes: TX={conn.tx_bytes}, RX={conn.rx_bytes}"))
        await conn.close()


async def run_responder(host: str, port: int, verbose: bool) -> None:
    print(_info(f"Listening on {host}:{port} ..."))

    event = asyncio.Event()

    async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = writer.get_extra_info("peername")
        print(_ok(f"Accepted connection from {addr}"))
        conn = WireConn(reader, writer, verbose)
        try:
            if not await do_multistream_select(conn, is_initiator=False):
                return
            await do_noise_handshake(conn, is_initiator=False, verbose=verbose)
        finally:
            print()
            print(_info(f"Total bytes: TX={conn.tx_bytes}, RX={conn.rx_bytes}"))
            await conn.close()
            event.set()

    server = await asyncio.start_server(handle_client, host, port)
    async with server:
        print(_info("Waiting for connection... (Ctrl+C to stop)"))
        await event.wait()


def main() -> None:
    parser = argparse.ArgumentParser(description="Noise handshake wire-level diagnostic tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--connect",
        metavar="MULTIADDR",
        help="Connect to a peer (e.g., /ip4/127.0.0.1/tcp/9000)",
    )
    group.add_argument(
        "--listen",
        metavar="MULTIADDR",
        help="Listen for a peer (e.g., /ip4/0.0.0.0/tcp/9000)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Full hex dumps of all messages"
    )
    args = parser.parse_args()

    print(f"{_BOLD}Noise Handshake Wire Diagnostic{_RESET}")
    print(f"{_BOLD}{'=' * 40}{_RESET}")

    if args.connect:
        host, port = parse_multiaddr(args.connect)
        asyncio.run(run_initiator(host, port, args.verbose))
    else:
        host, port = parse_multiaddr(args.listen)
        asyncio.run(run_responder(host, port, args.verbose))


if __name__ == "__main__":
    main()
