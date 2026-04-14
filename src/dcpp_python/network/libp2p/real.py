"""
libp2p Host Implementation for Python

This module provides a libp2p host implementation for DCPP with production-ready
APIs but PARTIAL network operations depending on py-libp2p availability.

IMPORTANT - Implementation Status:
    - API: Production-ready, matches Rust implementation
    - DHT operations: LOCAL CACHE via KademliaDHT (see dht_real.py)
    - GossipSub: LOCAL HANDLERS ONLY - publish() calls local callbacks
    - Peer connections: Requires py-libp2p to be installed

What works without py-libp2p:
    - RealHostConfig - Configuration objects
    - HostEvent / HostEventData - Event types and data structures
    - Topic subscription tracking
    - Local message handler registration

What works with py-libp2p installed:
    - TCP transport with Noise encryption
    - Ed25519 identity generation
    - Peer connections
    - DCPP stream handler (`/dcpp/1.0.0`) with Profile 1 framing

What requires additional wiring:
    - GossipSub network publishing (currently local-only)
    - Real Kademlia DHT queries (currently local cache)

To check if py-libp2p is available:
    from dcpp_python.libp2p_real import is_available
    if is_available():
        # Full networking available
    else:
        # Local-only mode

Features:
- Ed25519 identity
- TCP transport with Noise encryption (requires py-libp2p)
- Kademlia DHT integration (local cache + ready for real DHT)
- GossipSub topic management (local handlers + ready for real pubsub)
- DCPP protocol stream handler (`/dcpp/1.0.0`) with Profile 1 framing
"""

import asyncio
import functools
import inspect
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncContextManager, Awaitable, Callable, Dict, List, Optional, Protocol, Set, Tuple, Type, TYPE_CHECKING, cast

# Trio support for libp2p 0.5.0+
try:
    import trio

    TRIO_AVAILABLE = True
except ImportError:
    TRIO_AVAILABLE = False
    trio = None  # type: ignore

from dcpp_python.core.constants import PROTOCOL_ID, MAX_MESSAGE_SIZE, MAGIC_BYTES
from dcpp_python.core.messages import MessageType
from dcpp_python.core.framing import (
    DCPPFramer,
    ChecksumError,
    MagicBytesError,
    FramingError,
    MessageTooLargeError,
)
from dcpp_python.network.interfaces import HostProtocol, StreamProtocol, StreamHandler
from dcpp_python.network.dht.base import ProviderRecord
from dcpp_python.core.utils import decode_uint32_be, decode_uint16_be
from dcpp_python.network.dht.kademlia import (
    KademliaDHT,
    DHTCommand,
    DHTCommandType,
    DHTResponse,
    BootstrapConfig,
    derive_dht_key,
)
from dcpp_python.crypto.peer_id import format_peer_id

if TYPE_CHECKING:
    from trio.lowlevel import TrioToken


class KadDHTProtocol(Protocol):
    async def provide(self, key: str) -> None:
        ...

    async def find_providers(self, key: str) -> list[object]:
        ...

    async def put_value(self, key: str, value: bytes) -> None:
        ...

    async def get_value(self, key: str) -> Optional[bytes]:
        ...

    def add_address(self, peer_id: bytes, multiaddr: str) -> None:
        ...

    def bootstrap(self) -> None:
        ...


class PubSubProtocol(Protocol):
    async def publish(self, topic: str, data: bytes) -> None:
        ...

    async def subscribe(self, topic: str) -> object:
        ...

    async def unsubscribe(self, topic: str) -> None:
        ...


class PubsubValidatorsProtocol(Protocol):
    signature_validator: Callable[[object], bool]
    PUBSUB_SIGNING_PREFIX: str

    def set_validator_host(self, host: object) -> None:
        ...


class PeerInfoProtocol(Protocol):
    peer_id: object


class PeerIDFactory(Protocol):
    def __call__(self, peer_id: bytes) -> object:
        ...


class MultiaddrFactory(Protocol):
    def __call__(self, addr: str) -> object:
        ...


class InfoFromP2PAddrProtocol(Protocol):
    def __call__(self, addr: object) -> PeerInfoProtocol:
        ...



class Libp2pHostProtocol(Protocol):
    def get_id(self) -> object:
        ...

    def set_stream_handler(self, protocol_id: object, handler: StreamHandler) -> None:
        ...

    def get_transport_addrs(self) -> list[object]:
        ...

    def run(self, listen_addrs: list[object]) -> AsyncContextManager[None]:
        ...

    async def connect(self, peer_info: object) -> None:
        ...

    async def disconnect(self, peer_id: object) -> None:
        ...

    async def new_stream(self, peer_id: object, protocols: list[object]) -> StreamProtocol:
        ...

    def get_connected_peers(self) -> list[object]:
        ...

    def get_network(self) -> object:
        ...

logger = logging.getLogger(__name__)

# DCPP protocol identifier for libp2p streams
DCPP_PROTOCOL_ID = "/dcpp/1.0.0"


# =============================================================================
# GossipSub Mode Configuration
# =============================================================================


class GossipSubMode(Enum):
    """GossipSub operation mode."""

    LOCAL = "local"  # Local handlers only (no network)
    NETWORK = "network"  # Full network pubsub (requires py-libp2p)


def get_gossipsub_mode() -> GossipSubMode:
    """
    Get GossipSub mode from DCPP_GOSSIPSUB_MODE environment variable.

    Valid values: local, network
    Default: local (safe for testing without py-libp2p pubsub wired)

    In 'local' mode, publish() calls local handlers only.
    In 'network' mode, publish() sends to network peers (requires py-libp2p).
    """
    import os

    env_value = os.environ.get("DCPP_GOSSIPSUB_MODE", "local").lower()
    try:
        return GossipSubMode(env_value)
    except ValueError:
        logger.warning(
            f"Invalid DCPP_GOSSIPSUB_MODE value '{env_value}', using 'local'. "
            f"Valid values: {', '.join(m.value for m in GossipSubMode)}"
        )
        return GossipSubMode.LOCAL


def is_gossipsub_network_mode() -> bool:
    """Check if GossipSub is in network mode."""
    return get_gossipsub_mode() == GossipSubMode.NETWORK


async def read_framed_message(stream: StreamProtocol) -> bytes:
    """
    Read a complete framed DCPP message from a libp2p stream.

    Handles partial reads by buffering until a complete frame is received.
    Validates magic bytes, version, and length before reading the full payload.

    Args:
        stream: libp2p INetStream or compatible stream object

    Returns:
        Complete frame bytes (header + payload)

    Raises:
        MagicBytesError: If magic bytes don't match
        FramingError: If version is invalid or other framing error
        MessageTooLargeError: If payload length exceeds MAX_MESSAGE_SIZE
        ConnectionError: If stream is closed before complete frame
        TimeoutError: If read exceeds configured timeout
    """
    # Configurable timeout (0 or negative disables timeouts)
    timeout_env = os.environ.get("DCPP_STREAM_READ_TIMEOUT", "30")
    timeout: Optional[float]
    try:
        timeout = float(timeout_env)
    except ValueError:
        timeout = 30.0
    if timeout <= 0:
        timeout = None

    async def _read_with_timeout(awaitable: Awaitable[bytes], remaining: Optional[float]) -> bytes:
        if remaining is None:
            return await awaitable
        try:
            asyncio.get_running_loop()
            return await asyncio.wait_for(awaitable, timeout=remaining)
        except RuntimeError:
            if TRIO_AVAILABLE:
                try:
                    with trio.fail_after(remaining):
                        return await awaitable
                except trio.TooSlowError as e:
                    raise TimeoutError("Stream read timed out") from e
            return await awaitable

    async def _read_exact(length: int, context: str) -> bytes:
        data = b""
        start = time.monotonic()
        while len(data) < length:
            remaining = None
            if timeout is not None:
                elapsed = time.monotonic() - start
                remaining = timeout - elapsed
                if remaining <= 0:
                    raise TimeoutError(f"Timed out while reading {context}")
            try:
                chunk = await _read_with_timeout(stream.read(length - len(data)), remaining)
            except (asyncio.TimeoutError, TimeoutError) as e:
                raise TimeoutError(f"Timed out while reading {context}") from e
            if not chunk:
                return data
            data += chunk
        return data

    # Step 1: Read the header completely (20 bytes)
    header = await _read_exact(DCPPFramer.HEADER_SIZE, "header")
    if not header:
        raise ConnectionError("Stream closed")
    if len(header) < DCPPFramer.HEADER_SIZE:
        raise FramingError(
            f"Incomplete header: expected {DCPPFramer.HEADER_SIZE} bytes, got {len(header)}"
        )

    # Step 2: Validate magic bytes BEFORE reading more data
    magic = header[0:4]
    if magic != MAGIC_BYTES:
        raise MagicBytesError(f"Invalid magic bytes: expected {MAGIC_BYTES!r}, got {magic!r}")

    # Step 3: Validate version (only accept v1.0 exactly per spec)
    version = decode_uint16_be(header, 4)
    if version != 0x0100:
        raise FramingError(
            f"Unsupported protocol version: 0x{version:04X}. Only DCPP v1.0 (0x0100) is supported."
        )

    # Step 4: Extract length and validate BEFORE reading payload
    length = decode_uint32_be(header, 12)
    if length > MAX_MESSAGE_SIZE:
        raise MessageTooLargeError(f"Payload size {length} exceeds maximum {MAX_MESSAGE_SIZE}")

    # Step 5: Read payload completely
    payload = await _read_exact(length, "payload")
    if len(payload) < length:
        raise FramingError(f"Incomplete payload: expected {length} bytes, got {len(payload)}")

    return header + payload


# Check if libp2p is available
# Note: Import paths changed between libp2p versions:
#   - v0.2.x: libp2p.typing, libp2p.network.stream.net_stream_interface
#   - v0.5.x: libp2p.custom_types, libp2p.abc
Libp2pINetStream: type[Any] = StreamProtocol
Libp2pTProtocol: type[Any] = str
Libp2pKadDHT: Optional[type[Any]] = None
DHTMode: Optional[object] = None
Libp2pGossipSub: Optional[type[Any]] = None
Libp2pPubsub: Optional[type[Any]] = None
GOSSIPSUB_PROTOCOL_ID: str = "/meshsub/1.0.0"

try:
    from libp2p import new_host
    from libp2p.crypto.secp256k1 import create_new_key_pair
    from libp2p.crypto.ed25519 import create_new_key_pair as create_ed25519_key_pair
    from libp2p.crypto.x25519 import (
        create_new_key_pair as create_new_x25519_key_pair,
    )
    from libp2p.peer.id import ID as PeerID
    from libp2p.peer.peerinfo import info_from_p2p_addr
    from libp2p.security.noise.transport import PROTOCOL_ID as NOISE_PROTOCOL_ID
    from libp2p.security.noise.transport import Transport as NoiseTransport
    import multiaddr  # type: ignore[import-untyped]

    # Try v0.5.x import paths first, fall back to v0.2.x
    try:
        from libp2p.abc import INetStream as _Libp2pINetStream
        from libp2p.custom_types import TProtocol as _Libp2pTProtocol
    except ImportError:
        # Fallback for older versions
        from libp2p.network.stream.net_stream_interface import (  # type: ignore[no-redef]
            INetStream as _Libp2pINetStream,
        )
        from libp2p.typing import TProtocol as _Libp2pTProtocol  # type: ignore[no-redef]

    Libp2pINetStream = _Libp2pINetStream
    Libp2pTProtocol = _Libp2pTProtocol

    LIBP2P_AVAILABLE = True

    # === Noise Ed25519/X25519 Interop ===
    # Newer py-libp2p builds natively support a dedicated X25519 Noise static key.
    # Only keep the local monkey-patch for older 0.2.x builds that still need it.
    NOISE_PATCH_APPLIED = False
    NOISE_NATIVE_FIX_AVAILABLE = False

    def _has_native_noise_x25519_fix() -> bool:
        try:
            from libp2p.security.noise.exceptions import NoiseStateError as _NoiseStateError
            from libp2p.security.noise.messages import verify_handshake_payload_sig
            from libp2p.security.noise.patterns import PatternXX as _PatternXX

            identity_kp = create_ed25519_key_pair()
            noise_kp = create_new_x25519_key_pair()
            local_peer = PeerID.from_pubkey(identity_kp.public_key)

            # Fixed builds reject Ed25519 keys as the Noise static DH key.
            invalid_pattern = _PatternXX(
                local_peer,
                identity_kp.private_key,
                identity_kp.private_key,
            )
            try:
                invalid_pattern.make_handshake_payload()
            except _NoiseStateError:
                pass
            else:
                return False

            # Fixed builds produce a verifiable payload over the X25519 static key.
            valid_pattern = _PatternXX(
                local_peer,
                identity_kp.private_key,
                noise_kp.private_key,
            )
            payload = valid_pattern.make_handshake_payload()
            return verify_handshake_payload_sig(payload, noise_kp.public_key)
        except Exception:
            return False

    NOISE_NATIVE_FIX_AVAILABLE = _has_native_noise_x25519_fix()
    if NOISE_NATIVE_FIX_AVAILABLE:
        logger.info(
            "[Noise] Native X25519 static-key support detected in py-libp2p; "
            "skipping local interop patch"
        )
    else:
        try:
            import libp2p as _libp2p_mod

            _libp2p_version = getattr(_libp2p_mod, "__version__", None)
            logger.info(
                "[Noise] Attempting Ed25519/X25519 interop patch (py-libp2p %s)",
                _libp2p_version or "unknown",
            )

            from nacl.signing import SigningKey as _NaclSigningKey, VerifyKey as _NaclVerifyKey
            from nacl.exceptions import BadSignatureError as _NaclBadSigError
            from libp2p.crypto.keys import (
                KeyPair as _KeyPair,
                KeyType as _KeyType,
                PublicKey as _PublicKey,
                PrivateKey as _PrivateKey,
            )
            from libp2p.crypto.x25519 import X25519PublicKey as _X25519PublicKey
            from cryptography.hazmat.primitives import serialization as _crypto_serialization

            class FixedEd25519PublicKey(_PublicKey):
                """Ed25519 public key using nacl.signing.VerifyKey (spec-compliant)."""

                def __init__(self, verify_key: _NaclVerifyKey) -> None:
                    self._verify_key = verify_key

                def to_bytes(self) -> bytes:
                    return bytes(self._verify_key)

                @classmethod
                def from_bytes(cls, key_bytes: bytes) -> "FixedEd25519PublicKey":
                    return cls(_NaclVerifyKey(key_bytes))

                def get_type(self) -> _KeyType:
                    return _KeyType.Ed25519

                def verify(self, data: bytes, signature: bytes) -> bool:
                    try:
                        self._verify_key.verify(data, signature)
                        return True
                    except _NaclBadSigError:
                        return False

            class FixedEd25519PrivateKey(_PrivateKey):
                """Ed25519 private key using nacl.signing.SigningKey (spec-compliant)."""

                def __init__(self, signing_key: _NaclSigningKey) -> None:
                    self._signing_key = signing_key

                @classmethod
                def new(cls, seed: bytes = None) -> "FixedEd25519PrivateKey":
                    if seed is not None:
                        if len(seed) != 32:
                            raise ValueError("Ed25519 seed must be 32 bytes")
                        sk = _NaclSigningKey(seed)
                    else:
                        sk = _NaclSigningKey.generate()
                    return cls(sk)

                def to_bytes(self) -> bytes:
                    return bytes(self._signing_key)

                @classmethod
                def from_bytes(cls, data: bytes) -> "FixedEd25519PrivateKey":
                    return cls(_NaclSigningKey(data))

                def get_type(self) -> _KeyType:
                    return _KeyType.Ed25519

                def sign(self, data: bytes) -> bytes:
                    signed = self._signing_key.sign(data)
                    return signed.signature

                def get_public_key(self) -> _PublicKey:
                    return FixedEd25519PublicKey(self._signing_key.verify_key)

            def patched_create_ed25519_key_pair(seed: bytes = None) -> _KeyPair:
                """Create an Ed25519 key pair using proper nacl.signing (spec-compliant)."""
                priv = FixedEd25519PrivateKey.new(seed)
                pub = priv.get_public_key()
                return _KeyPair(priv, pub)

            def patched_get_pubkey_from_noise_keypair(key_pair: Any) -> _PublicKey:
                """Return X25519PublicKey for noise static key (not Ed25519PublicKey)."""
                try:
                    raw_bytes = key_pair.public.public_bytes(
                        _crypto_serialization.Encoding.Raw,
                        _crypto_serialization.PublicFormat.Raw,
                    )
                except Exception:
                    raw_bytes = getattr(key_pair.public, "to_bytes", lambda: None)()
                    if not raw_bytes:
                        raw_bytes = getattr(key_pair, "public_bytes", lambda: None)()
                    if not raw_bytes:
                        raise TypeError(
                            "Unsupported noise keypair public key type for X25519 extraction"
                        )
                return _X25519PublicKey.from_bytes(raw_bytes)

            import libp2p.crypto.ed25519 as _ed25519_mod
            import libp2p.crypto.serialization as _ser_mod
            from libp2p.security.noise.patterns import PatternXX as _PatternXX

            _ed25519_mod.Ed25519PublicKey = FixedEd25519PublicKey  # type: ignore[misc]
            _ed25519_mod.Ed25519PrivateKey = FixedEd25519PrivateKey  # type: ignore[misc]
            _ed25519_mod.create_new_key_pair = patched_create_ed25519_key_pair  # type: ignore[misc]

            _ser_mod.key_type_to_public_key_deserializer[  # type: ignore[index]
                _KeyType.Ed25519.value
            ] = FixedEd25519PublicKey.from_bytes
            _ser_mod.key_type_to_private_key_deserializer[  # type: ignore[index]
                _KeyType.Ed25519.value
            ] = FixedEd25519PrivateKey.from_bytes

            _PatternXX._get_pubkey_from_noise_keypair = staticmethod(  # type: ignore[assignment]
                patched_get_pubkey_from_noise_keypair
            )

            create_ed25519_key_pair = patched_create_ed25519_key_pair  # type: ignore[misc] # noqa: F811

            NOISE_PATCH_APPLIED = True
            logger.info(
                "[Noise] Installed Ed25519/X25519 interop patch for rust-libp2p compatibility"
            )
        except Exception as noise_patch_err:
            logger.warning(f"[Noise] Could not install interop patch: {noise_patch_err}")

    # Try to import KadDHT for real DHT operations
    try:
        from libp2p.kad_dht.kad_dht import KadDHT as _Libp2pKadDHT, DHTMode as _DHTMode

        KADDHT_AVAILABLE = True
        Libp2pKadDHT = _Libp2pKadDHT
        DHTMode = _DHTMode
        logger.info("py-libp2p KadDHT available for real DHT operations")
    except ImportError:
        KADDHT_AVAILABLE = False
        Libp2pKadDHT = None
        DHTMode = None
        logger.warning("py-libp2p KadDHT not available - DHT will use local cache only")

    # Try to import GossipSub for real pubsub operations
    try:
        from libp2p.pubsub.gossipsub import (
            GossipSub as _Libp2pGossipSub,
            PROTOCOL_ID as _GOSSIPSUB_PROTOCOL_ID,
        )
        from libp2p.pubsub.pubsub import Pubsub as _Libp2pPubsub

        GOSSIPSUB_AVAILABLE = True
        logger.info("py-libp2p GossipSub available for real pubsub operations")
        Libp2pGossipSub = _Libp2pGossipSub
        Libp2pPubsub = _Libp2pPubsub
        GOSSIPSUB_PROTOCOL_ID = str(_GOSSIPSUB_PROTOCOL_ID)

        # Patch the signature validator to handle Ed25519 keys from rust-libp2p
        # rust-libp2p 0.54+ sends keys in a format that py-libp2p 0.5.0 may not
        # correctly deserialize due to protobuf schema differences
        try:
            from libp2p.pubsub import validators as pubsub_validators
            from libp2p.crypto.pb import crypto_pb2
            from libp2p.crypto.ed25519 import Ed25519PublicKey
            from libp2p.crypto.serialization import deserialize_public_key as orig_deserialize
            from libp2p.peer.id import ID
            from libp2p.pubsub.pb import rpc_pb2

            pubsub_validators_typed = cast(PubsubValidatorsProtocol, pubsub_validators)
            # Store original signature_validator
            orig_signature_validator = pubsub_validators_typed.signature_validator
            PUBSUB_SIGNING_PREFIX = pubsub_validators_typed.PUBSUB_SIGNING_PREFIX

            def patched_deserialize_public_key(data: bytes) -> object:
                """
                Deserialize public key with better Ed25519 handling for rust-libp2p interop.
                """
                try:
                    return orig_deserialize(data)
                except Exception as e:
                    try:
                        parsed = crypto_pb2.PublicKey.FromString(data)
                        if parsed.key_type == 0 and len(parsed.data) == 32:
                            logger.debug(
                                "[GossipSub] Attempting Ed25519 parse for 32-byte key with type=0"
                            )
                            return Ed25519PublicKey.from_bytes(parsed.data)
                        if len(data) == 32:
                            logger.debug(
                                "[GossipSub] Attempting Ed25519 parse for raw 32-byte data"
                            )
                            return Ed25519PublicKey.from_bytes(data)
                    except Exception as inner_e:
                        logger.debug(f"[GossipSub] Ed25519 fallback also failed: {inner_e}")
                    raise e

            # Store reference to host for peerstore access (set when pubsub initializes)
            _validator_host_ref: List[Optional[object]] = [None]

            def set_validator_host(host: object) -> None:
                """Set host reference for signature validator to access peerstore."""
                _validator_host_ref[0] = host
                logger.debug("[GossipSub] Validator host reference set")

            def patched_signature_validator(msg: rpc_pb2.Message) -> bool:
                """
                Patched signature validator that handles Ed25519 keys from rust-libp2p.
                Supports empty key field by looking up the key from peerstore.
                """
                logger.info(
                    f"[GossipSub] Validating message from {msg.from_id.hex()[:16]}... "
                    f"(key={len(msg.key)} bytes, sig={len(msg.signature)} bytes, "
                    f"topics={list(msg.topicIDs)})"
                )

                if msg.signature == b"":
                    logger.warning("[GossipSub] Reject: no signature attached for msg")
                    return False

                msg_pubkey = None

                # Try to get key from message first
                if msg.key and len(msg.key) > 0:
                    try:
                        msg_pubkey = patched_deserialize_public_key(msg.key)
                        logger.debug(
                            f"[GossipSub] Got key from message: {type(msg_pubkey).__name__}"
                        )
                    except Exception as e:
                        logger.debug(f"[GossipSub] Could not deserialize message key: {e}")

                # If no key in message, try peerstore lookup
                if msg_pubkey is None and _validator_host_ref[0] is not None:
                    try:
                        host = cast(Any, _validator_host_ref[0])
                        peer_id = ID(msg.from_id)
                        msg_pubkey = host.get_peerstore().pubkey(peer_id)
                        if msg_pubkey:
                            logger.debug(
                                f"[GossipSub] Got key from peerstore: {type(msg_pubkey).__name__}"
                            )
                    except Exception as e:
                        logger.debug(f"[GossipSub] Could not get key from peerstore: {e}")

                # If still no key, try to extract from peer ID (Ed25519 inline keys)
                if msg_pubkey is None:
                    try:
                        peer_id = ID(msg.from_id)
                        # Ed25519 peer IDs have the pubkey embedded: 0x00 0x24 0x08 0x01 0x12 0x20 <32 bytes>
                        if (
                            len(msg.from_id) == 38
                            and msg.from_id[:6] == b"\x00\x24\x08\x01\x12\x20"
                        ):
                            key_bytes = msg.from_id[6:]
                            msg_pubkey = Ed25519PublicKey.from_bytes(key_bytes)
                            logger.debug("[GossipSub] Extracted Ed25519 key from peer ID")
                    except Exception as e:
                        logger.debug(f"[GossipSub] Could not extract key from peer ID: {e}")

                if msg_pubkey is None:
                    logger.warning(
                        f"[GossipSub] Reject: could not obtain public key for {msg.from_id.hex()[:16]}..."
                    )
                    return False

                # Verify sender ID matches key
                derived_id = ID.from_pubkey(cast(Any, msg_pubkey))
                if derived_id.to_bytes() != msg.from_id:
                    logger.warning("[GossipSub] Reject: signing key does not match sender ID")
                    return False

                # Verify signature
                msg_without_key_sig = rpc_pb2.Message(
                    data=msg.data, topicIDs=msg.topicIDs, from_id=msg.from_id, seqno=msg.seqno
                )
                payload = PUBSUB_SIGNING_PREFIX.encode() + msg_without_key_sig.SerializeToString()
                try:
                    result = bool(cast(Any, msg_pubkey).verify(payload, msg.signature))
                    if result:
                        logger.info(
                            f"[GossipSub] Message validated successfully from {msg.from_id.hex()[:16]}..."
                        )
                    else:
                        logger.warning("[GossipSub] Signature verification failed")
                    return result
                except Exception as e:
                    logger.warning(f"[GossipSub] Signature verification exception: {e}")
                    return False

            # Export set_validator_host so it can be called when host is ready
            setattr(pubsub_validators_typed, "set_validator_host", set_validator_host)

            # Monkey-patch the signature_validator function in both modules
            # validators module (for future imports)
            setattr(pubsub_validators_typed, "signature_validator", patched_signature_validator)
            # pubsub module (which has already imported it directly)
            import libp2p.pubsub.pubsub as pubsub_module

            setattr(pubsub_module, "signature_validator", patched_signature_validator)

            logger.info("[GossipSub] Installed Ed25519 interop patch for rust-libp2p compatibility")
        except Exception as patch_err:
            logger.warning(f"[GossipSub] Could not install Ed25519 interop patch: {patch_err}")

    except ImportError:
        GOSSIPSUB_AVAILABLE = False
        Libp2pGossipSub = None
        Libp2pPubsub = None
        GOSSIPSUB_PROTOCOL_ID = "/meshsub/1.0.0"  # Fallback for type hints
        logger.warning("py-libp2p GossipSub not available - pubsub will use local handlers only")

except ImportError:
    LIBP2P_AVAILABLE = False
    KADDHT_AVAILABLE = False
    GOSSIPSUB_AVAILABLE = False
    # Note: Warning/error handling is done at the daemon level, not here.
    # This allows the module to be imported without side effects.
    # Define placeholders for type hints
    Libp2pINetStream = StreamProtocol
    Libp2pTProtocol = str
    Libp2pKadDHT = None
    DHTMode = None
    Libp2pGossipSub = None
    Libp2pPubsub = None
    GOSSIPSUB_PROTOCOL_ID = "/meshsub/1.0.0"  # Fallback for type hints


class HostEvent(Enum):
    """Events emitted by the libp2p host."""

    PEER_CONNECTED = "peer_connected"
    PEER_DISCONNECTED = "peer_disconnected"
    DCPP_REQUEST = "dcpp_request"  # DCPP protocol message received
    DCPP_RESPONSE = "dcpp_response"  # DCPP protocol response received
    DCPP_REQUEST_FAILED = "dcpp_request_failed"  # Outbound request failed
    PROVIDER_FOUND = "provider_found"  # DHT provider found
    DHT_PROVIDERS_FOUND = "dht_providers_found"  # DHT query completed
    GOSSIP_MESSAGE = "gossip_message"  # GossipSub message received
    GOSSIP_SUBSCRIBED = "gossip_subscribed"  # Subscribed to topic


@dataclass
class DCPPRequest:
    """DCPP protocol request - a framed message sent to a peer."""

    message_type: MessageType
    payload: bytes


@dataclass
class DCPPResponse:
    """DCPP protocol response - a framed message received from a peer."""

    message_type: MessageType
    payload: bytes


@dataclass
class HostEventData:
    """Data associated with a host event."""

    event_type: HostEvent
    peer_id: Optional[bytes] = None
    # For DCPP_REQUEST events
    message_type: Optional[MessageType] = None
    payload: Optional[bytes] = None
    stream: Optional[StreamProtocol] = None  # Stream for responding
    request_id: int = 0  # Request ID for correlation (REQUIRED for responses)
    # For PROVIDER_FOUND
    key: Optional[bytes] = None
    # For GOSSIP_MESSAGE
    topic: Optional[str] = None
    data: Optional[bytes] = None
    # For DCPP_REQUEST_FAILED
    error: Optional[str] = None


@dataclass
class RealHostConfig:
    """Configuration for the real libp2p host."""

    listen_addrs: List[str] = field(default_factory=lambda: ["/ip4/0.0.0.0/tcp/4001"])
    bootstrap_peers: List[Tuple[bytes, str]] = field(default_factory=list)
    dht_server_mode: bool = False
    idle_timeout: int = 60
    enable_dht: bool = True
    enable_gossipsub: bool = True
    # DHT configuration
    dht_reannounce_interval: int = 3600  # 1 hour
    dht_provider_ttl: int = 86400  # 24 hours
    # GossipSub configuration
    gossipsub_heartbeat_interval: float = 1.0
    gossipsub_message_cache_ttl: int = 120  # 2 minutes
    # External address configuration (NAT traversal / WAN deployment)
    advertise_addrs: List[str] = field(default_factory=list)  # Explicit addresses to advertise
    enable_relay: bool = False  # Enable relay client for NAT traversal
    enable_hole_punch: bool = False  # Enable hole punching for direct connections
    dial_timeout_secs: float = 30.0  # Timeout for dial attempts


class RealHost(HostProtocol):
    """Real libp2p host for DCPP.

    This implementation uses the py-libp2p library for actual P2P networking.
    Includes integrated Kademlia DHT and GossipSub support.

    Note: libp2p 0.5.0+ uses trio internally. This class runs the trio-based
    libp2p host in a separate thread, allowing the asyncio-based daemon to
    run normally. Communication happens via thread-safe queues and events.
    """

    def __init__(self, config: RealHostConfig):
        if not LIBP2P_AVAILABLE:
            raise RuntimeError("libp2p not available. Install with: pip install libp2p")
        if not TRIO_AVAILABLE:
            raise RuntimeError("trio not available. Install with: pip install trio")

        self._config = config
        self._host: Optional[Libp2pHostProtocol] = None
        self._key_pair: Optional[object] = None
        self._local_peer_id: Optional[bytes] = None
        self._event_queue: asyncio.Queue[HostEventData] = asyncio.Queue()
        self._handlers: Dict[str, StreamHandler] = {}
        self._started = False

        # DHT integration
        self._dht: Optional[KademliaDHT] = None
        self._dht_command_queue: asyncio.Queue[DHTCommand] = asyncio.Queue()
        self._dht_task: Optional[asyncio.Task[None]] = None
        # Real py-libp2p KadDHT (if available)
        self._libp2p_kad_dht: Optional[KadDHTProtocol] = None

        # GossipSub integration
        self._subscribed_topics: Set[str] = set()
        self._topic_handlers: Dict[str, List[Callable[[str, bytes, Optional[bytes]], None]]] = {}
        self._gossipsub_task: Optional[asyncio.Task[None]] = None
        # Real py-libp2p PubSub (if available)
        self._libp2p_pubsub: Optional[PubSubProtocol] = None
        # Store subscription objects for message receiving
        self._topic_subscriptions: Dict[str, object] = {}
        # Trio nursery for message receiver tasks (set when pubsub starts)
        self._pubsub_nursery: Optional[object] = None
        # Queue for new subscription requests (thread-safe for asyncio/trio bridge)
        self._subscription_queue: queue.Queue[str] = queue.Queue()

        # Threading for trio/asyncio isolation
        # libp2p 0.5.0+ uses trio, so we run it in a separate thread
        self._trio_thread: Optional[threading.Thread] = None
        self._trio_token: Optional["TrioToken"] = None  # For calling trio from other threads
        self._host_ready: threading.Event = threading.Event()
        self._stop_requested: threading.Event = threading.Event()
        self._actual_listen_addrs: List[str] = []
        # Connection request queue (thread-safe for trio/asyncio bridge)
        self._connect_queue: queue.Queue[Tuple[str, object]] = queue.Queue()
        self._connect_results: Dict[str, bool] = {}  # addr -> success
        self._connect_errors: Dict[str, str] = {}  # addr -> error string

    def set_advertise_addrs(self, addrs: List[str]) -> None:
        """
        Update the advertise addresses for DHT provider records.

        This should be called after start() when the peer ID is known,
        allowing addresses to include the /p2p/<peer_id> suffix.

        Args:
            addrs: List of multiaddr strings to advertise
        """
        self._config.advertise_addrs = addrs
        logger.debug(f"Updated advertise addresses: {len(addrs)} addr(s)")

    async def start(self) -> None:
        """Start the libp2p host.

        The host runs in a separate thread using trio (required for libp2p 0.5.0+).
        This allows the asyncio-based daemon to run normally while libp2p operates
        in its own event loop.

        Per RFC Section 3.1: MUST support TCP transport with Noise encryption.
        Per RFC Section 4.1: Protocol ID is /dcpp/1.0.0
        """
        if self._started:
            return

        try:
            import libp2p as _libp2p_mod

            logger.info(
                "py-libp2p version: %s", getattr(_libp2p_mod, "__version__", "unknown")
            )
        except Exception as e:
            logger.debug(f"Failed to read py-libp2p version: {e}")

        try:
            logger.info(f"[Noise] Patch applied: {NOISE_PATCH_APPLIED}")
            logger.info(f"[Noise] Native X25519 fix available: {NOISE_NATIVE_FIX_AVAILABLE}")
        except Exception:
            # NOISE_PATCH_APPLIED may not be defined if libp2p import failed
            pass

        # Generate Ed25519 key pair
        try:
            self._key_pair = create_ed25519_key_pair()
        except Exception:
            # Fall back to secp256k1 if ed25519 not available
            self._key_pair = create_new_key_pair()

        try:
            pub_len = len(self._key_pair.public_key.to_bytes())
            priv_len = len(self._key_pair.private_key.to_bytes())
            logger.info(
                f"Identity key lengths: public={pub_len} bytes, private={priv_len} bytes"
            )
        except Exception as e:
            logger.debug(f"Failed to read identity key lengths: {e}")

        sec_opt = None
        noise_only = os.environ.get("DCPP_LIBP2P_NOISE_ONLY", "0") == "1"
        try:
            if "noise_privkey" in inspect.signature(NoiseTransport).parameters:
                noise_key_pair = create_new_x25519_key_pair()
                sec_opt = {
                    NOISE_PROTOCOL_ID: NoiseTransport(
                        self._key_pair,
                        noise_privkey=noise_key_pair.private_key,
                    ),
                }
                logger.info(
                    "[Noise] Using dedicated X25519 static key for Noise transport"
                )
            elif noise_only:
                sec_opt = {
                    NOISE_PROTOCOL_ID: NoiseTransport(self._key_pair),
                }
                logger.info("[Noise] Using Noise-only security transports for interop")
        except Exception as e:
            logger.warning(f"[Noise] Failed to configure explicit Noise transport: {e}")

        if sec_opt is not None:
            logger.info(
                "[Noise] Security protocols: %s", [str(p) for p in sec_opt.keys()]
            )

        # Create the host (but don't start yet - that happens in host.run())
        self._host = cast(
            Libp2pHostProtocol,
            new_host(
                key_pair=self._key_pair,
                sec_opt=sec_opt,
                muxer_preference="YAMUX",
            ),
        )
        if self._host is None:
            raise RuntimeError("libp2p host creation failed")
        host = self._host
        peer_id_obj = cast(Any, host.get_id())
        self._local_peer_id = cast(bytes, peer_id_obj.to_bytes())

        # Parse listen addresses (RFC Section 3.1: MUST support TCP)
        listen_maddrs = []
        for addr in self._config.listen_addrs:
            try:
                listen_maddrs.append(multiaddr.Multiaddr(addr))
            except Exception as e:
                logger.error(f"Invalid listen address {addr}: {e}")

        # Register DCPP protocol handler for /dcpp/1.0.0 (RFC Section 4.1)
        self._host.set_stream_handler(DCPP_PROTOCOL_ID, self._handle_dcpp_stream)

        # Reset thread synchronization state
        self._host_ready.clear()
        self._stop_requested.clear()
        self._actual_listen_addrs = []

        def _run_trio_host() -> None:
            """Run the libp2p host in a trio event loop (separate thread)."""

            async def _trio_main() -> None:
                try:
                    # py-libp2p moved trio service helpers from async_service to
                    # anyio_service in 0.6.x. Support both layouts.
                    try:
                        from libp2p.tools.anyio_service import background_trio_service
                    except ImportError:
                        from libp2p.tools.async_service import (  # type: ignore[attr-defined]
                            background_trio_service,
                        )

                    # Capture trio token for cross-thread calls
                    self._trio_token = trio.lowlevel.current_trio_token()

                    async with host.run(listen_addrs=listen_maddrs):
                        # Capture actual listen addresses
                        self._actual_listen_addrs = [str(a) for a in host.get_transport_addrs()]
                        for addr in self._actual_listen_addrs:
                            logger.info(f"Listening on {addr}")

                        # Signal that host is ready
                        self._host_ready.set()

                        # Initialize and run Pubsub service if in NETWORK mode
                        # Use proper async with for trio service lifecycle
                        async def _run_main_loop() -> None:
                            while not self._stop_requested.is_set():
                                # Process any pending connection requests
                                try:
                                    while not self._connect_queue.empty():
                                        addr_str, peer_info = self._connect_queue.get_nowait()
                                        try:
                                            await host.connect(peer_info)
                                            self._connect_results[addr_str] = True
                                            self._connect_errors.pop(addr_str, None)
                                            logger.info(f"[CONN-TRIO] Connected to {addr_str}")
                                        except Exception as e:
                                            self._connect_results[addr_str] = False
                                            self._connect_errors[addr_str] = (
                                                f"{type(e).__name__}: {e}"
                                            )
                                            logger.debug(
                                                f"[CONN-TRIO] Failed to connect to {addr_str}: {e}"
                                            )
                                except Exception as e:
                                    logger.debug(f"[CONN-TRIO] Queue processing error: {e}")

                                await trio.sleep(0.1)

                        if GOSSIPSUB_AVAILABLE and get_gossipsub_mode() == GossipSubMode.NETWORK:
                            try:
                                # GossipSub configuration aligned with rust-libp2p 0.54:
                                # - Support both /meshsub/1.0.0 and /meshsub/1.1.0 for interop
                                # - heartbeat_interval=10 (matches Rust's 10s)
                                # - Mesh parameters: degree=6, low=4, high=12
                                gossipsub_protocols = [
                                    "/meshsub/1.1.0",  # GossipSub v1.1 (rust-libp2p default)
                                    "/meshsub/1.0.0",  # GossipSub v1.0 (fallback)
                                ]
                                logger.info(
                                    f"[GossipSub] Initializing with protocols: {gossipsub_protocols}"
                                )
                                assert Libp2pGossipSub is not None and Libp2pPubsub is not None
                                gossipsub_router = Libp2pGossipSub(
                                    protocols=gossipsub_protocols,
                                    degree=6,
                                    degree_low=4,
                                    degree_high=12,
                                    heartbeat_interval=10,  # Match Rust's 10 second interval
                                )
                                self._libp2p_pubsub = Libp2pPubsub(self._host, gossipsub_router)
                                # Set host reference for signature validator (peerstore access)
                                try:
                                    from libp2p.pubsub import validators as pv

                                    if hasattr(pv, "set_validator_host"):
                                        getattr(pv, "set_validator_host")(self._host)
                                except Exception as e:
                                    logger.debug(f"[GossipSub] Could not set validator host: {e}")

                                # Message receiver task for subscriptions
                                async def _receive_messages(topic: str, subscription: object) -> None:
                                    """Receive messages from a subscription and deliver to handlers."""
                                    logger.debug(
                                        f"[GossipSub] Starting message receiver for {topic}"
                                    )
                                    try:
                                        while True:
                                            msg = await cast(Any, subscription).get()
                                            logger.info(
                                                f"[GossipSub] Received message on {topic} from {msg.from_id.hex()[:16]}..."
                                            )
                                            # Deliver to local handlers (sync handlers for trio/asyncio compatibility)
                                            handlers = self._topic_handlers.get(topic, [])
                                            for handler in handlers:
                                                try:
                                                    handler(topic, msg.data, msg.from_id)
                                                    logger.debug(
                                                        f"[GossipSub] Handler completed for {topic}"
                                                    )
                                                except Exception as e:
                                                    logger.error(f"[GossipSub] Handler error: {e}")
                                    except trio.EndOfChannel:
                                        logger.debug(f"[GossipSub] Channel closed for {topic}")
                                    except Exception as e:
                                        logger.error(
                                            f"[GossipSub] Message receiver error for {topic}: {e}"
                                        )

                                # Run Pubsub as a background service with proper nesting
                                async with background_trio_service(cast(Any, self._libp2p_pubsub)):
                                    logger.info(
                                        "[GossipSub] Mode: NETWORK - py-libp2p PubSub service running"
                                    )

                                    # Start a nursery for message receivers
                                    async with trio.open_nursery() as nursery:
                                        # Store nursery reference for new subscriptions
                                        self._pubsub_nursery = nursery
                                        # Start connection processing immediately once the host
                                        # is ready. Otherwise bootstrap dials can time out while
                                        # PubSub subscriptions are still initializing.
                                        nursery.start_soon(_run_main_loop)

                                        # Task to handle new subscription requests from thread-safe queue
                                        async def _handle_new_subscriptions() -> None:
                                            pubsub = self._libp2p_pubsub
                                            if pubsub is None:
                                                return
                                            while True:
                                                # Poll the thread-safe queue for new subscriptions
                                                try:
                                                    topic = self._subscription_queue.get_nowait()
                                                    if topic not in self._topic_subscriptions:
                                                        try:
                                                            sub = await pubsub.subscribe(topic)
                                                            self._topic_subscriptions[topic] = sub
                                                            nursery.start_soon(
                                                                _receive_messages, topic, sub
                                                            )
                                                            logger.info(
                                                                f"[GossipSub] Started receiver for topic: {topic}"
                                                            )
                                                        except Exception as e:
                                                            logger.warning(
                                                                f"[GossipSub] Failed to start receiver for {topic}: {e}"
                                                            )
                                                except Exception:
                                                    # Queue is empty, sleep briefly
                                                    pass
                                                await trio.sleep(0.1)

                                        nursery.start_soon(_handle_new_subscriptions)

                                        # Subscribe to topics that were requested before pubsub started
                                        for topic in list(self._subscribed_topics):
                                            if topic not in self._topic_subscriptions:
                                                try:
                                                    sub = await self._libp2p_pubsub.subscribe(topic)
                                                    self._topic_subscriptions[topic] = sub
                                                    nursery.start_soon(
                                                        _receive_messages, topic, sub
                                                    )
                                                    logger.info(
                                                        f"[GossipSub] Started receiver for pending topic: {topic}"
                                                    )
                                                except Exception as e:
                                                    logger.warning(
                                                        f"[GossipSub] Failed to subscribe to pending {topic}: {e}"
                                                    )
                                        while not self._stop_requested.is_set():
                                            await trio.sleep(0.1)
                            except Exception as e:
                                logger.warning(f"[GossipSub] Failed to run PubSub service: {e}")
                                self._libp2p_pubsub = None
                                # Fall back to running without Pubsub
                                await _run_main_loop()
                        else:
                            await _run_main_loop()

                        logger.debug("Host stopping (stop requested)")
                except Exception as e:
                    logger.error(f"Trio host error: {e}")
                    self._host_ready.set()  # Don't block start()
                    raise

            try:
                trio.run(_trio_main)
            except Exception as e:
                logger.error(f"Trio thread error: {e}")
            logger.debug("Trio host thread exiting")

        # Start the trio host in a separate thread
        self._trio_thread = threading.Thread(
            target=_run_trio_host,
            name="libp2p-trio-host",
            daemon=True,
        )
        self._trio_thread.start()

        # Wait for host to be ready (with timeout)
        if not self._host_ready.wait(timeout=10.0):
            logger.error("Host failed to start within timeout")
            self._stop_requested.set()
            raise RuntimeError("libp2p host failed to start")

        # Initialize DHT if enabled (RFC Section 9.1)
        if self._config.enable_dht:
            from dcpp_python.network.dht.base import DHTConfig

            dht_config = DHTConfig(
                reannounce_interval=self._config.dht_reannounce_interval,
                provider_ttl=self._config.dht_provider_ttl,
            )
            bootstrap_config = BootstrapConfig(static_peers=self._config.bootstrap_peers)
            self._dht = KademliaDHT(
                dht_config,
                command_queue=self._dht_command_queue,
                bootstrap_config=bootstrap_config,
            )
            self._dht.set_local_identity(self._local_peer_id, self._config.listen_addrs)
            await self._dht.start()
            self._dht_task = asyncio.create_task(self._process_dht_commands())

            # Initialize real py-libp2p KadDHT if available
            if KADDHT_AVAILABLE and self._host is not None and Libp2pKadDHT is not None and DHTMode:
                try:
                    # Create KadDHT in server mode for providing
                    self._libp2p_kad_dht = Libp2pKadDHT(self._host, cast(Any, DHTMode).SERVER)
                    logger.info("[DHT] Real py-libp2p KadDHT initialized - NETWORK mode enabled")
                except Exception as e:
                    logger.warning(f"[DHT] Failed to initialize py-libp2p KadDHT: {e}")
                    logger.info("[DHT] Falling back to LOCAL CACHE mode")
                    self._libp2p_kad_dht = None
            else:
                logger.info("[DHT] Using LOCAL CACHE mode (py-libp2p KadDHT not available)")

            logger.info("DHT initialized")

        # Log GossipSub mode for debugging cross-impl connectivity
        # Note: Actual Pubsub initialization happens in the trio thread (_trio_main)
        gossipsub_mode = get_gossipsub_mode()
        if self._config.enable_gossipsub:
            if gossipsub_mode == GossipSubMode.NETWORK:
                if not GOSSIPSUB_AVAILABLE:
                    logger.warning(
                        "[GossipSub] Mode: NETWORK requested but py-libp2p PubSub not available. "
                        "Messages will only reach local handlers."
                    )
                # Pubsub is initialized and run in the trio thread
            else:
                logger.info(
                    "[GossipSub] Mode: LOCAL - messages delivered to local handlers only. "
                    "Set DCPP_GOSSIPSUB_MODE=network to enable network publishing."
                )

        self._started = True
        logger.info(f"Host started with peer ID: {format_peer_id(self._local_peer_id)}")

    async def stop(self) -> None:
        """Stop the libp2p host."""
        if not self._started:
            return

        # Signal stop to trio thread
        self._stop_requested.set()

        # Stop DHT
        if self._dht_task:
            self._dht_task.cancel()
            try:
                await self._dht_task
            except asyncio.CancelledError:
                pass
            self._dht_task = None

        if self._dht:
            await self._dht.stop()
            self._dht = None

        # Stop GossipSub
        if self._gossipsub_task:
            self._gossipsub_task.cancel()
            try:
                await self._gossipsub_task
            except asyncio.CancelledError:
                pass
            self._gossipsub_task = None

        # Clear subscriptions
        self._subscribed_topics.clear()
        self._topic_handlers.clear()

        # Wait for trio thread to finish
        if self._trio_thread and self._trio_thread.is_alive():
            self._trio_thread.join(timeout=5.0)
            if self._trio_thread.is_alive():
                logger.warning("Trio host thread did not stop cleanly")
            self._trio_thread = None

        # The host is closed when the trio context exits
        self._host = None

        self._started = False
        logger.info("Host stopped")

    @property
    def peer_id(self) -> bytes:
        """Get the local peer ID."""
        if self._local_peer_id is None:
            raise RuntimeError("Host not started")
        return self._local_peer_id

    @property
    def addrs(self) -> List[str]:
        """Get listen addresses."""
        return self._config.listen_addrs

    async def connect(self, peer_id: bytes, addrs: List[str]) -> bool:
        """
        Connect to a peer.

        Handles both multiaddrs with and without /p2p/<peer_id> suffix.
        If an address lacks the peer ID and one is provided via the peer_id
        parameter, the peer_id will be appended to complete the multiaddr.

        Note: py-libp2p uses trio internally. Connections are queued and
        processed by the trio thread to avoid context conflicts.
        """
        if not self._started or not self._host:
            logger.debug("[CONN] Cannot connect - host not started")
            return False

        peer_id_str = format_peer_id(peer_id)
        logger.debug(f"[CONN] Connecting to peer {peer_id_str} via {len(addrs)} address(es)")

        try:
            # Parse peer info from addresses
            last_error: Optional[str] = None
            for addr_str in addrs:
                try:
                    logger.debug(f"[CONN] Trying address: {addr_str}")

                    # If address lacks /p2p/ and we have a peer_id, append it
                    if "/p2p/" not in addr_str and peer_id_str != "unknown":
                        addr_str = f"{addr_str}/p2p/{peer_id_str}"
                        logger.debug(f"[CONN] Appended peer ID to address: {addr_str}")

                    maddr = multiaddr.Multiaddr(addr_str)
                    peer_info = info_from_p2p_addr(maddr)
                    try:
                        logger.debug(
                            "[CONN] Peer info: peer_id=%s addrs=%s",
                            getattr(peer_info, "peer_id", None),
                            getattr(peer_info, "addrs", None),
                        )
                    except Exception:
                        pass

                    # Queue connection request for trio thread
                    self._connect_results.pop(addr_str, None)  # Clear any previous result
                    self._connect_errors.pop(addr_str, None)
                    self._connect_queue.put((addr_str, peer_info))

                    # Wait for result (with timeout)
                    import time

                    start_time = time.time()
                    timeout = 10.0  # seconds
                    while addr_str not in self._connect_results:
                        if time.time() - start_time > timeout:
                            logger.debug(
                                "[CONN] Connection timeout for %s (last error: %s)",
                                addr_str,
                                self._connect_errors.get(addr_str),
                            )
                            break
                        await asyncio.sleep(0.1)

                    if self._connect_results.get(addr_str):
                        logger.info(f"[CONN] Connected to peer {peer_id_str} at {addr_str}")
                        await self._event_queue.put(
                            HostEventData(event_type=HostEvent.PEER_CONNECTED, peer_id=peer_id)
                        )
                        return True
                    else:
                        last_error = self._connect_errors.get(addr_str)
                        logger.debug(
                            "[CONN] Failed to connect via %s (error: %s)",
                            addr_str,
                            last_error,
                        )
                        continue
                except Exception as e:
                    logger.debug(f"[CONN] Failed to connect via {addr_str}: {e}")
                    continue
            logger.warning(
                "[CONN] Failed to connect to peer %s (tried %d addresses, last error: %s)",
                peer_id_str,
                len(addrs),
                last_error or "unknown",
            )
            return False
        except Exception as e:
            logger.error(f"[CONN] Connection error for peer {peer_id_str}: {e}")
            return False

    async def disconnect(self, peer_id: bytes) -> None:
        """Disconnect from a peer."""
        if not self._started or not self._host:
            return

        try:
            pid = PeerID(peer_id)
            await self._host.disconnect(pid)
            await self._event_queue.put(
                HostEventData(event_type=HostEvent.PEER_DISCONNECTED, peer_id=peer_id)
            )
        except Exception as e:
            logger.error(f"Disconnect failed: {e}")

    async def new_stream(self, peer_id: bytes, protocol_id: str) -> StreamProtocol:
        """Open a new stream to a peer."""
        if not self._started or not self._host:
            raise RuntimeError("Host not started")

        try:
            pid = PeerID(peer_id)
            if TRIO_AVAILABLE and self._trio_token is not None:
                # py-libp2p requires trio context; proxy to trio thread
                runner = functools.partial(
                    trio.from_thread.run,
                    self._host.new_stream,
                    pid,
                    [protocol_id],
                    trio_token=self._trio_token,
                )
                # Run synchronously to ensure trio context is honored
                stream = runner()
            else:
                stream = await self._host.new_stream(pid, [protocol_id])
            return stream
        except Exception as e:
            logger.error(
                "Failed to open stream: %s: %r (trio=%s token_set=%s)",
                type(e).__name__,
                e,
                TRIO_AVAILABLE,
                self._trio_token is not None,
            )
            raise

    def set_stream_handler(self, protocol_id: str, handler: StreamHandler) -> None:
        """Register a handler for incoming streams."""
        self._handlers[protocol_id] = handler
        if self._host:
            self._host.set_stream_handler(protocol_id, handler)

    async def _handle_dcpp_stream(self, stream: StreamProtocol) -> None:
        """Handle incoming DCPP protocol stream with full envelope framing."""
        try:
            libp2p_stream = cast(Any, stream)
            # Read complete framed message with reliable buffering
            try:
                data = await read_framed_message(stream)
            except ConnectionError:
                # Clean close
                return
            except (MagicBytesError, FramingError, MessageTooLargeError, TimeoutError) as e:
                logger.warning(f"Frame read error - dropping connection: {e}")
                await stream.close()
                return

            # Decode with mandatory CRC verification
            try:
                result = DCPPFramer.decode(data)
            except ChecksumError as e:
                logger.warning(f"CRC mismatch - dropping frame: {e}")
                await stream.close()
                return
            except (MagicBytesError, FramingError) as e:
                logger.warning(f"Frame decode error - dropping frame: {e}")
                await stream.close()
                return

            msg_type = result.message_type
            payload = result.payload
            request_id = result.request_id

            remote_peer = cast(bytes, libp2p_stream.muxed_conn.peer_id.to_bytes())

            # Emit DCPP_REQUEST event with the stream for responding
            # Include request_id for correlation (MUST be echoed in response)
            await self._event_queue.put(
                HostEventData(
                    event_type=HostEvent.DCPP_REQUEST,
                    peer_id=remote_peer,
                    message_type=msg_type,
                    payload=payload,
                    stream=stream,
                    request_id=request_id,
                )
            )

            # Don't close stream - let caller respond via send_dcpp_response
        except Exception as e:
            logger.error(f"DCPP stream handling error: {e}")
            await stream.close()

    async def send_dcpp_request(
        self,
        peer_id: bytes,
        message_type: MessageType,
        payload: bytes,
    ) -> Optional[DCPPResponse]:
        """
        Send a DCPP protocol message to a peer with full envelope framing.

        Uses DCPPFramer with:
        - Magic bytes (REQUIRED)
        - Request ID for correlation (auto-generated)
        - CRC-32C checksum (MANDATORY)

        Args:
            peer_id: Target peer ID
            message_type: DCPP message type
            payload: CBOR-encoded payload

        Returns:
            DCPPResponse if successful, None otherwise
        """
        if not self._started or not self._host:
            return None

        try:
            # Encode request with full envelope framing (includes request ID)
            frame, request_id = DCPPFramer.encode_request(message_type, payload)

            if TRIO_AVAILABLE and self._trio_token is not None:
                try:
                    response_data = await asyncio.to_thread(
                        trio.from_thread.run,
                        self._send_dcpp_request_trio,
                        peer_id,
                        DCPP_PROTOCOL_ID,
                        frame,
                        trio_token=self._trio_token,
                    )
                except Exception as e:
                    logger.error(
                        "Failed to send DCPP request (trio): %s: %r",
                        type(e).__name__,
                        e,
                    )
                    return None
                if response_data is None:
                    return None
            else:
                stream = await self.new_stream(peer_id, DCPP_PROTOCOL_ID)

                # Write request frame
                await stream.write(frame)

                # Read response with reliable framing
                try:
                    response_data = await read_framed_message(stream)
                except ConnectionError:
                    logger.warning("Stream closed before response received")
                    return None
                except (MagicBytesError, FramingError, MessageTooLargeError, TimeoutError) as e:
                    logger.warning(f"Invalid response frame: {e}")
                    return None

            try:
                result = DCPPFramer.decode(response_data)

                # Verify request ID matches - MUST reject on mismatch per spec
                if result.request_id != request_id:
                    logger.error(
                        f"Request ID mismatch: sent {request_id}, got {result.request_id} - "
                        "treating as invalid response"
                    )
                    return None

                # Correlate response with original request
                DCPPFramer.correlate_response(result)

                return DCPPResponse(
                    message_type=result.message_type,
                    payload=result.payload,
                )
            except (ChecksumError, MagicBytesError, FramingError) as e:
                logger.warning(f"Invalid response frame: {e}")
                return None
        except Exception as e:
            logger.error(f"Failed to send DCPP request: {type(e).__name__}: {e!r}")
            await self._event_queue.put(
                HostEventData(
                    event_type=HostEvent.DCPP_REQUEST_FAILED,
                    peer_id=peer_id,
                    error=str(e),
                )
            )
            return None

    async def _send_dcpp_request_trio(
        self,
        peer_id: bytes,
        protocol_id: str,
        frame: bytes,
    ) -> Optional[bytes]:
        """Send a DCPP request via the trio host and return the raw response frame."""
        if self._host is None:
            return None
        pid = PeerID(peer_id)
        stream = await self._host.new_stream(pid, [protocol_id])
        try:
            await stream.write(frame)
            return await read_framed_message(stream)
        except ConnectionError:
            logger.warning("Stream closed before response received")
            return None
        except (MagicBytesError, FramingError, MessageTooLargeError, TimeoutError) as e:
            logger.warning(f"Invalid response frame: {e}")
            return None
        finally:
            try:
                await stream.close()
            except Exception:
                pass

    async def send_dcpp_response(
        self,
        stream: StreamProtocol,
        message_type: MessageType,
        payload: bytes,
        request_id: int = 0,
    ) -> bool:
        """
        Respond to an incoming DCPP protocol request with full envelope framing.

        The request_id from the original request MUST be echoed in the response
        to enable request/response correlation.

        Args:
            stream: The stream from a DCPP_REQUEST event
            message_type: Response message type
            payload: CBOR-encoded response payload
            request_id: The request ID to echo (from the original request)

        Returns:
            True if successful
        """
        try:
            # Encode response with full envelope, echoing the request ID
            frame = DCPPFramer.encode_response(message_type, payload, request_id)
            await stream.write(frame)
            await stream.close()
            return True
        except Exception as e:
            logger.error(f"Failed to send DCPP response: {e}")
            return False

    def connected_peers(self) -> List[bytes]:
        """Get list of connected peer IDs."""
        if not self._started or not self._host:
            return []

        # Use host.get_connected_peers() for the most accurate list
        # Note: peerstore contains all known peers, not just connected ones
        try:
            peers = cast(Any, self._host).get_connected_peers()
            return [cast(Any, p).to_bytes() for p in peers]
        except AttributeError:
            # Fallback for different libp2p versions
            try:
                peerstore = cast(Any, self._host).get_network().peerstore
                peers = peerstore.peer_ids()
                return [cast(Any, p).to_bytes() for p in peers]
            except AttributeError:
                return []

    async def next_event(self) -> Optional[HostEventData]:
        """Get the next event from the queue."""
        try:
            return await asyncio.wait_for(self._event_queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            return None

    async def bootstrap(self, peers: List[Tuple[bytes, str]]) -> None:
        """
        Bootstrap with known peers (RFC Section 9.3).

        Per Rust implementation parity, this method:
        1. Seeds the DHT routing table by adding each peer's address
        2. Dials each peer to establish connections
        3. Triggers Kademlia bootstrap to discover additional peers

        The routing table seeding is critical - without it, Kademlia has
        no starting points for its iterative lookup process.

        Args:
            peers: List of (peer_id, multiaddr) tuples for bootstrap nodes
        """
        if not peers:
            logger.debug("No bootstrap peers provided")
            return

        logger.info(f"Bootstrapping with {len(peers)} peers...")

        # Step 1: Connect to each bootstrap peer (also seeds routing table)
        connected = 0
        for peer_id, addr in peers:
            try:
                success = await self.connect(peer_id, [addr])
                if success:
                    connected += 1
                    logger.debug(f"Connected to bootstrap peer at {addr}")
                else:
                    logger.debug(f"Failed to connect to bootstrap peer at {addr}")
            except Exception as e:
                logger.warning(f"Bootstrap peer connection error ({addr}): {e}")

        # Step 2: Send BOOTSTRAP command to DHT to trigger Kademlia discovery
        if self._dht and connected > 0:
            await self._dht._bootstrap(peers)

        logger.info(f"Bootstrap complete: {connected}/{len(peers)} peers connected")

    # ========== DHT Operations ==========

    async def provide(self, key: bytes, multiaddrs: Optional[List[str]] = None) -> bool:
        """
        Announce as a provider for a key in the DHT.

        Args:
            key: DHT key (32 bytes)
            multiaddrs: Multiaddresses to announce (defaults to advertise_addrs, then listen_addrs)

        Returns:
            True if announcement succeeded
        """
        if not self._dht:
            logger.warning("DHT not enabled - cannot provide")
            return False

        # Priority: explicit multiaddrs > config advertise_addrs > listen_addrs
        addrs = multiaddrs or self._config.advertise_addrs or self._config.listen_addrs
        return await self._dht.provide(key, addrs)

    async def find_providers(self, key: bytes) -> List[ProviderRecord]:
        """
        Find providers for a key in the DHT.

        Args:
            key: DHT key (32 bytes)

        Returns:
            List of provider records
        """
        if not self._dht:
            logger.warning("DHT not enabled - cannot find providers")
            return []

        providers = await self._dht.find_providers(key)

        # Emit event for each provider found
        for provider in providers:
            await self._event_queue.put(
                HostEventData(
                    event_type=HostEvent.PROVIDER_FOUND,
                    peer_id=provider.node_id,
                    key=key,
                )
            )

        return providers

    async def put_dht_value(self, key: bytes, value: bytes) -> bool:
        """
        Store a value in the DHT.

        Args:
            key: DHT key (32 bytes)
            value: Value to store

        Returns:
            True if storage succeeded
        """
        if not self._dht:
            return False
        return await self._dht.put_value(key, value)

    async def get_dht_value(self, key: bytes) -> Optional[bytes]:
        """
        Retrieve a value from the DHT.

        Args:
            key: DHT key (32 bytes)

        Returns:
            Value bytes or None if not found
        """
        if not self._dht:
            return None
        return await self._dht.get_value(key)

    async def _process_dht_commands(self) -> None:
        """Process DHT commands from the command queue.

        If py-libp2p KadDHT is available and initialized, uses real DHT operations.
        Otherwise falls back to local cache behavior via dht_real.process_dht_command.
        """
        from dcpp_python.network.dht.kademlia import process_dht_command

        while self._started:
            try:
                command = await asyncio.wait_for(self._dht_command_queue.get(), timeout=1.0)

                # Try to use real py-libp2p KadDHT if available
                if KADDHT_AVAILABLE and self._libp2p_kad_dht is not None:
                    response = await self._process_dht_command_with_real_kad(command)
                else:
                    # Fall back to local cache / stub mode
                    response = process_dht_command(command, kademlia=None)

                if command.response_queue:
                    await command.response_queue.put(response)

            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"DHT command processing error: {e}")

    async def _process_dht_command_with_real_kad(self, command: DHTCommand) -> DHTResponse:
        """Process a DHT command using real py-libp2p KadDHT.

        Args:
            command: DHT command to process

        Returns:
            DHTResponse with result
        """
        try:
            if self._libp2p_kad_dht is None:
                return DHTResponse(success=False, error="KadDHT not initialized")
            kad = self._libp2p_kad_dht
            if command.command_type == DHTCommandType.PROVIDE:
                # Advertise as provider for this key (RFC Section 9.1)
                key_hex = command.key.hex()[:16]
                logger.info(f"[DHT NETWORK] Providing key: {key_hex}...")
                # py-libp2p KadDHT.provide() expects string key
                key_str = f"/dcpp/provider/{command.key.hex()}"
                success = bool(await self._run_kad_dht(kad.provide, key_str))
                if success:
                    logger.info(f"[DHT NETWORK] Successfully providing: {key_hex}...")
                else:
                    logger.warning(f"[DHT NETWORK] Failed to provide: {key_hex}...")
                return DHTResponse(success=success)

            elif command.command_type == DHTCommandType.FIND_PROVIDERS:
                # Find providers for this key (RFC Section 9.1)
                key_hex = command.key.hex()[:16]
                logger.info(f"[DHT NETWORK] Finding providers for: {key_hex}...")
                key_str = f"/dcpp/provider/{command.key.hex()}"
                providers = await self._run_kad_dht(kad.find_providers, key_str)
                provider_list = cast(list[object], providers or [])
                # Convert to ProviderRecord format
                provider_records = []
                for provider in provider_list:
                    provider_obj = cast(Any, provider)
                    provider_records.append(
                        ProviderRecord(
                            node_id=provider_obj.peer_id.to_bytes()
                            if hasattr(provider_obj.peer_id, "to_bytes")
                            else bytes(provider_obj.peer_id),
                            multiaddrs=[str(addr) for addr in getattr(provider_obj, "addrs", [])],
                            collection_id="",
                            timestamp=int(time.time()),
                            ttl=86400,
                        )
                    )
                logger.info(
                    f"[DHT NETWORK] Found {len(provider_records)} providers for: {key_hex}..."
                )
                return DHTResponse(success=True, data=provider_records)

            elif command.command_type == DHTCommandType.PUT_VALUE:
                # Store value in DHT
                key_str = f"/dcpp/value/{command.key.hex()}"
                await self._run_kad_dht(kad.put_value, key_str, command.value)
                return DHTResponse(success=True)

            elif command.command_type == DHTCommandType.GET_VALUE:
                # Retrieve value from DHT
                key_str = f"/dcpp/value/{command.key.hex()}"
                value = await self._run_kad_dht(kad.get_value, key_str)
                return DHTResponse(success=True, data=value)

            elif command.command_type == DHTCommandType.BOOTSTRAP:
                # Bootstrap with peers (seed routing table if API supports it)
                peers = command.peers or []
                logger.info(f"[DHT NETWORK] Bootstrapping with {len(peers)} peers")
                if not peers:
                    return DHTResponse(success=True)

                has_add_address = hasattr(kad, "add_address") and callable(
                    getattr(kad, "add_address")
                )
                has_bootstrap = hasattr(kad, "bootstrap") and callable(
                    getattr(kad, "bootstrap")
                )
                if not has_add_address or not has_bootstrap:
                    return DHTResponse(
                        success=False,
                        error="Kademlia backend missing add_address/bootstrap methods - wiring incomplete",
                    )

                added_count = 0
                for peer_id, addr in peers:
                    try:
                        peer_obj = None
                        if peer_id:
                            try:
                                peer_obj = cast(PeerIDFactory, PeerID)(peer_id)
                            except Exception:
                                peer_obj = None
                        if peer_obj is None:
                            try:
                                if "info_from_p2p_addr" in globals():
                                    info = cast(InfoFromP2PAddrProtocol, info_from_p2p_addr)(
                                        cast(MultiaddrFactory, multiaddr.Multiaddr)(addr)
                                    )
                                    peer_obj = info.peer_id
                            except Exception:
                                peer_obj = None
                        if peer_obj is None:
                            logger.warning(
                                f"[DHT NETWORK] Missing peer ID for bootstrap addr: {addr}"
                            )
                            continue

                        try:
                            addr_obj = cast(MultiaddrFactory, multiaddr.Multiaddr)(addr)
                        except Exception:
                            addr_obj = addr

                        await self._run_kad_dht(
                            self._libp2p_kad_dht.add_address, peer_obj, addr_obj
                        )
                        added_count += 1
                    except Exception as e:
                        logger.warning(f"[DHT NETWORK] Failed to add bootstrap peer {addr}: {e}")

                if added_count == 0:
                    return DHTResponse(
                        success=False,
                        error="Failed to add any bootstrap peers to routing table",
                    )

                try:
                    await self._run_kad_dht(self._libp2p_kad_dht.bootstrap)
                    return DHTResponse(success=True)
                except Exception as e:
                    logger.error(f"[DHT NETWORK] Bootstrap failed: {e}")
                    return DHTResponse(success=False, error=str(e))

            else:
                return DHTResponse(
                    success=False, error=f"Unknown command type: {command.command_type}"
                )

        except Exception as e:
            logger.error(f"[DHT NETWORK] Command failed: {e}")
            return DHTResponse(success=False, error=str(e))

    async def _run_kad_dht(self, func: Callable[..., Any], *args: object) -> Any:
        """Run KadDHT operations in the trio host thread when available."""
        if TRIO_AVAILABLE and self._trio_token is not None:
            if inspect.iscoroutinefunction(func):
                return await asyncio.to_thread(
                    trio.from_thread.run,
                    func,
                    *args,
                    trio_token=self._trio_token,
                )
            return await asyncio.to_thread(
                trio.from_thread.run_sync,
                func,
                *args,
                trio_token=self._trio_token,
            )
        result = func(*args)
        if inspect.isawaitable(result):
            return await result
        return result

    # ========== GossipSub Operations ==========

    async def subscribe(
        self, topic: str, handler: Optional[Callable[[str, bytes, Optional[bytes]], None]] = None
    ) -> bool:
        """
        Subscribe to a GossipSub topic.

        Behavior depends on DCPP_GOSSIPSUB_MODE environment variable:
        - local (default): Registers local handler only
        - network: Also subscribes via py-libp2p (requires wiring)

        Args:
            topic: Topic string (e.g., "/dcpp/1.0/collection/{collection_id}")
            handler: Optional callback for messages on this topic

        Returns:
            True if subscription succeeded
        """
        if not self._config.enable_gossipsub:
            logger.warning("GossipSub not enabled in config")
            return False

        mode = get_gossipsub_mode()
        self._subscribed_topics.add(topic)

        if handler:
            if topic not in self._topic_handlers:
                self._topic_handlers[topic] = []
            self._topic_handlers[topic].append(handler)

        # Log subscription with mode info
        handler_count = len(self._topic_handlers.get(topic, []))

        # Subscribe via real py-libp2p PubSub if available and in network mode
        if mode == GossipSubMode.NETWORK and self._libp2p_pubsub is not None:
            try:
                # Send subscription request to trio context via thread-safe queue
                self._subscription_queue.put(topic)
                logger.info(
                    f"[GossipSub NETWORK] Subscribed to topic '{topic}' "
                    f"({handler_count} handler(s)) - NETWORK subscription queued"
                )
            except Exception as e:
                logger.warning(f"[GossipSub] Failed to queue subscription for {topic}: {e}")
                logger.info(f"Falling back to local-only subscription for '{topic}'")
        elif mode == GossipSubMode.NETWORK:
            logger.info(
                f"[GossipSub NETWORK] Subscribed to topic '{topic}' "
                f"({handler_count} handler(s)) - local only (py-libp2p PubSub not available)"
            )
        else:
            logger.debug(
                f"[GossipSub LOCAL] Subscribed to topic '{topic}' ({handler_count} handler(s))"
            )

        await self._event_queue.put(
            HostEventData(
                event_type=HostEvent.GOSSIP_SUBSCRIBED,
                topic=topic,
            )
        )

        logger.info(f"Subscribed to topic: {topic}")
        return True

    async def unsubscribe(self, topic: str) -> bool:
        """
        Unsubscribe from a GossipSub topic.

        Args:
            topic: Topic string

        Returns:
            True if unsubscription succeeded
        """
        self._subscribed_topics.discard(topic)
        self._topic_handlers.pop(topic, None)
        logger.info(f"Unsubscribed from topic: {topic}")
        return True

    async def publish(self, topic: str, data: bytes) -> bool:
        """
        Publish a message to a GossipSub topic.

        Behavior depends on DCPP_GOSSIPSUB_MODE environment variable:
        - local (default): Calls local handlers only, no network transmission
        - network: Sends to network peers via py-libp2p (requires wiring)

        Args:
            topic: Topic string
            data: Message data

        Returns:
            True if publish succeeded
        """
        if not self._config.enable_gossipsub:
            logger.warning("GossipSub not enabled in config")
            return False

        mode = get_gossipsub_mode()

        # Local handler delivery (always performed)
        local_handlers_called = 0
        if topic in self._topic_handlers:
            for handler in self._topic_handlers[topic]:
                try:
                    handler(topic, data, self._local_peer_id)
                    local_handlers_called += 1
                except Exception as e:
                    logger.error(f"Topic handler error: {e}")

        # Network delivery (only in network mode)
        if mode == GossipSubMode.NETWORK:
            if self._libp2p_pubsub is not None:
                try:
                    # Use real py-libp2p PubSub to publish to network
                    await self._libp2p_pubsub.publish(topic, data)
                    logger.info(
                        f"[GossipSub NETWORK] Published {len(data)} bytes to topic '{topic}' "
                        f"(network + {local_handlers_called} local handlers)"
                    )
                except Exception as e:
                    logger.error(f"[GossipSub NETWORK] Failed to publish to network: {e}")
                    logger.info(
                        f"Message delivered to {local_handlers_called} local handler(s) only"
                    )
            else:
                logger.warning(
                    f"[GossipSub] NETWORK mode but py-libp2p PubSub not available. "
                    f"Message delivered to {local_handlers_called} local handler(s) only."
                )
        else:
            logger.debug(
                f"[GossipSub LOCAL] Published {len(data)} bytes to topic '{topic}' "
                f"({local_handlers_called} local handlers)"
            )

        return True

    def get_subscribed_topics(self) -> List[str]:
        """Get list of subscribed topics."""
        return list(self._subscribed_topics)


class DCPPRealNode:
    """DCPP Node using real libp2p.

    Provides collection-aware networking for DCPP with integrated
    DHT discovery and GossipSub announcements.
    """

    def __init__(self, config: RealHostConfig, collections: List[str]):
        self._host = RealHost(config)
        self._collections = set(collections)
        self._announced_collections: Set[str] = set()
        self._guardian_cache: Dict[str, List[ProviderRecord]] = {}

    @property
    def peer_id(self) -> bytes:
        """Get local peer ID."""
        return self._host.peer_id

    @property
    def host(self) -> RealHost:
        """Get the underlying host."""
        return self._host

    async def start(self, addrs: Optional[List[str]] = None) -> None:
        """Start the node."""
        await self._host.start()

        # Subscribe to collection topics
        for collection_id in self._collections:
            topic = self._collection_topic(collection_id)
            await self._host.subscribe(topic, self._handle_collection_message)
            logger.info(f"Subscribed to collection topic: {topic}")

    async def stop(self) -> None:
        """Stop the node."""
        # Unsubscribe from all topics
        for collection_id in self._collections:
            topic = self._collection_topic(collection_id)
            await self._host.unsubscribe(topic)

        await self._host.stop()

    async def bootstrap(self, peers: List[Tuple[bytes, str]]) -> None:
        """Bootstrap with known peers."""
        await self._host.bootstrap(peers)

    def set_advertise_addrs(self, addrs: List[str]) -> None:
        """
        Update advertise addresses for DHT provider records.

        This should be called after start() once the peer ID is known,
        allowing computed addresses to include /p2p/<peer_id> suffix.

        Args:
            addrs: Multiaddr strings to advertise (from compute_advertise_addrs)
        """
        self._host.set_advertise_addrs(addrs)

    async def announce_collection(
        self, collection_id: str, advertise_addrs: Optional[List[str]] = None
    ) -> bool:
        """
        Announce collection guardianship via DHT.

        Args:
            collection_id: Collection ID to announce
            advertise_addrs: Multiaddrs to include in provider record (defaults to listen addrs)

        Returns:
            True if announcement succeeded
        """
        dht_key = derive_dht_key(collection_id)
        logger.info(f"Providing on DHT for: {collection_id} (key: {dht_key.hex()})")
        success = await self._host.provide(dht_key, advertise_addrs)

        if success:
            self._announced_collections.add(collection_id)
            addr_count = len(advertise_addrs) if advertise_addrs else 0
            logger.info(
                f"Announced as guardian for: {collection_id} "
                f"({addr_count} advertise addr(s) in provider record)"
            )
        else:
            logger.warning(f"Failed to announce for: {collection_id}")

        return success

    async def find_guardians(self, collection_id: str) -> List[ProviderRecord]:
        """
        Find guardians for a collection via DHT.

        Args:
            collection_id: Collection ID

        Returns:
            List of provider records for guardians
        """
        dht_key = derive_dht_key(collection_id)
        providers = await self._host.find_providers(dht_key)

        # Cache the results
        self._guardian_cache[collection_id] = providers

        logger.info(f"Found {len(providers)} guardians for: {collection_id}")
        return providers

    async def publish_announcement(self, collection_id: str, data: bytes) -> bool:
        """
        Publish announcement to collection GossipSub topic.

        Args:
            collection_id: Collection ID
            data: CBOR-encoded ANNOUNCE message

        Returns:
            True if publish succeeded
        """
        topic = self._collection_topic(collection_id)
        success = await self._host.publish(topic, data)

        if success:
            logger.debug(f"Published announcement to: {topic}")
        else:
            logger.warning(f"Failed to publish to: {topic}")

        return success

    async def subscribe_collection(self, collection_id: str) -> bool:
        """
        Subscribe to a collection's GossipSub topic.

        Args:
            collection_id: Collection ID

        Returns:
            True if subscription succeeded
        """
        self._collections.add(collection_id)
        topic = self._collection_topic(collection_id)
        return await self._host.subscribe(topic, self._handle_collection_message)

    async def unsubscribe_collection(self, collection_id: str) -> bool:
        """
        Unsubscribe from a collection's GossipSub topic.

        Args:
            collection_id: Collection ID

        Returns:
            True if unsubscription succeeded
        """
        self._collections.discard(collection_id)
        topic = self._collection_topic(collection_id)
        return await self._host.unsubscribe(topic)

    def _handle_collection_message(
        self, topic: str, data: bytes, sender: Optional[bytes]
    ) -> None:
        """
        Handle incoming GossipSub message for a collection.

        Note: This is a sync function to work from both asyncio and trio contexts.
        Uses put_nowait() for thread-safe queue access.

        Args:
            topic: Topic string
            data: Message data
            sender: Sender peer ID
        """
        # Extract collection ID from topic
        if topic.startswith("/dcpp/1.0/collection/"):
            collection_id = topic[len("/dcpp/1.0/collection/") :]
        else:
            collection_id = "unknown"

        # Emit event for the message using put_nowait for thread-safety
        self._host._event_queue.put_nowait(
            HostEventData(
                event_type=HostEvent.GOSSIP_MESSAGE,
                peer_id=sender,
                topic=topic,
                data=data,
            )
        )

        sender_id = sender.hex()[:16] if sender else "unknown"
        logger.debug(f"Received message for collection {collection_id} from {sender_id}...")

    def _collection_topic(self, collection_id: str) -> str:
        """Get GossipSub topic for a collection."""
        return f"/dcpp/1.0/collection/{collection_id}"

    async def next_event(self) -> Optional[HostEventData]:
        """Get next event."""
        return await self._host.next_event()

    def connected_peers(self) -> List[bytes]:
        """Get connected peers."""
        return self._host.connected_peers()

    def get_announced_collections(self) -> List[str]:
        """Get list of collections we've announced guardianship for."""
        return list(self._announced_collections)

    def get_subscribed_collections(self) -> List[str]:
        """Get list of collections we're subscribed to."""
        return list(self._collections)


def is_available() -> bool:
    """Check if real libp2p is available."""
    return LIBP2P_AVAILABLE
