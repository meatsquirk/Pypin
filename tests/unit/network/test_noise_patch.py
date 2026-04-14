"""Regression tests for Noise X25519 interop behavior.

These tests verify the behavior we need from py-libp2p after upstream fixes:
- Noise payloads are signed over a dedicated X25519 static key
- Fixed upstream builds reject Ed25519 keys as the Noise static DH key
- This project reports whether it is using upstream behavior or the local patch
"""

import pytest

pytest.importorskip("libp2p")

from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.crypto.x25519 import create_new_key_pair as create_x25519_key_pair
from libp2p.peer.id import ID
from libp2p.security.noise.exceptions import NoiseStateError
from libp2p.security.noise.messages import (
    NoiseHandshakePayload,
    make_data_to_be_signed,
    make_handshake_payload_sig,
    verify_handshake_payload_sig,
)
from libp2p.security.noise.patterns import PatternXX

from dcpp_python.network.libp2p.real import (
    NOISE_NATIVE_FIX_AVAILABLE,
    NOISE_PATCH_APPLIED,
)


@pytest.fixture(autouse=True)
def _ensure_noise_compatibility_present():
    if not (NOISE_NATIVE_FIX_AVAILABLE or NOISE_PATCH_APPLIED):
        pytest.skip("No Noise interop support detected")


def test_noise_payload_signs_x25519_static_key():
    """The signed Noise payload must use the X25519 static public key bytes."""
    identity_kp = create_new_key_pair()
    noise_kp = create_x25519_key_pair()

    sig = make_handshake_payload_sig(identity_kp.private_key, noise_kp.public_key)
    assert len(sig) == 64
    assert make_data_to_be_signed(noise_kp.public_key) == (
        b"noise-libp2p-static-key:" + noise_kp.public_key.to_bytes()
    )

    payload = NoiseHandshakePayload(identity_kp.public_key, sig)
    assert verify_handshake_payload_sig(payload, noise_kp.public_key)


def test_runtime_exposes_upstream_fix_or_local_patch():
    """The project should detect either the upstream fix or the local fallback patch."""
    assert NOISE_NATIVE_FIX_AVAILABLE or NOISE_PATCH_APPLIED


@pytest.mark.skipif(
    not NOISE_NATIVE_FIX_AVAILABLE,
    reason="requires upstream py-libp2p Noise/X25519 fix",
)
def test_upstream_fix_rejects_ed25519_as_noise_static_key():
    """Fixed upstream builds reject Ed25519 keys as the Noise static DH key."""
    identity_kp = create_new_key_pair()
    local_peer = ID.from_pubkey(identity_kp.public_key)
    pattern = PatternXX(local_peer, identity_kp.private_key, identity_kp.private_key)

    with pytest.raises(NoiseStateError):
        pattern.make_handshake_payload()
