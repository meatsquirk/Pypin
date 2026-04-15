"""
Peer ID formatting helpers.

libp2p peer IDs are base58btc-encoded multihashes. These helpers provide
minimal base58 encoding and safe display formatting without extra deps.
"""

from __future__ import annotations

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {ch: i for i, ch in enumerate(BASE58_ALPHABET)}


def base58_encode(data: bytes) -> str:
    """Encode bytes to Base58 (Bitcoin alphabet)."""
    if not data:
        return ""

    num = int.from_bytes(data, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = BASE58_ALPHABET[rem] + encoded

    # Preserve leading zero bytes as '1'
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return ("1" * pad) + encoded


def base58_decode(data: str) -> bytes:
    """Decode Base58 (Bitcoin alphabet) string to bytes."""
    if not data:
        return b""

    num = 0
    for ch in data:
        if ch not in BASE58_INDEX:
            raise ValueError(f"Invalid base58 character: {ch!r}")
        num = num * 58 + BASE58_INDEX[ch]

    # Convert to bytes (big-endian)
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num > 0 else b""

    # Restore leading zero bytes from leading '1's
    pad = 0
    for ch in data:
        if ch == "1":
            pad += 1
        else:
            break
    return (b"\x00" * pad) + full


def format_peer_id(peer_id: bytes | None) -> str:
    """
    Format a peer ID as base58, preserving already-encoded strings.
    """
    if not peer_id:
        return "unknown"

    try:
        decoded = peer_id.decode("ascii")
        if decoded and all(ch in BASE58_ALPHABET for ch in decoded):
            return decoded
    except UnicodeDecodeError:
        pass

    return base58_encode(peer_id)
