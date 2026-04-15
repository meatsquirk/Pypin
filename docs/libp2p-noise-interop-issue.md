# Cross-Implementation libp2p Interop Failure: Noise Negotiation

**Status**: Open — blocked on upstream py-libp2p fix (no release > 0.2.7 available)

## Summary

Interop failure occurs at the libp2p **security upgrade step** (Noise
handshake), not at the application or GossipSub layer. Because security
negotiation happens before any protocol streams are opened, this failure
blocks all higher-level communication — including GossipSub ANNOUNCE
propagation — and causes TC-004 to fail.

| Component | Version |
|-----------|---------|
| Python    | py-libp2p **0.2.7** (latest on PyPI as of 2025-01) |
| Rust      | rust-libp2p **0.54** (libp2p-noise 0.44, Noise + Yamux defaults) |

## Observed Behaviour

Python node logs show repeated:

```
failed to upgrade security for peer ... failed to negotiate the secure protocol
```

The failure happens **after** multistream-select successfully agrees on
`/noise`, **during** the Noise XX handshake itself.

## Expected Behaviour

Per the [libp2p Noise specification](https://github.com/libp2p/specs/blob/master/noise/README.md),
Rust and Python nodes should:

1. Negotiate `/noise` via multistream-select — **this succeeds**
2. Complete the `Noise_XX_25519_ChaChaPoly_SHA256` handshake using **X25519** static keys
3. Establish an encrypted channel, then negotiate a stream multiplexer
4. Open GossipSub streams and propagate messages (ANNOUNCE, etc.)

Step 2 fails.

## Protocol Background

### How libp2p Connection Establishment Works

Connection establishment follows a strict layered sequence defined in the
[libp2p connections spec](https://github.com/libp2p/specs/blob/master/connections/README.md):

```
TCP connect
  └─► multistream-select: agree on security protocol (/noise)
        └─► Noise XX handshake (3 messages)          ← FAILURE HERE
              └─► multistream-select: agree on muxer (/yamux/1.0.0)
                    └─► Open substreams (GossipSub, DCPP, KadDHT, etc.)
```

Because security negotiation is the **first** post-TCP step, a failure here
prevents everything above it — muxer negotiation, stream creation, and all
application protocols.

### The Noise XX Handshake

The libp2p Noise spec mandates a single handshake pattern:

```
Noise_XX_25519_ChaChaPoly_SHA256

  -> e              (initiator sends ephemeral X25519 key)
  <- e, ee, s, es  (responder: ephemeral key, DH, static key, DH)
  -> s, se          (initiator: static key, DH)
```

Key requirements from the spec:

- **DH function `25519`** operates on the **Montgomery curve (X25519)**, per
  [RFC 7748 §5](https://tools.ietf.org/html/rfc7748#section-5).
- **Static keys** used in the Noise handshake **must be X25519 keys**, separate
  from the libp2p identity key (Ed25519, Edwards curve).
- The spec explicitly states: *"None of the key types supported by libp2p for
  use as identity keys are fully compatible with Noise."*
- The **signature** authenticating the static key signs:
  `"noise-libp2p-static-key:" + X25519_static_pubkey_bytes`
  using the Ed25519 identity private key.

### Wire Framing and Payload Format

| Element | Spec Requirement |
|---------|-----------------|
| Wire framing | 2-byte big-endian length prefix + Noise message |
| Handshake payload | Raw protobuf (no inner length prefix) |
| Prologue | Empty (zero-length, both peers must agree) |

The handshake payload protobuf:

```protobuf
message NoiseHandshakePayload {
    optional bytes identity_key = 1;
    optional bytes identity_sig = 2;
    optional NoiseExtensions extensions = 4;
}

message NoiseExtensions {
    repeated bytes webtransport_certhashes = 1;
    repeated string stream_muxers = 2;
}
```

## Root Cause: Ed25519 Used as Noise Static Key in py-libp2p 0.2.7

py-libp2p 0.2.7 violates the Noise spec by using **Ed25519 keys directly as
the Noise static DH key**. In the source (`libp2p/security/noise/patterns.py`),
`_get_pubkey_from_noise_keypair` uses `Ed25519PublicKey.from_bytes()` for the
static key, while declaring the protocol name as
`Noise_XX_25519_ChaChaPoly_SHA256` (which mandates X25519 DH).

### Exact Failure Sequence

**When py-libp2p is the responder** (message 2, `<- e, ee, s, es`):

1. py-libp2p sends its static key `s` as **Ed25519 bytes** (32-byte Edwards
   curve point).
2. The remote rust-libp2p peer interprets these bytes as an **X25519
   Montgomery u-coordinate** and performs X25519 scalar multiplication.
3. Because Edwards and Montgomery representations differ, the `es` DH
   produces an **incorrect shared secret**.
4. The CipherState derived from the wrong shared secret fails to decrypt
   subsequent messages — **MAC mismatch**, handshake aborts.

**When py-libp2p is the initiator** (message 3, `-> s, se`):

Same failure at the `se` DH step — wrong key type produces wrong shared
secret, MAC verification fails.

**Even if DH somehow completed** (it won't, but for completeness):

The signature verification would also fail. py-libp2p signs:

```
"noise-libp2p-static-key:" + Ed25519_pubkey_bytes
```

But rust-libp2p verifies:

```
"noise-libp2p-static-key:" + received_bytes  (interpreted as X25519)
```

The signed data doesn't match the verification data, so the signature check
fails independently.

### Compliance Summary

| Requirement | Spec | py-libp2p 0.2.7 | rust-libp2p 0.54 |
|---|---|---|---|
| Protocol ID | `/noise` | `/noise` | `/noise` |
| Protocol name | `Noise_XX_25519_ChaChaPoly_SHA256` | matches | matches |
| Handshake pattern | XX | XX | XX |
| **Static key type** | **X25519 (Montgomery)** | **Ed25519 (Edwards)** | **X25519** |
| Signature prefix | `noise-libp2p-static-key:` | matches | matches |
| **Signed data** | prefix + **X25519** bytes | prefix + **Ed25519** bytes | prefix + X25519 bytes |
| Wire framing | 2-byte BE length prefix | matches | matches |
| Payload format | Raw protobuf | matches | matches |
| Prologue | Empty | Empty | Empty |

## rust-libp2p Noise History (Context)

rust-libp2p tightened its Noise implementation across several releases:

| libp2p-noise version | Shipped with | Change |
|---|---|---|
| v0.42.2 | ~rust-libp2p 0.52 | Deprecated all non-XX patterns, `NoiseConfig`, `NoiseAuthenticated` ([PR #3768](https://github.com/libp2p/rust-libp2p/pull/3768)) |
| v0.43.0 | ~rust-libp2p 0.53 | **Removed** all deprecated APIs, legacy payload handling ([PR #3511](https://github.com/libp2p/rust-libp2p/pull/3511)) |
| v0.44.0 | rust-libp2p 0.54 | Migrated to `{In,Out}boundConnectionUpgrade` traits (API change, no wire change) |

Historical note: the go-libp2p/rust-libp2p **length-prefix disagreement**
([rust-libp2p#1631](https://github.com/libp2p/rust-libp2p/issues/1631)) was
resolved in earlier versions (v0.21–v0.24 transition) and is not the issue
here. Modern rust-libp2p sends and expects raw protobuf payloads (no inner
length prefix).

## Related Issues and Specs

### Specifications
- [libp2p Noise spec](https://github.com/libp2p/specs/blob/master/noise/README.md) — mandates X25519 static keys, XX pattern, signature format
- [libp2p connections spec](https://github.com/libp2p/specs/blob/master/connections/README.md) — multistream-select and connection upgrade flow
- [Noise Protocol Framework](https://noiseprotocol.org/noise.html) — `25519` DH function defined as X25519
- [RFC 7748](https://tools.ietf.org/html/rfc7748) — X25519 / Curve25519 specification

### GitHub Issues
- [libp2p/specs#195](https://github.com/libp2p/specs/issues/195) — Standardize Noise handshake for libp2p
- [libp2p/specs#246](https://github.com/libp2p/specs/issues/246) — Noise Pipes fallback (led to removing IK/XXfallback)
- [libp2p/rust-libp2p#1631](https://github.com/libp2p/rust-libp2p/issues/1631) — rust/go Noise payload framing disagreement (resolved)
- [libp2p/specs#593](https://github.com/libp2p/specs/issues/593) — Ed25519 signature verification rule inconsistencies

## Impact on DCPP

Because this project uses libp2p as its control plane
([DCPP RFC Wire Protocol](DCPP-RFC-Wire-Protocol.md)), the Noise failure
blocks:

- **GossipSub ANNOUNCE propagation** — peers cannot form a mesh
- **KadDHT peer/content discovery** — DHT queries cannot traverse the network
- **Direct DCPP protocol streams** (`/dcpp/1.0.0`) — all framed message exchange
- **TC-004 test case** — cross-implementation interop test fails

The `real.py` implementation (`src/dcpp_python/network/libp2p/real.py`) already
includes try/except fallback imports anticipating a future py-libp2p 0.5.x API,
but the underlying Noise static key bug is in the library itself.

## Mitigation Options

### Option 1: Wait for upstream fix (recommended)

File an issue on [libp2p/py-libp2p](https://github.com/libp2p/py-libp2p/issues)
requesting X25519 key separation in the Noise transport. The fix requires:

1. Generate a separate X25519 keypair for the Noise static key (do not reuse
   the Ed25519 identity key)
2. Sign `"noise-libp2p-static-key:" + X25519_static_pubkey_bytes` with the
   Ed25519 identity key
3. Send the X25519 static public key as the Noise `s` value in the handshake

### Option 2: Patch py-libp2p locally

Fork py-libp2p and apply the X25519 key separation patch. This involves
modifying `libp2p/security/noise/patterns.py` to:

- Generate X25519 static keys using `cryptography` or `pynacl`
  (`nacl.bindings.crypto_scalarmult_ed25519_base_noclamp` or
  `nacl.bindings.crypto_sign_ed25519_sk_to_curve25519`)
- Convert the Ed25519 signing key to X25519 for DH, or generate an
  independent X25519 keypair
- Update the signature computation to sign the X25519 public key bytes

### Option 3: Use stub/simulated libp2p for testing

The project already supports `DCPP_STUB_MODE=1` with a simulated libp2p host
(`libp2p_host.py`). This allows development and testing of the DCPP protocol
layer without depending on the real libp2p transport. Cross-implementation
interop testing is deferred until the upstream fix lands.
