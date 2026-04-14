# DCPP Wire Protocol Specification

## RFC: DCPP/1.0 Wire Protocol

**Status:** Draft

**Version:** 0.1

**Date:** January 2026

**Authors:** [Matthew Quirk]

---

## Abstract

This document specifies the wire protocol for the Distributed Content Preservation Protocol (DCPP). DCPP is a protocol for collective preservation of data, with a particular focus toward blockchain-referenced content, built on top of libp2p (control plane), BitTorrent (data plane), and IPFS (content addressing).

This specification defines:
- Protocol identifiers and versioning
- Message formats and serialization
- Node discovery and announcement
- Collection manifest exchange
- Health probing and verification
- Integration with BitTorrent for bulk data transfer

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Protocol Stack](#3-protocol-stack)
4. [Protocol Identifiers](#4-protocol-identifiers)
5. [Message Format](#5-message-format)
6. [Message Types](#6-message-types)
7. [Node State Machine](#7-node-state-machine)
8. [Collection Manifest](#8-collection-manifest)
9. [Peer Discovery](#9-peer-discovery)
10. [Health Probing](#10-health-probing)
11. [Collection Sharding](#11-collection-sharding)
12. [BitTorrent Integration](#12-bittorrent-integration)
13. [Security Considerations](#13-security-considerations)
14. [IANA Considerations](#14-iana-considerations)

---

## 1. Introduction

### 1.1 Purpose

DCPP enables collective preservation of personal content, NFT collections and other blockchain-referenced content. Participants who care about specific collections store and serve that content, creating redundancy through aligned self-interest rather than payment.

### 1.2 Design Goals

1. **Interoperability:** Any conforming implementation must interoperate
2. **Simplicity:** Minimal message types, clear semantics
3. **Efficiency:** Leverage existing protocols (libp2p, BitTorrent) rather than reinvent
4. **Reliability:** System continues functioning despite node failures or churn
5. **Availability:** Content remains accessible when at least one guardian is online
6. **Fault Tolerance:** No single point of failure; graceful degradation under stress
7. **Flexibility:** Support diverse deployment scenarios (single user to large networks)

### 1.3 Scope

This specification covers:
- Control plane messages over libp2p
- Coordination with BitTorrent data plane
- Node behavior and state transitions

This specification does NOT cover:
- Application-layer concerns (UI, storage backends)
- Blockchain interaction (chain-specific adapters)
- IPFS internals (uses IPFS as black box for CID operations)

### 1.4 Relationship to Other Protocols

```
┌─────────────────────────────────────────┐
│            DCPP/1.0 (this spec)         │
├─────────────┬─────────────┬─────────────┤
│   libp2p    │ BitTorrent  │    IPFS     │
│  (control)  │   (data)    │  (content)  │
└─────────────┴─────────────┴─────────────┘
```

---

## 2. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

| Term | Definition |
|------|------------|
| **Node** | A participant in the DCPP network running a conforming implementation |
| **Collection** | A logical grouping of content identified by a Collection ID scheme |
| **Sub-Collection** | A logical grouping within a collection (e.g., by trait, series, or token range) |
| **Guardian** | A node that stores and serves content for a specific collection |
| **Full Guardian** | A guardian that stores a complete collection (all tokens) |
| **Shard Guardian** | A guardian that stores one or more complete shards of a sharded collection |
| **Partial Guardian** | A guardian with incomplete content (syncing or degraded state) |
| **Observer** | A node that monitors collection health but does not store content |
| **Swarm** | The set of all guardians currently serving a specific collection |
| **Quorum** | Minimum number of guardians required for acceptable availability (implementation-defined) |
| **Manifest** | Canonical record of a collection's contents, structure, and metadata |
| **Collection ID** | The root-of-trust identifier for a collection, expressed as `{scheme}:{value}` |
| **CID** | Content Identifier (IPFS) - self-describing content-addressed hash |
| **Shard** | A subset of a collection assigned to a node for storage |
| **Peer ID** | libp2p peer identifier (public key hash) |

---

## 3. Protocol Stack

### 3.1 Transport Layer

DCPP control messages are transported over libp2p streams. Implementations MUST support:
- TCP transport
- QUIC transport (RECOMMENDED for performance)
- Noise encryption (required by libp2p)

Implementations SHOULD support:
- WebSocket transport (enables browser-based light clients and web interfaces)

#### 3.1.1 Raw TCP (Test Only)

Raw TCP (without libp2p) MAY be used for local testing and interoperability experiments, but MUST NOT be used in production networks. When raw TCP is used, messages MUST still use the full DCPP envelope defined in Section 5.1.

### 3.2 Data Layer

Bulk content transfer uses BitTorrent protocol. Each collection (or shard) is represented as a torrent with:
- Infohash derived from collection manifest
- Piece size appropriate for collection size
- BitTorrent v2 protocol (BEP 52) - REQUIRED for SHA-256 piece integrity

### 3.3 Content Addressing

All content is addressed using IPFS CIDv1. Implementations MUST use consistent parameters for interoperability:
- **Multibase:** base32 (RFC 4648, lowercase)
- **Multihash:** sha2-256 (0x12)
- **Multicodec:** dag-pb (0x70) for directories, raw (0x55) for files
- **CID version:** 1

Implementations MUST verify content against CID before accepting. See [IPFS CID Specification](https://github.com/multiformats/cid) for encoding details.

---

## 4. Protocol Identifiers

### 4.1 libp2p Protocol ID

```
/dcpp/1.0.0
```

Version follows semantic versioning. Implementations MUST reject unsupported protocol versions.

### 4.2 Protocol Negotiation

Nodes advertise DCPP support via libp2p protocol negotiation. Multiple versions MAY be supported simultaneously for backwards compatibility.

### 4.3 Collection Identifier Schemes (UCI)

DCPP uses a Universal Collection Identifier (UCI) scheme to decouple identity from verification. The Collection ID is the root of trust; verification rules are determined by the scheme.

**Format:** `{scheme}:{value}`

**Standard Schemes:**

| Scheme | Format | Verification Logic (Truth) | Use Case |
|--------|--------|----------------------------|----------|
| `chain` | `chain:{chain_id}:{network}:{contract}` | Query chain state (token URIs) and verify manifest matches | NFTs, DAOs, on-chain history |
| `key` | `key:{algorithm}:{pubkey}` | Manifest MUST be signed by this key | Personal backups, friend networks, mutable datasets |
| `hash` | `hash:{algorithm}:{hash}` | Manifest merkle_root MUST equal the hash | IPFS snapshots, software releases |
| `uuid` | `uuid:{uuid}` | Trust-on-first-use (TOFU) for the first valid manifest | Ad-hoc sharing, scratchpads |
| `dns` | `dns:{domain}` | Fetch via HTTPS and/or DNSSEC for `/dcpp-manifest.json` | Institutional archives, Web 2.0 bridges |

**Examples:**
- `chain:eth:mainnet:0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D` (BAYC on Ethereum mainnet)
- `key:ed25519:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY` (Ed25519 public key, Base58)
- `hash:sha256:bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi` (SHA-256 hash as CID)
- `uuid:123e4567-e89b-12d3-a456-426614174000`
- `dns:archive.org`

Implementations MAY support additional schemes. Unknown schemes MUST be treated as unverifiable unless explicitly configured by the operator.

**Implementation Note:** For `chain` and `dns` schemes, verification may require external adapters or async HTTP fetching. Implementations MAY treat these schemes as "unverifiable" (skipped) if the required adapter is not configured, in which case ANNOUNCE handling SHOULD accept the manifest with a warning rather than rejecting it outright.

---

## 5. Message Format

### 5.1 Envelope

All DCPP messages MUST use a common envelope format on all transports:

```
┌─────────────────────────────────────────┐
│  Magic (4 bytes): 0x44435050 ("DCPP")   │
├─────────────────────────────────────────┤
│  Version (2 bytes): 0x0100 (v1.0)       │
├─────────────────────────────────────────┤
│  Type (2 bytes): Message type code      │
├─────────────────────────────────────────┤
│  Request ID (4 bytes): Correlation ID   │  <- NEW: Tracing/Response matching
├─────────────────────────────────────────┤
│  Length (4 bytes): Payload length       │
├─────────────────────────────────────────┤
│  CRC32 (4 bytes): Payload checksum      │
├─────────────────────────────────────────┤
│  Payload (variable): Message-specific   │
└─────────────────────────────────────────┘
```

Total header size: 20 bytes

#### 5.1.1 Magic Bytes

Implementations MUST include magic bytes. Receivers MUST validate the magic bytes before attempting to parse the rest of the header.

#### 5.1.2 Request ID (Correlation)

The `Request ID` is a random 4-byte integer generated by the sender.
- **Requests:** Sender generates a new ID.
- **Responses:** Responder MUST echo the request's ID in this field.
- **Notifications (e.g. ANNOUNCE):** Sender generates a new ID; receivers log it for tracing.

This enables asynchronous multiplexing of multiple in-flight requests/responses over a single stream and distributed tracing. Responses may arrive out of order and are matched via Request ID.

#### 5.1.3 CRC32 Checksum

The CRC32 field contains a CRC-32C (Castagnoli) checksum of the payload bytes. This provides an additional integrity check beyond transport-level guarantees, catching implementation bugs and memory corruption. Receivers MUST verify the checksum and discard messages with mismatches.

### 5.2 Serialization

Message payloads are serialized using CBOR (RFC 8949). CBOR is chosen for:
- Compact binary representation
- Schema flexibility
- Wide library support
- Self-describing format

### 5.3 Maximum Message Size

Messages MUST NOT exceed 32 MB (33,554,432 bytes). Implementations MUST reject messages exceeding this limit without processing.

---

## 6. Message Types

### 6.1 Message Type Codes

| Code | Name | Direction | Description |
|------|------|-----------|-------------|
| 0x0001 | HELLO | Bidirectional | Initial handshake |
| 0x0002 | ANNOUNCE | Broadcast | Announce collections this node guards |
| 0x0003 | GET_MANIFEST | Request | Request collection manifest |
| 0x0004 | MANIFEST | Response | Collection manifest response |
| 0x0005 | GET_PEERS | Request | Request peers for a collection |
| 0x0006 | PEERS | Response | List of peers for a collection |
| 0x0007 | HEALTH_PROBE | Request | Verify node has specific content |
| 0x0008 | HEALTH_RESPONSE | Response | Response to health probe |
| 0x0009 | GOODBYE | Notification | Graceful disconnect |
| 0x00FF | ERROR | Response | Error response |

### 6.2 HELLO (0x0001)

Sent immediately after libp2p stream is established. Both peers send HELLO.

```cbor
{
  "version": "1.0.0",           ; Protocol version
  "node_id": bytes,             ; libp2p Peer ID
  "capabilities": [string],     ; Supported capabilities
  "collections": [string],      ; Collection IDs this node is interested in
  "timestamp": uint64           ; Unix timestamp (seconds)
}
```

**Capabilities:**
- `"guardian"` - Node stores and serves content
- `"seeder"` - Node participates in BitTorrent seeding
- `"observer"` - Node monitors health but does not store content
- `"light"` - Node only queries, does not serve

**Forward Compatibility:**
Receivers MUST ignore any `capabilities` strings they do not understand. This allows future protocol versions to add new capabilities without breaking older nodes.

**Collection Declaration:**
- Nodes with `"guardian"` capability MUST include their guarded collections
- Other nodes MAY include collections of interest for optimized peer matching

### 6.3 ANNOUNCE (0x0002)

Broadcast to pub/sub topic to announce guardianship. Sent periodically and on changes.

**Rate Limiting:** Nodes SHOULD NOT broadcast ANNOUNCE more frequently than once every 5 minutes per collection. Receivers MAY ignore announcements from nodes exceeding this rate.

**Genesis Announcement:** When a node announces a collection that the receiver has no record of, the announcing node MUST be able to provide the manifest immediately or upon the receiver's first GET_MANIFEST request for that collection.

**BitTorrent Status:** Nodes MAY include an explicit BitTorrent status per collection. If present, it MUST be one of: `"none"`, `"leeching"`, `"seeding"`, `"paused"`, `"error"`.

```cbor
{
  "node_id": bytes,
  "collections": [
    {
      "id": string,             ; Collection ID ({scheme}:{value})
      "manifest_cid": string,   ; CID of current manifest
      "coverage": float,        ; 0.0-1.0, fraction of collection stored
      "bt_status": string,      ; OPTIONAL: "none" | "leeching" | "seeding" | "paused" | "error"
      "shard_ids": [uint32]     ; Which shards this node holds (if sharded)
    }
  ],
  "timestamp": uint64,
  "signature": bytes            ; Signed by node's libp2p key
}
```

### 6.4 GET_MANIFEST (0x0003)

Request a collection's manifest from a peer.

```cbor
{
  "collection_id": string,      ; Collection ID
  "version": uint32 | null,     ; Specific version, or null for latest
  "since_version": uint32 | null ; If set, return diff since this version
}
```

**Diff Mode:** When `since_version` is set, the response MANIFEST SHOULD include only items that changed since the specified version. If the responder cannot provide a diff (e.g., version too old), it MUST return the full manifest.

### 6.5 MANIFEST (0x0004)

Response containing collection manifest. See Section 8 for manifest structure.

```cbor
{
  "collection_id": string,
  "manifest": Manifest,         ; Full manifest object
  "signature": bytes            ; Required for `key` scheme, optional otherwise
}
```

### 6.6 GET_PEERS (0x0005)

Request peers who guard a specific collection.

```cbor
{
  "collection_id": string,
  "shard_id": uint32 | null,    ; Specific shard, or null for any
  "max_peers": uint32           ; Maximum peers to return (default: 20)
}
```

### 6.7 PEERS (0x0006)

Response with peer information.

```cbor
{
  "collection_id": string,
  "peers": [
    {
      "node_id": bytes,
      "multiaddrs": [string],   ; libp2p multiaddresses
      "coverage": float,
      "last_seen": uint64,      ; Unix timestamp
      "response_quality": float ; 0.0-1.0, based on probe response times (see 10.4)
    }
  ]
}
```

**Empty Response:** If the collection is known but no peers are available, return an empty `peers` array. Only return UNKNOWN_COLLECTION error if the collection ID itself is not recognized.

**Response Quality:** Value of 1.0 indicates consistently fast probe responses (likely local storage). Lower values indicate slower responses. Nodes with no probe history SHOULD have `response_quality` of 0.5 (unknown).

### 6.8 HEALTH_PROBE (0x0007)

Request to verify node has specific content. Used for proof-of-storage.

```cbor
{
  "collection_id": string,
  "challenges": [
    {
      "cid": string,            ; CID to verify
      "offset": uint64,         ; Byte offset into content
      "length": uint32          ; Number of bytes to return (max 1024)
    }
  ],
  "nonce": bytes                ; Random nonce to prevent replay
}
```

### 6.9 HEALTH_RESPONSE (0x0008)

Response to health probe.

```cbor
{
  "nonce": bytes,               ; Echo back nonce
  "responses": [
    {
      "cid": string,
      "data": bytes | null,     ; Requested bytes, or null if not available
      "error": string | null    ; Error message if data unavailable
    }
  ]
}
```

### 6.10 GOODBYE (0x0009)

Graceful disconnect notification.

```cbor
{
  "reason": string,             ; "shutdown" | "maintenance" | "leaving_collection"
  "collections": [string]       ; Collections being abandoned (if leaving)
}
```

### 6.11 ERROR (0x00FF)

Error response to any request.

```cbor
{
  "code": uint32,               ; Error code
  "message": string,            ; Human-readable message
  "request_type": uint16        ; Type of request that caused error
}
```

**Error Codes:**

| Code | Name | Description |
|------|------|-------------|
| 1 | UNKNOWN_COLLECTION | Collection ID not recognized |
| 2 | MANIFEST_NOT_FOUND | Manifest not available |
| 3 | INVALID_REQUEST | Malformed request |
| 4 | RATE_LIMITED | Too many requests |
| 5 | INTERNAL_ERROR | Node internal error |
| 6 | BUSY_TRY_LATER | Node overloaded, retry after backoff |

---

## 7. Node State Machine

### 7.1 Node States

```
┌─────────────┐
│   OFFLINE   │
└──────┬──────┘
       │ start
       ▼
┌─────────────┐
│ CONNECTING  │──────────────────┐
└──────┬──────┘                  │
       │ connected               │ failed
       ▼                         ▼
┌─────────────┐           ┌─────────────┐
│    READY    │◄──────────│  DEGRADED   │
└──────┬──────┘  recover  └─────────────┘
       │
       │ (per collection)
       ▼
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  SYNCING    │────▶│  GUARDING   │─ ─ ▶│   SEEDING   │
└─────────────┘     └─────────────┘     └─────────────┘
                                         (optional)
```

**Recommended Timeouts:**
- CONNECTING → DEGRADED: SHOULD timeout after 60 seconds if no peers found
- DEGRADED recovery attempts: SHOULD retry every 30 seconds
- SYNCING timeout: Implementation-defined based on collection size

### 7.2 State Descriptions

| State | Description |
|-------|-------------|
| OFFLINE | Node not running |
| CONNECTING | Establishing libp2p connections |
| READY | Connected to network, not yet guarding any collections |
| SYNCING | Downloading collection content |
| GUARDING | Have content, responding to probes and DCPP requests |
| SEEDING | (Optional) Actively seeding via BitTorrent in addition to GUARDING |
| DEGRADED | Connectivity issues, limited functionality |

**Note:** SEEDING is an optional enhancement. Nodes MAY remain in GUARDING state and serve content only via DCPP protocol. SEEDING enables faster bulk transfers for new guardians joining the swarm.

### 7.3 Collection States (per collection)

| State | Description |
|-------|-------------|
| UNKNOWN | Not tracking this collection |
| INTERESTED | Want to guard, haven't started sync |
| SYNCING | Downloading content |
| COMPLETE | Have full collection/shard |
| PARTIAL | Have partial content (resumable) |
| STALE | Have old manifest version |

### 7.4 Genesis Announcement

The first validly announced manifest establishes the "genesis" state for a collection in that peer's view of the network. Nodes MUST apply the verification rules in Section 8.5 before accepting genesis.

### 7.5 Collection Conflict Resolution

If two different manifest CIDs are announced for the same new `collection_id`, peers resolve the conflict using the Collection ID scheme:

- **`key` scheme:** Accept only manifests signed by the key; unsigned or mismatched signatures are rejected.
- **`hash` scheme:** Accept only manifests whose content root equals the ID; conflicting manifests are invalid.
- **`chain` scheme:** Verify against chain state; accept the manifest that matches the current on-chain token URIs and supply.
- **`uuid` scheme:** Trust-on-first-use (TOFU); accept the first valid manifest seen. Implementations SHOULD surface conflicts (TOFU_CONFLICT status) rather than silently ignoring them, allowing operators to investigate and manually override if needed. Conflicting manifests MUST NOT be automatically accepted.
- **`dns` scheme:** Fetch the authoritative manifest from `https://{value}/dcpp-manifest.json`; conflicting announcements are ignored.

If conflicts persist within a scheme-defined verification window (e.g., inconsistent chain reads), peers MAY fall back to "first seen" and mark the collection as `STALE` until verified.

#### 7.5.1 Merge-Capable Conflict Resolution

For schemes that support multiple authorized writers (e.g., a group key or explicit multi-signer policy), peers MAY attempt a deterministic merge instead of choosing a single manifest. Merge is OPTIONAL and MUST be verifiable and reproducible.

**Merge Rules (Deterministic):**
1. **Item-level union:** Merge manifests by `token_id` (or item key). Include the union of all items.
2. **Last-write-wins fields:** For overlapping items, prefer the item with the greater `updated_at` (or `created_at` if `updated_at` missing). If timestamps tie, choose the item whose `metadata_cid` is lexicographically lower to break ties.
3. **Tombstones (optional):** If an item includes a `status` of `deleted` (or a future tombstone marker), it MUST override older non-deleted versions.
4. **Merkle root recompute:** The merged manifest MUST recompute `merkle_root` and any shard roots deterministically.
5. **Re-signing required:** The merged manifest MUST be signed by the authorized key set for that scheme. Peers MUST reject merges that are not properly authorized.

If a node cannot verify the merge (missing items, missing signatures, or non-deterministic rules), it MUST treat the conflict as unresolved and fall back to the base scheme rule (`first seen`, `STALE`, or authoritative source).

---

## 8. Collection Manifest

### 8.1 Manifest Structure

```cbor
{
  "protocol": "dcpp/1.0",
  "type": "nft-collection",     ; Deprecated: prefer Collection ID scheme

  ; Identification
  "collection_id": string,        ; "{scheme}:{value}"
  "chain": string | null,         ; Optional for chain-based schemes
  "contract": string | null,      ; Optional for chain-based schemes
  "name": string,                 ; Human-readable name

  ; Versioning
  "version": uint32,              ; Manifest version number
  "created_at": uint64,           ; Unix timestamp
  "updated_at": uint64,           ; Unix timestamp

  ; Content summary
  "total_items": uint32,          ; Total tokens in collection
  "total_size_bytes": uint64,     ; Total content size
  "merkle_root": string,          ; CID of merkle root (IPFS UnixFS DAG)

  ; Hierarchy (optional, for sub-collections)
  "parent_collection": string | null,
  "sub_collections": [
    {
      "id": string,
      "name": string,
      "item_range": [uint32, uint32]  ; Token ID range
    }
  ],

  ; Sharding (for large collections)
  "sharding": {
    "enabled": bool,
    "shard_count": uint32,
    "shard_size": uint32          ; Items per shard
  } | null,

  ; BitTorrent info
  "torrent": {
    "infohash": string,           ; BitTorrent infohash
    "magnet": string,             ; Magnet URI
    "piece_length": uint32        ; Bytes per piece
  },

  ; Items (if small collection) or item index location
  "items": [Item] | null,
  "items_index_cid": string | null  ; CID of separate items index
}
```

**Legacy `type` Values:** Implementations MAY include `nft-collection`, `personal-backup`, or `snapshot` for backward compatibility. New implementations SHOULD rely on the Collection ID scheme for verification rules.

### 8.2 Item Structure

```cbor
{
  "token_id": string,             ; Token ID (string to handle large numbers)
  "metadata_cid": string,         ; CID of metadata JSON
  "media": [
    {
      "type": string,             ; "image" | "video" | "audio" | "model" | "html"
      "cid": string,
      "size_bytes": uint64,
      "mime_type": string
    }
  ],
  "storage_type": string,         ; See 8.2.1 Storage Types
  "status": string                ; See 8.2.2 Item Status
}
```

#### 8.2.1 Storage Types

| Type | Description |
|------|-------------|
| `ipfs` | Content addressed via IPFS CID |
| `arweave` | Stored on Arweave permanent storage |
| `filecoin` | Stored on Filecoin network |
| `swarm` | Stored on Ethereum Swarm |
| `onchain` | Data stored directly on blockchain |
| `http` | Traditional HTTP URL (centralized) |

Implementations MAY support additional storage types. Unknown types SHOULD be treated as `http` (fetch via gateway if possible).

#### 8.2.2 Item Status

| Status | Description |
|--------|-------------|
| `unknown` | Item not yet verified; default for new items |
| `available` | Content verified accessible from original source |
| `at_risk` | Content accessible but source shows degradation signs |
| `broken` | Content not accessible from original source |

### 8.2.3 Merkle Root Construction

The `merkle_root` field contains a CID constructed using IPFS UnixFS DAG format:
- Items sorted by `token_id` (lexicographic string sort)
- Each item represented as a DAG node containing its CIDs
- Root CID computed using standard IPFS dag-pb encoding

This allows partial verification: a node can verify it has correct items for a shard without downloading the entire manifest.

### 8.3 Items Index

The manifest can include items inline or reference an external index:

- **Inline items:** `items` array contains all Item objects directly
- **External index:** `items_index_cid` references a separate CBOR file containing the items array

**Threshold:** Collections with more than **10,000 items** SHOULD use external index (matches sharding threshold). Smaller collections MAY use external index to keep manifests lightweight.

**Index Structure:** The external index is a CBOR file:
```cbor
{
  "collection_id": string,
  "items": [Item, Item, ...]
}
```

### 8.4 Manifest Versioning

- Manifest version increments when collection changes
- Changes include: new mints, metadata updates, content status changes
- Nodes SHOULD fetch updated manifest when version is newer
- Old manifest versions MAY be cached for historical reference

### 8.5 Manifest Verification Rules

Manifest verification depends on the Collection ID scheme:

| Scheme | Required Verification |
|--------|------------------------|
| `chain` | Verify manifest matches on-chain state (token URIs, supply) |
| `key` | Verify manifest signature matches the public key in the Collection ID |
| `hash` | Verify manifest content root equals the Collection ID hash |
| `uuid` | Accept first valid manifest seen (TOFU) unless user overrides |
| `dns` | Fetch and verify manifest from `https://{value}/dcpp-manifest.json` (optionally DNSSEC) |

If a Manifest includes a `type` field, it MUST NOT override the scheme-derived verification rules. Implementations MAY use `type` for display or legacy compatibility.

---

## 9. Peer Discovery

### 9.1 DHT-Based Discovery

Nodes use libp2p Kademlia DHT for peer discovery. Nodes providing a collection SHOULD:
1. Announce to DHT with key: `sha256("dcpp/1.0:" + collection_id)`
2. Re-announce periodically (RECOMMENDED: every 1 hour)
3. Set DHT record TTL to 24 hours

**Key Format:** The version prefix (`dcpp/1.0:`) ensures namespace separation from other protocols and allows future protocol versions to use different DHT keyspaces.

#### 9.1.1 Private Collection DHT Discovery

For private collections, nodes derive DHT keys from the Collection Key rather than the collection ID:
- DHT key: `sha256("dcpp/1.0/private:" + collection_key)`
- This prevents discovery by parties who don't possess the Collection Key
- Re-announcement and TTL rules are identical to public collections

### 9.2 Pub/Sub Discovery

Nodes MAY subscribe to collection-specific pub/sub topics:
- Topic format: `/dcpp/1.0/collection/{collection_id}`
- ANNOUNCE messages broadcast to topic
- Pub/sub is ephemeral; no persistence after node disconnects

#### 9.2.1 Private Collection Pub/Sub

For private collections, nodes use a derived topic to prevent collection ID disclosure:
- Topic format: `/dcpp/1.0/private/{topic_key_hex}`
- Where `topic_key_hex = hex(sha256("dcpp/1.0/private:" + collection_key))`
- Only nodes with the Collection Key can derive and subscribe to the correct topic

This provides unlinkability: observers cannot determine which private collection a topic corresponds to without possessing the Collection Key.

### 9.3 Bootstrap Nodes

Bootstrap node addresses are published at (implementations SHOULD check in order):
1. DNS TXT record: `_dcpp-bootstrap.dcpp.network`
2. IPNS: `/ipns/bootstrap.dcpp.network`

Implementations MUST NOT hardcode bootstrap node addresses in the protocol specification or code, as these may change. DNS and IPNS provide updateable discovery.

### 9.4 DHT Entry Lifetime

- DHT records SHOULD have a TTL of 24 hours
- Nodes MUST re-announce before TTL expiry to remain discoverable
- Stale entries (not re-announced) are automatically pruned by DHT

---

## 10. Health Probing

### 10.1 Probe Protocol

To verify a node actually stores content:
1. Challenger sends HEALTH_PROBE with random CID from collection
2. Challenged node returns bytes at specified offset
3. Challenger verifies response matches local copy or CID

### 10.2 Probe Frequency

- Nodes SHOULD probe each peer at least once per 24 hours
- Nodes MAY probe more frequently for high-value collections
- Failed probes SHOULD be retried 3 times before marking peer as unhealthy

### 10.3 Probe Limits

- Maximum challenges per probe: 10
- Maximum bytes per challenge: 1024
- Minimum interval between probes to same peer: 60 seconds

### 10.4 Response Time Tracking (Anti-Leech)

To discourage nodes from fetching content on-demand from public IPFS gateways rather than storing locally:

1. **Track response latency:** Nodes SHOULD record probe response times per peer
2. **Compute rolling average:** Maintain average response time over last 10 probes
3. **Flag slow responders:** Peers with average response time > 2 seconds SHOULD be flagged as potentially not storing locally
4. **Deprioritize in peer lists:** When responding to GET_PEERS, nodes SHOULD:
   - Exclude peers flagged as slow responders, OR
   - Sort peers by response time (fastest first)
   - Include a `response_quality` field (0.0-1.0) in peer entries

**Rationale:** Local disk reads typically complete in <100ms. IPFS gateway fetches typically take 1-5+ seconds. Tracking response time provides soft detection without protocol complexity.

**Note:** This is not cryptographically enforced. A sophisticated leecher could cache frequently-probed content. The goal is to raise the cost of leeching, not eliminate it entirely.

---

## 11. Collection Sharding

### 11.1 Sharding Threshold

Collections with more than **10,000 tokens** MUST be sharded. Collections with 10,000 or fewer tokens MAY be stored as a whole.

### 11.2 Shard Size

- Default shard size: 1,000 tokens
- Shards MUST be contiguous token ID ranges
- Shard count = ceil(total_tokens / shard_size)

Example: Collection with 25,000 tokens → 25 shards of 1,000 tokens each

### 11.3 Shard Assignment Algorithm

Shard assignment ensures that a node's owned tokens are always in their assigned shard(s).

```
function assignShards(nodeId, ownedTokenIds, collection):
  # 1. Find shards containing owned tokens
  requiredShards = set()
  for tokenId in ownedTokenIds:
    shardId = floor(tokenId / collection.shardSize)
    requiredShards.add(shardId)

  # 2. If no owned tokens, assign based on node ID
  if requiredShards.isEmpty():
    hashValue = sha256(nodeId + collection.id)
    shardId = hashValue % collection.shardCount
    requiredShards.add(shardId)

  return requiredShards
```

### 11.4 Shard Properties

| Property | Description |
|----------|-------------|
| **Self-interest** | Your tokens are always in your shard(s) |
| **Deterministic** | Given node ID + owned tokens, assignment is reproducible |
| **No coordination** | Nodes don't need to agree on assignments |
| **Anti-leech** | Must store complete shard(s), not just owned tokens |

### 11.5 Shard Manifest

Each shard has its own torrent:

```cbor
{
  "collection_id": string,
  "shard_id": uint32,
  "token_range": [uint32, uint32],   ; [start, end) token IDs
  "item_count": uint32,
  "size_bytes": uint64,
  "merkle_root": string,             ; CID of shard merkle root
  "torrent": {
    "infohash": string,
    "magnet": string
  }
}
```

---

## 12. BitTorrent Integration

### 12.1 Torrent Generation

For each collection/shard, generate a torrent file:
1. Files organized by token_id
2. Piece size chosen based on collection size:
   - < 1 GB: 256 KB pieces
   - 1-10 GB: 1 MB pieces
   - > 10 GB: 4 MB pieces
3. Infohash included in manifest

### 12.2 Seeding Coordination

- Nodes announce BitTorrent seeding status in ANNOUNCE messages
- If included, `bt_status` MUST reflect actual BitTorrent status
- GET_PEERS returns BitTorrent-capable peers
- Nodes SHOULD seed while in GUARDING or SEEDING state
- Nodes MAY upload verified pieces while in SYNCING, but MUST NOT advertise seeding status until the collection is COMPLETE
- If included, per-collection `bt_status` in ANNOUNCE MUST reflect actual BitTorrent status for that collection

### 12.3 CID ↔ Torrent Mapping

Each file in torrent maps to a CID:
- Torrent file path: `{token_id}/{filename}`
- Mapping stored in manifest items array
- Verification: after BT download, verify each file against CID

---

## 13. Security Considerations

### 13.1 Message Authentication

- ANNOUNCE messages MUST be signed by node's libp2p key
- Other messages authenticated by libp2p connection (Noise protocol)

### 13.2 Replay Protection & Time

To prevent replay attacks and ensure freshness:
1. **Timestamps:** Messages containing a `timestamp` field (HELLO, ANNOUNCE) MUST be rejected if the timestamp deviates more than **5 minutes** from the receiver's local clock.
2. **Nonces:** The `signature` in ANNOUNCE messages covers `(node_id + collections + timestamp)`. Since timestamp is included, strictly monotonic or unique nonces are not required if the 5-minute window is enforced, though implementations MAY track seen signatures within that window to prevent immediate replays.

### 13.3 Denial of Service

- Nodes SHOULD implement rate limiting per peer
- RECOMMENDED limits:
  - 100 requests per minute per peer
  - 10 MB response data per minute per peer
  - Max 10 concurrent streams per peer
- **Backpressure:** Nodes under load SHOULD return ERROR code 0x0006 (`BUSY_TRY_LATER`) instead of dropping messages or hanging.

### 13.4 Sybil Resistance

- Proof of storage (HEALTH_PROBE) limits benefit of fake nodes
- Nodes SHOULD weight peer quality by successful probe history

### 13.5 Content Integrity

- All content verified against CID before acceptance
- Manifest merkle root enables partial verification

---

## 14. IANA Considerations

This document has no IANA actions.

The protocol identifier `/dcpp/1.0.0` is registered in the libp2p protocol registry (informal).

---

## Appendix A: CBOR Schema (CDDL)

```cddl
; Message envelope (binary, not CBOR)
envelope = (
  magic: uint32,      ; 0x44435050
  version: uint16,    ; 0x0100
  type: uint16,
  request_id: uint32, ; Correlation ID
  length: uint32,
  payload: bytes
)

; HELLO message
hello = {
  version: tstr,
  node_id: bstr,
  capabilities: [* tstr],
  collections: [* tstr],
  timestamp: uint
}

; ANNOUNCE message
announce = {
  node_id: bstr,
  collections: [* collection-announcement],
  timestamp: uint,
  signature: bstr
}

collection-announcement = {
  id: tstr,
  manifest_cid: tstr,
  coverage: float32,
  ? bt_status: tstr,
  ? shard_ids: [* uint]
}

; ... (additional schemas)
```

---

## Appendix B: Example Message Flow

### B.1 New Node Joining Network

```
Node A                           Node B (existing)
   │                                   │
   │──────── HELLO ───────────────────▶│
   │◀─────── HELLO ────────────────────│
   │                                   │
   │──────── GET_PEERS(bayc) ─────────▶│
   │◀─────── PEERS ────────────────────│
   │                                   │
   │──────── GET_MANIFEST(bayc) ──────▶│
   │◀─────── MANIFEST ─────────────────│
   │                                   │
   │ (joins BitTorrent swarm, downloads)│
   │                                   │
   │──────── ANNOUNCE ────────────────▶│ (broadcast)
```

### B.2 Health Probe

```
Node A                           Node B
   │                                   │
   │──────── HEALTH_PROBE ────────────▶│
   │         cid: Qm..., offset: 1024  │
   │         length: 256, nonce: xyz   │
   │                                   │
   │◀─────── HEALTH_RESPONSE ──────────│
   │         nonce: xyz                │
   │         data: <256 bytes>         │
```

---

## Appendix C: Reference Implementation Notes

Reference implementations are available at:
- TypeScript/Node.js: `@dcpp/node`
- Rust: `dcpp-rs`
- Python: `dcpp-py`

---

*— End of Specification —*
