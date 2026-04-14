# Changelog

All notable changes to the DCPP Wire Protocol library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-01-23

### Added

#### Core Protocol
- Full envelope message framing (Profile1) with magic bytes, version, CRC32C
- All DCPP message types: HELLO, ANNOUNCE, GET_MANIFEST, MANIFEST, GET_PEERS, PEERS, HEALTH_PROBE, HEALTH_RESPONSE, GOODBYE, ERROR
- Membership messages: INVITE, JOIN, JOIN_ACK, LEAVE, REVOKE, GET_MEMBERS, MEMBERS, KEY_ROTATE
- Ed25519 message signing with canonical CBOR encoding
- CIDv1 computation and verification (IPFS-compatible)
- Collection manifest and item structures
- Shard assignment algorithms
- Peer management and ranking

#### Storage
- File-system storage backend with CID verification
- Path traversal prevention and input sanitization
- Download state persistence for resume support
- Disk space monitoring

#### Networking (Feature-gated)
- libp2p integration with Kademlia DHT and GossipSub (`libp2p-host` feature)
- BitTorrent BEP 52 hybrid v1+v2 support (`bittorrent` feature)
- Bootstrap discovery via DNS/HTTP (`bootstrap-discovery` feature)

#### API & Operations
- HTTP ingest API for content management (`ingest-api` feature)
- Prometheus metrics endpoint (`metrics` feature)
- Structured JSON logging (`structured-logging` feature)
- Rate limiting module for API protection
- Protocol state machine for node and collection management

#### Security
- Path traversal prevention in storage operations
- Collection ID and CID sanitization
- Rate limiting with sliding/fixed window algorithms
- Comprehensive fuzz testing targets
- Security audit infrastructure

#### Testing
- 357+ unit tests covering all modules
- E2E test harness for multi-node scenarios
- Load testing infrastructure
- Platform compatibility tests
- Fuzz targets for all parsing code

### Security
- All filesystem paths validated against base directory escape
- Input sanitization for collection IDs and CIDs
- Ed25519 signature verification with canonical CBOR
- CID content verification prevents tampering

## [Unreleased]

### Planned
- WebSocket transport support
- Additional storage backends (S3, IPFS)
- Enhanced peer discovery mechanisms
- Collection encryption support
