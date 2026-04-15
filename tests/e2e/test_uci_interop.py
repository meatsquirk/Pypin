"""
UCI Interop Tests

Tests for UCI parsing, verification, and genesis storage with test vectors
that can be compared against the Rust implementation.
"""

import pytest
import json
from dataclasses import dataclass, asdict
from typing import Any


# =============================================================================
# Test Vectors
# =============================================================================

UCI_PARSING_VECTORS = [
    {
        # Using hex-encoded 32-byte Ed25519 public key for consistent cross-platform parsing
        "name": "key_scheme_ed25519_base58",
        "input": "key:ed25519:0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
        "expected": {
            "scheme": "key",
            "algorithm": "ed25519",
            "pubkey_length": 32,
            "is_verifiable": True,
            "requires_signature": True,
        },
    },
    {
        "name": "key_scheme_ed25519_hex",
        "input": "key:ed25519:0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
        "expected": {
            "scheme": "key",
            "algorithm": "ed25519",
            "pubkey_length": 32,
            "is_verifiable": True,
            "requires_signature": True,
        },
    },
    {
        "name": "hash_scheme_sha256_cid",
        "input": "hash:sha256:bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        "expected": {
            "scheme": "hash",
            "algorithm": "sha256",
            "is_verifiable": True,
            "requires_signature": False,
        },
    },
    {
        "name": "hash_scheme_sha256_hex",
        "input": "hash:sha256:0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "expected": {
            "scheme": "hash",
            "algorithm": "sha256",
            "hash_length": 32,
            "is_verifiable": True,
        },
    },
    {
        "name": "uuid_scheme_with_dashes",
        "input": "uuid:123e4567-e89b-12d3-a456-426614174000",
        "expected": {
            "scheme": "uuid",
            "uuid_value": "123e4567-e89b-12d3-a456-426614174000",
            "is_verifiable": True,
            "is_tofu": True,
        },
    },
    {
        "name": "uuid_scheme_no_dashes",
        "input": "uuid:123e4567e89b12d3a456426614174000",
        "expected": {
            "scheme": "uuid",
            "uuid_value": "123e4567-e89b-12d3-a456-426614174000",
            "is_verifiable": True,
            "is_tofu": True,
        },
    },
    {
        "name": "dns_scheme_simple",
        "input": "dns:archive.org",
        "expected": {
            "scheme": "dns",
            "domain": "archive.org",
            "dns_manifest_url": "https://archive.org/dcpp-manifest.json",
            "is_verifiable": True,
        },
    },
    {
        "name": "dns_scheme_subdomain",
        "input": "dns:dcpp.example.com",
        "expected": {
            "scheme": "dns",
            "domain": "dcpp.example.com",
            "dns_manifest_url": "https://dcpp.example.com/dcpp-manifest.json",
        },
    },
    {
        # BAYC contract address (exactly 40 hex chars after 0x)
        "name": "chain_scheme_eth_mainnet",
        "input": "chain:eth:mainnet:0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
        "expected": {
            "scheme": "chain",
            "chain_id": "eth",
            "network": "mainnet",
            "contract": "0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
        },
    },
    {
        "name": "unknown_scheme_lenient",
        "input": "custom:somevalue",
        "expected": {
            "scheme": "unknown",
            "value": "somevalue",
            "is_verifiable": False,
        },
    },
]

UCI_INVALID_VECTORS = [
    {
        "name": "missing_colon",
        "input": "invalid",
        "error": "must contain scheme:value",
    },
    {
        "name": "empty_scheme",
        "input": ":value",
        "error": "scheme cannot be empty",
    },
    {
        "name": "empty_value",
        "input": "key:",
        "error": "value cannot be empty",
    },
    {
        "name": "invalid_ed25519_key_length",
        "input": "key:ed25519:0xabcd",
        "error": "32 bytes",
    },
    {
        "name": "invalid_eth_address",
        "input": "chain:eth:mainnet:invalid",
        "error": "address",
    },
    {
        "name": "invalid_uuid_length",
        "input": "uuid:not-a-valid-uuid",
        "error": "32 hex",
    },
    {
        "name": "invalid_dns_no_tld",
        "input": "dns:localhost",
        "error": "Invalid DNS",
    },
]

VERIFICATION_VECTORS = [
    {
        "name": "key_rejects_unsigned",
        "collection_id": "key:ed25519:0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d",
        "manifest_cid": "QmTest",
        "has_signature": False,
        "expected_status": "failed",
        "expected_message": "Signature required",
    },
    {
        "name": "hash_rejects_mismatch",
        "collection_id": "hash:sha256:bafybeic5gf7h6m5hhvq7w7oazwfbf7fqpwrxgc7hzlhgqj5vqgqtga2mtu",
        "manifest_cid": "QmTest",
        "merkle_root": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        "has_signature": False,
        "expected_status": "failed",
        "expected_message": "mismatch",
    },
    {
        "name": "hash_accepts_match",
        "collection_id": "hash:sha256:bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        "manifest_cid": "QmTest",
        "merkle_root": "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        "has_signature": False,
        "expected_status": "verified",
    },
    {
        "name": "uuid_accepts_first",
        "collection_id": "uuid:123e4567-e89b-12d3-a456-426614174000",
        "manifest_cid": "QmFirst",
        "has_signature": False,
        "expected_status": "tofu_accepted",
        "is_first_seen": True,
    },
    {
        "name": "uuid_rejects_conflict",
        "collection_id": "uuid:123e4567-e89b-12d3-a456-426614174000",
        "manifest_cid": "QmConflict",
        "has_signature": False,
        "expected_status": "tofu_conflict",
        "genesis_cid": "QmFirst",
        "is_first_seen": False,
    },
    {
        "name": "dns_fetch_path",
        "collection_id": "dns:archive.org",
        "manifest_cid": "QmTest",
        "has_signature": False,
        "expected_url": "https://archive.org/dcpp-manifest.json",
    },
    {
        "name": "chain_skipped",
        "collection_id": "chain:eth:mainnet:0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D",
        "manifest_cid": "QmTest",
        "has_signature": False,
        "expected_status": "skipped",
    },
]


# =============================================================================
# Tests
# =============================================================================


class TestUCIParsing:
    """Tests for UCI parsing."""

    @pytest.mark.parametrize("vector", UCI_PARSING_VECTORS, ids=lambda v: v["name"])
    def test_parsing_valid(self, vector):
        """Test parsing valid UCI strings."""
        from dcpp_python.uci import parse_uci, UCIScheme

        uci = parse_uci(vector["input"])
        expected = vector["expected"]

        # Check scheme
        if expected.get("scheme"):
            assert uci.scheme.value == expected["scheme"]

        # Check algorithm
        if expected.get("algorithm"):
            assert uci.algorithm == expected["algorithm"]

        # Check pubkey length
        if expected.get("pubkey_length"):
            assert uci.pubkey_bytes is not None
            assert len(uci.pubkey_bytes) == expected["pubkey_length"]

        # Check hash length
        if expected.get("hash_length"):
            assert uci.hash_bytes is not None
            assert len(uci.hash_bytes) == expected["hash_length"]

        # Check UUID
        if expected.get("uuid_value"):
            assert uci.uuid_value == expected["uuid_value"]

        # Check domain
        if expected.get("domain"):
            assert uci.domain == expected["domain"]

        # Check DNS URL
        if expected.get("dns_manifest_url"):
            assert uci.dns_manifest_url == expected["dns_manifest_url"]

        # Check chain components
        if expected.get("chain_id"):
            assert uci.chain_id == expected["chain_id"]
        if expected.get("network"):
            assert uci.network == expected["network"]
        if expected.get("contract"):
            assert uci.contract == expected["contract"]

        # Check boolean properties
        if "is_verifiable" in expected:
            assert uci.is_verifiable == expected["is_verifiable"]
        if "requires_signature" in expected:
            assert uci.requires_signature == expected["requires_signature"]
        if "is_tofu" in expected:
            assert uci.is_tofu == expected["is_tofu"]

    @pytest.mark.parametrize("vector", UCI_INVALID_VECTORS, ids=lambda v: v["name"])
    def test_parsing_invalid(self, vector):
        """Test that invalid UCI strings raise appropriate errors."""
        from dcpp_python.uci import parse_uci, InvalidUCIError

        with pytest.raises(Exception) as exc_info:
            parse_uci(vector["input"])

        # Check error message contains expected text
        error_msg = str(exc_info.value).lower()
        expected_text = vector["error"].lower()
        assert expected_text in error_msg, f"Expected '{expected_text}' in '{error_msg}'"


class TestGenesisStorage:
    """Tests for genesis storage."""

    @pytest.fixture
    def memory_genesis_store(self):
        """Create an in-memory genesis store."""
        from dcpp_python.storage import MemoryGenesisStore
        return MemoryGenesisStore()

    @pytest.mark.asyncio
    async def test_record_genesis(self, memory_genesis_store):
        """Test recording a genesis record."""
        collection_id = "uuid:123e4567-e89b-12d3-a456-426614174000"
        manifest_cid = "QmTestManifest"

        record = await memory_genesis_store.record_genesis(
            collection_id, manifest_cid, 1, b"\x01\x02\x03"
        )

        assert record.collection_id == collection_id
        assert record.manifest_cid == manifest_cid
        assert record.manifest_version == 1
        assert record.announcing_node_id == b"\x01\x02\x03"

    @pytest.mark.asyncio
    async def test_get_genesis(self, memory_genesis_store):
        """Test retrieving a genesis record."""
        collection_id = "uuid:123e4567-e89b-12d3-a456-426614174000"
        await memory_genesis_store.record_genesis(collection_id, "QmTest", 1)

        record = await memory_genesis_store.get_genesis(collection_id)
        assert record is not None
        assert record.manifest_cid == "QmTest"

        # Non-existent should return None
        record = await memory_genesis_store.get_genesis("uuid:nonexistent")
        assert record is None

    @pytest.mark.asyncio
    async def test_conflict_detection(self, memory_genesis_store):
        """Test conflict detection and recording."""
        from dcpp_python.storage import GenesisState

        collection_id = "uuid:123e4567-e89b-12d3-a456-426614174000"

        # Record genesis
        await memory_genesis_store.record_genesis(collection_id, "QmOriginal", 1)

        # Same CID should not create conflict
        record = await memory_genesis_store.record_conflict(collection_id, "QmOriginal")
        assert record.state == GenesisState.TRUSTED

        # Different CID should create conflict
        record = await memory_genesis_store.record_conflict(collection_id, "QmConflict")
        assert record.state == GenesisState.CONFLICTED
        assert "QmConflict" in record.conflict_cids

    @pytest.mark.asyncio
    async def test_conflict_resolution(self, memory_genesis_store):
        """Test conflict resolution."""
        from dcpp_python.storage import GenesisState

        collection_id = "uuid:123e4567-e89b-12d3-a456-426614174000"

        # Setup conflict
        await memory_genesis_store.record_genesis(collection_id, "QmOriginal", 1)
        await memory_genesis_store.record_conflict(collection_id, "QmConflict")

        # Resolve by accepting conflict
        record = await memory_genesis_store.resolve_conflict(
            collection_id, "QmConflict", "Newer manifest", b"\x09\x09"
        )

        assert record.state == GenesisState.RESOLVED
        assert record.manifest_cid == "QmConflict"
        assert record.resolution_notes == "Newer manifest"


class TestManifestVerification:
    """Tests for manifest verification pipeline."""

    @pytest.fixture
    def mock_manifest(self):
        """Create a mock manifest for testing."""
        class MockManifest:
            def __init__(self):
                self.collection_id = "test:collection"
                self.merkle_root = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
                self.version = 1

            def to_dict(self):
                return {
                    "collection_id": self.collection_id,
                    "merkle_root": self.merkle_root,
                    "version": self.version,
                }

        return MockManifest()

    @pytest.fixture
    def memory_genesis_store(self):
        """Create an in-memory genesis store."""
        from dcpp_python.storage import MemoryGenesisStore
        return MemoryGenesisStore()

    @pytest.mark.asyncio
    async def test_hash_verification_match(self, mock_manifest):
        """Test hash verification with matching merkle root."""
        from dcpp_python.manifest_verify import ManifestVerificationPipeline, VerificationStatus

        pipeline = ManifestVerificationPipeline()

        # Collection ID with matching hash
        collection_id = "hash:sha256:bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"

        result = await pipeline.verify(collection_id, mock_manifest, "QmTest")
        assert result.status == VerificationStatus.VERIFIED

    @pytest.mark.asyncio
    async def test_hash_verification_mismatch(self, mock_manifest):
        """Test hash verification with mismatched merkle root."""
        from dcpp_python.manifest_verify import ManifestVerificationPipeline, VerificationStatus

        pipeline = ManifestVerificationPipeline()

        # Collection ID with different hash
        collection_id = "hash:sha256:bafybeic5gf7h6m5hhvq7w7oazwfbf7fqpwrxgc7hzlhgqj5vqgqtga2mtu"

        result = await pipeline.verify(collection_id, mock_manifest, "QmTest")
        assert result.status == VerificationStatus.FAILED
        assert "mismatch" in result.message.lower()

    @pytest.mark.asyncio
    async def test_uuid_tofu_first_seen(self, mock_manifest, memory_genesis_store):
        """Test UUID TOFU accepts first-seen manifest."""
        from dcpp_python.manifest_verify import ManifestVerificationPipeline, VerificationStatus

        pipeline = ManifestVerificationPipeline(genesis_store=memory_genesis_store)

        collection_id = "uuid:123e4567-e89b-12d3-a456-426614174000"

        result = await pipeline.verify(collection_id, mock_manifest, "QmFirst")
        assert result.status == VerificationStatus.TOFU_ACCEPTED
        assert result.genesis_cid == "QmFirst"

    @pytest.mark.asyncio
    async def test_uuid_tofu_conflict(self, mock_manifest, memory_genesis_store):
        """Test UUID TOFU rejects conflicting manifest."""
        from dcpp_python.manifest_verify import ManifestVerificationPipeline, VerificationStatus

        pipeline = ManifestVerificationPipeline(genesis_store=memory_genesis_store)

        collection_id = "uuid:123e4567-e89b-12d3-a456-426614174000"

        # First manifest
        await pipeline.verify(collection_id, mock_manifest, "QmFirst")

        # Second manifest with different CID should conflict
        result = await pipeline.verify(collection_id, mock_manifest, "QmSecond")
        assert result.status == VerificationStatus.TOFU_CONFLICT
        assert result.genesis_cid == "QmFirst"

    @pytest.mark.asyncio
    async def test_key_requires_signature(self, mock_manifest):
        """Test key scheme requires signature."""
        from dcpp_python.manifest_verify import ManifestVerificationPipeline, VerificationStatus

        pipeline = ManifestVerificationPipeline()

        collection_id = "key:ed25519:0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"

        result = await pipeline.verify(collection_id, mock_manifest, "QmTest")
        assert result.status == VerificationStatus.FAILED
        assert "signature" in result.message.lower()


class TestEnhancedAnnounceHandler:
    """Tests for enhanced ANNOUNCE handling."""

    @pytest.fixture
    def validator(self):
        """Create a message validator."""
        from dcpp_python.validation import MessageValidator
        return MessageValidator()

    @pytest.mark.asyncio
    async def test_basic_validation_rejection(self, validator):
        """Test that basic validation failures reject ANNOUNCE."""
        from dcpp_python.validation import EnhancedAnnounceHandler

        handler = EnhancedAnnounceHandler(validator)

        # Expired message should be rejected
        import time
        now = int(time.time())

        result = await handler.handle_announce(
            node_id=b"\x01\x02\x03",
            timestamp=now,
            expires_at=now - 10,  # Expired
            announce_seq=1,
            collections=[],
        )

        assert not result.is_accepted

    @pytest.mark.asyncio
    async def test_unknown_manifest_needs_fetch(self, validator):
        """Test that unknown manifests trigger fetch needed status."""
        from dcpp_python.validation import EnhancedAnnounceHandler, AnnounceHandleStatus

        handler = EnhancedAnnounceHandler(validator)

        import time
        now = int(time.time())

        result = await handler.handle_announce(
            node_id=b"\x01\x02\x03",
            timestamp=now,
            expires_at=now + 3600,
            announce_seq=1,
            collections=[
                {"id": "uuid:123e4567-e89b-12d3-a456-426614174000", "manifest_cid": "QmUnknown"},
            ],
        )

        assert result.status == AnnounceHandleStatus.FETCH_NEEDED
        assert "uuid:123e4567-e89b-12d3-a456-426614174000" in result.collections_to_fetch


def generate_test_vectors_json():
    """Generate test vectors as JSON for cross-language testing."""
    vectors = {
        "uci_parsing": UCI_PARSING_VECTORS,
        "uci_invalid": UCI_INVALID_VECTORS,
        "verification": VERIFICATION_VECTORS,
    }
    return json.dumps(vectors, indent=2)


if __name__ == "__main__":
    # Print test vectors as JSON when run directly
    print(generate_test_vectors_json())
