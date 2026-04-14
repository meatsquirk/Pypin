"""
Shared pytest fixtures for DCPP tests.

This module provides common fixtures used across the test suite.
"""

import os
import tempfile
import time
from pathlib import Path

import pytest

from dcpp_python.core.constants import Capability
from dcpp_python.crypto import generate_keypair, derive_peer_id
from dcpp_python.messages import Hello, CollectionAnnouncement
from dcpp_python.storage import MemoryStorage, FileSystemStorage
from dcpp_python.dht import LocalDHT, DHTConfig


# =============================================================================
# Crypto Fixtures
# =============================================================================


@pytest.fixture
def keypair():
    """Generate a fresh Ed25519 keypair for testing."""
    signing_key, verify_key = generate_keypair()
    return signing_key, verify_key


@pytest.fixture
def node_id(keypair):
    """Generate a peer ID from a keypair."""
    _, verify_key = keypair
    return derive_peer_id(verify_key)


@pytest.fixture
def second_keypair():
    """Generate a second keypair for multi-node tests."""
    return generate_keypair()


@pytest.fixture
def second_node_id(second_keypair):
    """Generate a second peer ID."""
    _, verify_key = second_keypair
    return derive_peer_id(verify_key)


# =============================================================================
# Message Fixtures
# =============================================================================


@pytest.fixture
def hello_message(node_id):
    """Create a sample HELLO message."""
    return Hello(
        version="1.0.0",
        node_id=node_id,
        capabilities=[Capability.GUARDIAN, Capability.SEEDER],
        collections=["eth:0xBC4CA0EdC45dEA4Fc3cF2cE12a7a31E2A1E84631"],
        timestamp=int(time.time()),
        user_agent="dcpp-py-test/0.1.0",
    )


@pytest.fixture
def collection_announcement():
    """Create a sample collection announcement."""
    return CollectionAnnouncement(
        id="eth:0xBC4CA0EdC45dEA4Fc3cF2cE12a7a31E2A1E84631",
        manifest_cid="bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        coverage=1.0,
        shard_ids=None,
    )


@pytest.fixture
def test_collection_id():
    """Standard test collection ID."""
    return "eth:0xBC4CA0EdC45dEA4Fc3cF2cE12a7a31E2A1E84631"


# =============================================================================
# Storage Fixtures
# =============================================================================


@pytest.fixture
def memory_storage():
    """Create an in-memory storage backend."""
    return MemoryStorage()


@pytest.fixture
def temp_storage(tmp_path):
    """Create a temporary filesystem storage backend."""
    return FileSystemStorage(tmp_path)


@pytest.fixture
def temp_dir(tmp_path):
    """Provide a temporary directory path."""
    return tmp_path


# =============================================================================
# DHT Fixtures
# =============================================================================


@pytest.fixture
def local_dht():
    """Create a local (in-memory) DHT for testing."""
    return LocalDHT()


@pytest.fixture
def dht_config():
    """Create a default DHT configuration."""
    return DHTConfig(
        bootstrap_peers=[],
        reannounce_interval=3600,
        provider_ttl=86400,
        max_providers=20,
    )


# =============================================================================
# Environment Fixtures
# =============================================================================


@pytest.fixture(autouse=True)
def reset_environment(monkeypatch):
    """Reset environment variables for test isolation."""
    # Ensure stub mode is enabled for tests
    monkeypatch.setenv("DCPP_STUB_MODE", "1")
    monkeypatch.setenv("DCPP_BT_ALLOW_LOCAL", "1")


@pytest.fixture
def strict_mode(monkeypatch):
    """Configure strict mode (require all dependencies)."""
    monkeypatch.setenv("DCPP_STUB_MODE", "0")
    monkeypatch.setenv("DCPP_BT_ALLOW_LOCAL", "0")


# =============================================================================
# Test Data Fixtures
# =============================================================================


@pytest.fixture
def sample_content():
    """Sample content bytes for storage tests."""
    return b"Hello, DCPP World! This is test content."


@pytest.fixture
def sample_manifest_dict():
    """Sample manifest dictionary."""
    return {
        "protocol": "dcpp/1.0",
        "collection_id": "eth:0xBC4CA0EdC45dEA4Fc3cF2cE12a7a31E2A1E84631",
        "version": 1,
        "created_at": int(time.time()),
        "items": [],
        "total_items": 0,
        "total_size_bytes": 0,
    }


# =============================================================================
# Markers
# =============================================================================


def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "e2e: marks tests as end-to-end tests"
    )
    config.addinivalue_line(
        "markers", "requires_libp2p: marks tests that require py-libp2p"
    )
    config.addinivalue_line(
        "markers", "requires_torf: marks tests that require torf"
    )
    config.addinivalue_line(
        "markers", "benchmark: marks performance tests"
    )
    config.addinivalue_line(
        "markers", "fuzz: marks fuzz/property-based tests"
    )
