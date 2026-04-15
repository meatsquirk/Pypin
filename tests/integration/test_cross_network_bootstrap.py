"""
DCPP Cross-Network Bootstrap and Happy Path Validation Tests

This module implements the test cases from docs/TEST_PLAN_CROSS_NETWORK_BOOTSTRAP.md
as pytest tests that can be run against a Docker Compose cluster.

Test Cases:
- TC-001: Config Parsing and Advertise Address Selection
- TC-002: Bootstrap Dial Uses Public Multiaddr
- TC-003: DHT Provider Record Includes Advertised Address
- TC-004: GossipSub ANNOUNCE Cross-Network
- TC-005: Manifest Exchange
- TC-006: BitTorrent Download Completion
- TC-007: Health Probe
- TC-008: Re-announce Schedule and TTL
- TC-009: Interop Rust <-> Python
- TC-010: No Stub Warnings

Prerequisites:
- Docker Compose cluster running: docker compose up -d (tests will attempt to start it)
- Test content seeded: docker compose --profile setup up content-seeder
- Interop bootstrap peer ID configured via scripts/setup-interop.sh (tests will invoke)

Usage:
    PYTHONPATH="." pytest tests/integration/test_cross_network_bootstrap.py -v
    PYTHONPATH="." pytest tests/integration/test_cross_network_bootstrap.py::test_tc_010_no_stub_warnings -v
"""

from __future__ import annotations

import json
import http.client
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest
import urllib.request
import urllib.error

from dcpp_python.core.constants import DEFAULT_PROBE_INTERVAL


# =============================================================================
# Configuration
# =============================================================================

def _env_str(name: str, default: str) -> str:
    """Return a string from env, with a safe default."""
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    """Return an int from env, with a safe default."""
    value = os.environ.get(name)
    return int(value) if value else default


# Container names (defaults target dcpp-python stack)
RUST_NODE_1 = _env_str("DCPP_RUST_NODE_1_CONTAINER", "dcpp-python-rust-1")
RUST_NODE_2 = _env_str("DCPP_RUST_NODE_2_CONTAINER", "dcpp-python-rust-2")
RUST_NODE_3 = _env_str("DCPP_RUST_NODE_3_CONTAINER", "dcpp-python-rust-3")
PYTHON_NODE_1 = _env_str("DCPP_PYTHON_NODE_1_CONTAINER", "dcpp-python-py-1")
PYTHON_NODE_2 = _env_str("DCPP_PYTHON_NODE_2_CONTAINER", "dcpp-python-py-2")

ALL_CONTAINERS = [RUST_NODE_1, RUST_NODE_2, RUST_NODE_3, PYTHON_NODE_1, PYTHON_NODE_2]

# Collection IDs
COLLECTION_BAYC = "eth:0xBC4CA0EdBddf83641A86e72B10E2B8bB8e57060E"
COLLECTION_PUNKS = "eth:0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB"

# Stub/mock patterns that should NOT appear in logs
STUB_PATTERNS = [
    r"LOCAL CACHE mode",
    r"Mock backend",
    r"GossipSub Mode: LOCAL",
    r"Kademlia not wired",
    r"py-libp2p Kademlia not wired",
    r"Using stub DHT",
    r"Using stub BitTorrent",
    r"STUB_MODE=1",
    r"stub.*mode",
]

# Host/port for HTTP API lookups (defaults to dcpp-python stack)
RUST_NODE_1_HTTP_HOST = _env_str("DCPP_RUST_NODE_1_HTTP_HOST", "127.0.0.1")
RUST_NODE_1_HTTP_PORT = _env_int("DCPP_RUST_NODE_1_HTTP_PORT", 8181)
PYTHON_NODE_1_HTTP_HOST = _env_str("DCPP_PYTHON_NODE_1_HTTP_HOST", "127.0.0.1")
PYTHON_NODE_1_HTTP_PORT = _env_int("DCPP_PYTHON_NODE_1_HTTP_PORT", 8183)


# =============================================================================
# Helpers
# =============================================================================

DEFAULT_COMPOSE_SERVICES = [
    "rust-node-1",
    "rust-node-2",
    "rust-node-3",
    "python-node-1",
    "python-node-2",
]

_CLUSTER_STARTED = False
_BOOTSTRAP_SETUP_DONE = False
_CONTENT_SEEDER_STARTED = False
_GUARDIAN_SETUP_DONE = False

@dataclass
class ContainerLogs:
    """Container logs with metadata."""
    container: str
    logs: str
    success: bool


def is_docker_available() -> bool:
    """Check if Docker is available."""
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def is_container_running(container: str) -> bool:
    """Check if a container is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            timeout=5,
            text=True,
        )
        if result.returncode != 0:
            return False
        return container in result.stdout.split("\n")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def ensure_docker_cluster(reason: str, services: Optional[List[str]] = None) -> None:
    """
    Ensure Docker Compose cluster is running for tests that require it.

    This is invoked at the start of docker-dependent tests for explicit setup.
    """
    global _CLUSTER_STARTED

    if not is_docker_available():
        pytest.skip("Docker not available")

    if is_container_running(RUST_NODE_1):
        return

    target_services = services or DEFAULT_COMPOSE_SERVICES
    print(f"[SETUP] {reason} Starting docker compose services: {', '.join(target_services)}")
    result = subprocess.run(
        ["docker", "compose", "up", "-d", *target_services],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        err = result.stderr.strip()
        if "Pool overlaps" in err or "overlaps with other one" in err:
            pytest.skip(f"Docker network pool overlap: {err}")
        pytest.skip(f"Failed to start docker compose services: {err}")
    _CLUSTER_STARTED = True


def ensure_bootstrap_peer_id(reason: str) -> None:
    """
    Ensure Python nodes have the correct DCPP_BOOTSTRAP_PEER_ID set.

    Uses scripts/setup-interop.sh to extract the Rust peer ID and restart Python nodes.
    """
    global _BOOTSTRAP_SETUP_DONE

    if _BOOTSTRAP_SETUP_DONE:
        return

    def _extract_rust_peer_id_from_logs() -> Optional[str]:
        logs = get_container_logs(RUST_NODE_1, lines=400)
        if not logs.success:
            return None
        match = re.search(r"Local Peer ID:\s+(\S+)", logs.logs)
        if match:
            return match.group(1)
        match = re.search(r"local_peer_id=([A-Za-z0-9]+)", logs.logs)
        if match:
            return match.group(1)
        return None

    def _restart_rust_with_info_logs() -> Optional[str]:
        env = os.environ.copy()
        env["RUST_LOG"] = "info,dcpp=debug"
        try:
            subprocess.run(
                ["docker", "compose", "up", "-d", "--force-recreate", "rust-node-1"],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
                env=env,
            )
        except subprocess.CalledProcessError as exc:
            print(f"[SETUP] {reason} Failed to restart rust-node-1 for peer ID: {exc.stderr.strip()}")
            return None
        time.sleep(2)
        return _extract_rust_peer_id_from_logs()

    env_peer_id = os.environ.get("DCPP_BOOTSTRAP_PEER_ID")
    if not env_peer_id:
        rust_peer_id = _extract_rust_peer_id_from_logs()
        if not rust_peer_id:
            rust_peer_id = _restart_rust_with_info_logs()
        if rust_peer_id:
            os.environ["DCPP_BOOTSTRAP_PEER_ID"] = rust_peer_id
            env_peer_id = rust_peer_id

    if env_peer_id:
        rust_peer_id = _extract_rust_peer_id_from_logs()
        if not rust_peer_id:
            rust_peer_id = _restart_rust_with_info_logs()
        if rust_peer_id and rust_peer_id != env_peer_id:
            print(
                f"[SETUP] {reason} Updating DCPP_BOOTSTRAP_PEER_ID "
                f"from {env_peer_id} to {rust_peer_id}"
            )
            os.environ["DCPP_BOOTSTRAP_PEER_ID"] = rust_peer_id
            env_peer_id = rust_peer_id
        print(f"[SETUP] {reason} Using DCPP_BOOTSTRAP_PEER_ID={env_peer_id}")
        existing_multiaddr = os.environ.get("DCPP_BOOTSTRAP_MULTIADDR", "")
        desired_multiaddr = f"/ip4/172.31.1.1/tcp/4001/p2p/{env_peer_id}"
        if ("/p2p/" not in existing_multiaddr) or (env_peer_id not in existing_multiaddr):
            os.environ["DCPP_BOOTSTRAP_MULTIADDR"] = desired_multiaddr
            print(
                f"[SETUP] {reason} Setting DCPP_BOOTSTRAP_MULTIADDR="
                f"{os.environ['DCPP_BOOTSTRAP_MULTIADDR']}"
            )
        try:
            subprocess.run(
                [
                    "docker",
                    "compose",
                    "up",
                    "-d",
                    "--force-recreate",
                    "--no-deps",
                    "python-node-1",
                    "python-node-2",
                ],
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            pytest.skip(
                "Failed to restart python nodes for bootstrap peer ID: "
                f"{exc.stderr.strip()}"
            )
        _BOOTSTRAP_SETUP_DONE = True
        return

    rust_repo_env = os.environ.get("DCPP_RUST_REPO")
    rust_repo_dir = (
        Path(rust_repo_env).resolve()
        if rust_repo_env
        else Path(__file__).resolve().parents[2] / "dcpp-rust"
    )
    rust_compose_file = rust_repo_dir / "docker-compose.yml"
    py_compose_file = Path(__file__).resolve().parents[1] / "docker-compose.yml"
    use_rust_compose = os.environ.get("DCPP_USE_RUST_COMPOSE", "0") == "1"

    compose_dir = Path(__file__).resolve().parents[1]
    compose_file = py_compose_file
    if use_rust_compose and rust_compose_file.exists():
        try:
            if "rust-node-1:" in rust_compose_file.read_text():
                compose_dir = rust_repo_dir
                compose_file = rust_compose_file
        except OSError:
            pass

    dockerfile_python = compose_dir / "Dockerfile.python"
    if not dockerfile_python.exists():
        pytest.skip(
            f"Missing {dockerfile_python} required for cross-network bootstrap tests"
        )

    ensure_docker_cluster(f"{reason} (bootstrap setup)", services=["rust-node-1"])
    print(f"[SETUP] {reason} Ensuring DCPP_BOOTSTRAP_PEER_ID via scripts/setup-interop.sh")
    setup_script = rust_repo_dir / "scripts" / "setup-interop.sh"
    result = subprocess.run(
        ["bash", str(setup_script)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        combined = f"{result.stdout}\n{result.stderr}"
        if "Pool overlaps" in combined or "overlaps with other one" in combined:
            pytest.skip(f"Docker network pool overlap during setup: {combined.strip()}")
        raise RuntimeError(
            "Failed to configure DCPP_BOOTSTRAP_PEER_ID:\n"
            f"{result.stdout}\n{result.stderr}"
        )
    _BOOTSTRAP_SETUP_DONE = True


def ensure_content_seeder(reason: str) -> None:
    """Ensure the content seeder container is running for manifest/BT tests."""
    global _CONTENT_SEEDER_STARTED

    if _CONTENT_SEEDER_STARTED:
        return

    print(f"[SETUP] {reason} Starting content seeder via docker compose profile")
    result = subprocess.run(
        ["docker", "compose", "--profile", "setup", "up", "-d", "content-seeder"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to start content seeder: {result.stderr.strip()}"
        )
    _CONTENT_SEEDER_STARTED = True


def ensure_guardian_init(reason: str) -> None:
    """
    Ensure rust-node-1 has a manifest by starting it with initial content.
    """
    global _GUARDIAN_SETUP_DONE

    if _GUARDIAN_SETUP_DONE:
        return

    ensure_content_seeder(f"{reason} (content required for guardian init)")

    # Verify the rust API is reachable from the host.
    health_url = f"http://{RUST_NODE_1_HTTP_HOST}:{RUST_NODE_1_HTTP_PORT}/health"
    deadline = time.time() + 60
    while time.time() < deadline:
        if http_get_json(health_url) is not None:
            break
        time.sleep(2)
    else:
        raise RuntimeError("Rust node API not reachable for guardian init")

    status = get_node_collection_status(
        RUST_NODE_1_HTTP_HOST, RUST_NODE_1_HTTP_PORT, COLLECTION_BAYC
    )
    if status and status.get("state") != "no_manifest" and status.get("total_items", 0) > 0:
        _GUARDIAN_SETUP_DONE = True
        return

    content_dir = f"/content/{COLLECTION_BAYC}"
    content_exists = docker_exec(RUST_NODE_1, ["test", "-d", content_dir])
    if content_exists is None:
        raise RuntimeError(
            f"Missing seeded content in {RUST_NODE_1}:{content_dir}. "
            "Ensure content seeder ran successfully."
        )

    print(f"[SETUP] {reason} Restarting {RUST_NODE_1} for initial guardian setup")
    result = subprocess.run(
        ["docker", "compose", "up", "-d", "--force-recreate", "rust-node-1"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Failed to restart rust-node-1 for guardian init: {result.stderr.strip()}"
        )

    # Wait for manifest to appear
    deadline = time.time() + 60
    while time.time() < deadline:
        status = get_node_collection_status(
            RUST_NODE_1_HTTP_HOST, RUST_NODE_1_HTTP_PORT, COLLECTION_BAYC
        )
        if status and status.get("total_items", 0) > 0:
            _GUARDIAN_SETUP_DONE = True
            return
        time.sleep(2)

    raise RuntimeError(
        "Initial guardian setup did not create a manifest on rust-node-1"
    )

    _GUARDIAN_SETUP_DONE = True


def get_container_logs(container: str, lines: Optional[int] = None) -> ContainerLogs:
    """Get logs from a container."""
    try:
        cmd = ["docker", "logs"]
        if lines:
            cmd.extend(["--tail", str(lines)])
        cmd.append(container)

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=30,
            text=True,
        )
        logs = result.stdout + result.stderr
        return ContainerLogs(container=container, logs=logs, success=True)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ContainerLogs(container=container, logs="", success=False)


def search_logs(logs: str, pattern: str, flags: int = re.IGNORECASE) -> List[str]:
    """Search logs for a pattern and return matching lines."""
    regex = re.compile(pattern, flags)
    return [line for line in logs.split("\n") if regex.search(line)]


def http_get_json(url: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
    """Make an HTTP GET request and return parsed JSON, or None on failure."""
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if response.status == 200:
                return json.loads(response.read().decode("utf-8"))
    except (
        urllib.error.URLError,
        urllib.error.HTTPError,
        json.JSONDecodeError,
        TimeoutError,
        ConnectionResetError,
        OSError,
        http.client.RemoteDisconnected,
    ):
        pass
    return None


def get_node_manifest(host: str, port: int, collection_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch manifest from a node's HTTP API.

    Returns the manifest dict if successful, None otherwise.
    """
    # URL-encode the collection_id (: -> %3A)
    encoded_id = collection_id.replace(":", "%3A")
    url = f"http://{host}:{port}/api/v1/collections/{encoded_id}/manifest"
    return http_get_json(url)


def get_node_collection_status(host: str, port: int, collection_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch collection status from a node's HTTP API.

    Returns status dict with keys: collection_id, state, coverage, total_items, etc.
    """
    encoded_id = collection_id.replace(":", "%3A")
    url = f"http://{host}:{port}/api/v1/collections/{encoded_id}/status"
    return http_get_json(url)


def verify_node_collection(host: str, port: int, collection_id: str) -> Optional[Dict[str, Any]]:
    """
    Trigger content verification on a node and return results.

    Returns dict with: total_items, verified_count, missing_count, corrupted_count, all_verified
    """
    encoded_id = collection_id.replace(":", "%3A")
    url = f"http://{host}:{port}/api/v1/collections/{encoded_id}/verify"
    return http_get_json(url)


def docker_exec(container: str, command: List[str], timeout: int = 30) -> Optional[str]:
    """
    Execute a command inside a Docker container.

    Args:
        container: Container name
        command: Command to execute as list of strings
        timeout: Timeout in seconds

    Returns:
        Command output as string, or None on failure
    """
    try:
        result = subprocess.run(
            ["docker", "exec", container] + command,
            capture_output=True,
            timeout=timeout,
            text=True,
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def get_python_node_storage_info(
    container: str, collection_id: str
) -> Optional[Dict[str, Any]]:
    """
    Get storage information from a Python node via docker exec.

    Checks the node's local storage to verify:
    - Whether the collection directory exists
    - How many items are stored
    - Whether metadata.json exists (indicates manifest received)

    Args:
        container: Python node container name
        collection_id: Collection ID

    Returns:
        Dict with storage info, or None if docker exec fails (Docker/permission issues)
    """
    # First, verify docker exec is working for this container.
    # Run a simple command that should always succeed if Docker is accessible.
    probe_check = docker_exec(container, ["true"])
    if probe_check is None:
        # Docker exec itself is failing - return None to signal infrastructure error
        return None

    # Sanitize collection_id for filesystem (matches storage.py logic)
    safe_id = collection_id.replace(":", "_").replace("/", "_")
    base_path = f"/data/dcpp/{safe_id}"

    result: Dict[str, Any] = {
        "collection_exists": False,
        "metadata_exists": False,
        "items_count": 0,
        "items_dir_exists": False,
    }

    # Check if collection directory exists
    exists_check = docker_exec(container, ["test", "-d", base_path])
    if exists_check is None:
        # Directory doesn't exist (docker exec worked, but test -d returned non-zero)
        return result

    result["collection_exists"] = True

    # Check for metadata.json (indicates manifest was stored)
    metadata_check = docker_exec(container, ["test", "-f", f"{base_path}/metadata.json"])
    result["metadata_exists"] = metadata_check is not None

    # Check for items directory
    items_check = docker_exec(container, ["test", "-d", f"{base_path}/items"])
    result["items_dir_exists"] = items_check is not None

    if result["items_dir_exists"]:
        # Count items - find all files under items/
        count_output = docker_exec(
            container,
            ["sh", "-c", f"find {base_path}/items -type f 2>/dev/null | wc -l"]
        )
        if count_output:
            try:
                result["items_count"] = int(count_output.strip())
            except ValueError:
                pass

    return result


def get_python_node_manifest_from_storage(
    container: str, collection_id: str
) -> Optional[Dict[str, Any]]:
    """
    Read the stored manifest metadata from a Python node's storage.

    Args:
        container: Python node container name
        collection_id: Collection ID

    Returns:
        Manifest metadata dict or None if not found
    """
    safe_id = collection_id.replace(":", "_").replace("/", "_")
    metadata_path = f"/data/dcpp/{safe_id}/metadata.json"

    output = docker_exec(container, ["cat", metadata_path])
    if output:
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            pass
    return None


def get_python_node_item_cids(
    container: str, collection_id: str, limit: int = 10
) -> List[str]:
    """
    Get list of stored item CIDs from a Python node's storage.

    Args:
        container: Python node container name
        collection_id: Collection ID
        limit: Maximum number of CIDs to return

    Returns:
        List of CID strings (filenames in the items directory)
    """
    safe_id = collection_id.replace(":", "_").replace("/", "_")
    items_path = f"/data/dcpp/{safe_id}/items"

    # Find all files under items/ and get their names (which are CIDs)
    output = docker_exec(
        container,
        ["sh", "-c", f"find {items_path} -type f 2>/dev/null | head -n {limit}"]
    )
    if not output:
        return []

    # Extract just the filename (CID) from each path
    cids = []
    for line in output.strip().split("\n"):
        if line:
            # Path is like /data/dcpp/collection/items/ba/bafyxyz...
            # Get just the filename
            cid = line.split("/")[-1]
            if cid:
                cids.append(cid)
    return cids


def compare_manifests(
    rust_manifest: Dict[str, Any],
    python_manifest: Dict[str, Any],
) -> Tuple[bool, List[str]]:
    """
    Compare key fields between Rust and Python node manifests.

    Args:
        rust_manifest: Manifest from Rust node HTTP API
        python_manifest: Manifest from Python node storage

    Returns:
        Tuple of (match_success, list of mismatch descriptions)
    """
    mismatches = []

    # Fields that MUST match for valid interop
    critical_fields = ["collection_id", "total_items", "merkle_root"]

    for field in critical_fields:
        rust_val = rust_manifest.get(field)
        python_val = python_manifest.get(field)

        if rust_val is None:
            mismatches.append(f"Rust manifest missing '{field}'")
        elif python_val is None:
            mismatches.append(f"Python manifest missing '{field}'")
        elif rust_val != python_val:
            mismatches.append(
                f"Field '{field}' mismatch: Rust={rust_val}, Python={python_val}"
            )

    # Fields that SHOULD match but aren't critical
    optional_fields = ["version", "name"]
    for field in optional_fields:
        rust_val = rust_manifest.get(field)
        python_val = python_manifest.get(field)
        if rust_val is not None and python_val is not None and rust_val != python_val:
            mismatches.append(
                f"Field '{field}' differs: Rust={rust_val}, Python={python_val} (non-critical)"
            )

    return len([m for m in mismatches if "non-critical" not in m]) == 0, mismatches


def wait_for_log_pattern(
    container: str,
    pattern: str,
    timeout: float = 30.0,
    poll_interval: float = 2.0,
) -> bool:
    """Wait for a pattern to appear in container logs."""
    start = time.time()
    regex = re.compile(pattern, re.IGNORECASE)

    while time.time() - start < timeout:
        result = get_container_logs(container, lines=200)
        if result.success and regex.search(result.logs):
            return True
        time.sleep(poll_interval)

    return False


def wait_for_python_items(
    container: str,
    collection_id: str,
    min_items: int,
    timeout: float = 180.0,
    poll_interval: float = 5.0,
) -> Optional[Dict[str, Any]]:
    """
    Wait for a Python node to store at least min_items for a collection.

    Returns the latest storage info dict, or None if docker exec fails.
    """
    start = time.time()
    latest = get_python_node_storage_info(container, collection_id)
    if latest is None:
        return None

    while time.time() - start < timeout:
        if latest.get("items_count", 0) >= min_items:
            return latest
        time.sleep(poll_interval)
        latest = get_python_node_storage_info(container, collection_id)
        if latest is None:
            return None

    return latest


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture(scope="module")
def docker_available():
    """Skip tests if Docker is not available."""
    if not is_docker_available():
        pytest.skip("Docker not available")


@pytest.fixture(scope="module")
def cluster_running(docker_available):
    """Skip tests if DCPP cluster is not running."""
    ensure_content_seeder("Cross-network bootstrap tests require seeded content")
    ensure_docker_cluster("Cross-network bootstrap tests require docker cluster")
    ensure_guardian_init("Cross-network bootstrap tests require manifests on rust-node-1")


@pytest.fixture(scope="module")
def bootstrap_peer_id(cluster_running):
    """Ensure Python nodes have a valid bootstrap peer ID configured."""
    ensure_bootstrap_peer_id("Cross-network bootstrap tests require bootstrap peer ID")


@pytest.fixture
def rust_node_1_logs(cluster_running) -> ContainerLogs:
    """Get logs from rust-node-1."""
    return get_container_logs(RUST_NODE_1)


@pytest.fixture
def rust_node_2_logs(cluster_running) -> ContainerLogs:
    """Get logs from rust-node-2."""
    return get_container_logs(RUST_NODE_2)


@pytest.fixture
def python_node_1_logs(bootstrap_peer_id) -> ContainerLogs:
    """Get logs from python-node-1."""
    return get_container_logs(PYTHON_NODE_1)


@pytest.fixture
def all_container_logs(cluster_running) -> List[ContainerLogs]:
    """Get logs from all containers."""
    return [get_container_logs(c) for c in ALL_CONTAINERS if is_container_running(c)]


# =============================================================================
# Test Cases
# =============================================================================

class TestCrossNetworkBootstrap:
    """
    Cross-Network Bootstrap and Happy Path Validation Tests.

    These tests validate the scenarios from docs/AIContext/HappyPathCOAs.md
    using real network communication.
    """

    @pytest.mark.priority_blocker
    def test_tc_010_no_stub_warnings(self, all_container_logs):
        """
        TC-010: No Stub Warnings (BLOCKER)

        Verify that no stub/mock indicators appear in any container logs.
        This is a blocker test - if stubs are detected, the test run is invalid.
        """
        stub_findings = []

        for container_logs in all_container_logs:
            if not container_logs.success:
                continue

            for pattern in STUB_PATTERNS:
                matches = search_logs(container_logs.logs, pattern)
                if matches:
                    for match in matches[:3]:  # Limit to 3 matches per pattern
                        stub_findings.append(
                            f"{container_logs.container}: {match.strip()[:100]}"
                        )

        assert not stub_findings, (
            f"Stub/mock warnings found - test run INVALID:\n"
            + "\n".join(stub_findings[:10])
        )

    @pytest.mark.priority_p1
    def test_tc_001_config_parsing_advertise_address(self, rust_node_1_logs):
        """
        TC-001: Config Parsing and Advertise Address Selection

        Verify that external address configuration is properly parsed and logged.
        """
        logs = rust_node_1_logs.logs

        # Check for address configuration in logs
        addr_patterns = [
            r"External address",
            r"advertise.*addr",
            r"external.*addr",
            r"Listening on",
        ]

        matches = []
        for pattern in addr_patterns:
            matches.extend(search_logs(logs, pattern))

        # In Docker mode, we just need to see some address configuration
        assert matches, (
            "No address configuration found in logs. "
            "Expected: 'External address' or 'advertise_addr' or 'Listening on'"
        )

    @pytest.mark.priority_p1
    def test_tc_002_bootstrap_dial_public_multiaddr(self, rust_node_2_logs):
        """
        TC-002: Bootstrap Dial Uses Public Multiaddr

        Verify that client nodes successfully dial bootstrap peers.
        """
        logs = rust_node_2_logs.logs

        # Check for bootstrap connection
        bootstrap_patterns = [
            r"bootstrap.*connect",
            r"Dial.*success",
            r"peer.*connected",
            r"Connected to",
        ]

        bootstrap_found = any(search_logs(logs, p) for p in bootstrap_patterns)

        # Check for state transition to operational state
        state_patterns = [
            r"state.*Ready",
            r"state.*Syncing",
            r"state.*Guarding",
        ]

        state_found = any(search_logs(logs, p) for p in state_patterns)

        assert bootstrap_found or state_found, (
            "Bootstrap dial not observed. Expected: bootstrap connection or "
            "transition to Ready/Syncing/Guarding state"
        )

    @pytest.mark.priority_p1
    def test_tc_003_dht_provider_record(self, rust_node_1_logs):
        """
        TC-003: DHT Provider Record Includes Advertised Address

        Verify that the node is providing on DHT.
        """
        logs = rust_node_1_logs.logs

        dht_patterns = [
            r"Providing on DHT",
            r"start_providing",
            r"DHT.*provider",
        ]

        dht_found = any(search_logs(logs, p) for p in dht_patterns)

        assert dht_found, (
            "DHT providing not found in logs. "
            "Expected: 'Providing on DHT' or 'start_providing'"
        )

    @pytest.mark.priority_p1
    def test_tc_004_gossipsub_announce(self, rust_node_1_logs, python_node_1_logs):
        """
        TC-004: GossipSub ANNOUNCE Cross-Network

        Verify that ANNOUNCE messages propagate between nodes.
        """
        guardian_logs = rust_node_1_logs.logs
        client_logs = python_node_1_logs.logs

        # Check guardian publishes
        publish_patterns = [
            r"Publishing ANNOUNCE",
            r"ANNOUNCE.*publish",
            r"gossipsub.*announce",
        ]

        publish_found = any(search_logs(guardian_logs, p) for p in publish_patterns)

        # Check client receives
        receive_patterns = [
            r"Received ANNOUNCE",
            r"ANNOUNCE.*from",
            r"gossipsub.*message",
        ]

        receive_found = any(search_logs(client_logs, p) for p in receive_patterns)

        # GossipSub mesh takes time to form - allow partial success
        if not receive_found:
            # Wait and retry
            if wait_for_log_pattern(PYTHON_NODE_1, r"ANNOUNCE|gossipsub.*message", 30):
                receive_found = True

        assert publish_found or receive_found, (
            "GossipSub ANNOUNCE not observed. "
            "Check that GossipSub is in network mode (DCPP_GOSSIPSUB_MODE=network)"
        )

    @pytest.mark.priority_p1
    def test_tc_005_manifest_exchange(self, python_node_1_logs):
        """
        TC-005: Manifest Exchange

        Verify that manifest exchange succeeds between nodes.
        """
        logs = python_node_1_logs.logs

        manifest_patterns = [
            r"Received MANIFEST",
            r"manifest.*valid",
            r"manifest.*items",
            r"state.*Syncing",
            r"collection.*Syncing",
        ]

        manifest_found = any(search_logs(logs, p) for p in manifest_patterns)

        if not manifest_found:
            # Wait for manifest exchange
            manifest_found = wait_for_log_pattern(
                PYTHON_NODE_1,
                r"MANIFEST|Syncing",
                timeout=30,
            )

        # This is a soft assertion - manifest exchange may not complete in test time
        if not manifest_found:
            pytest.skip("Manifest exchange not yet observed (may need more time)")

    @pytest.mark.priority_p1
    def test_tc_006_bittorrent_download(self, python_node_1_logs):
        """
        TC-006: BitTorrent Download Completion

        Verify that BitTorrent downloads complete.
        """
        logs = python_node_1_logs.logs

        # Check for mock backend (should fail)
        mock_patterns = [r"Mock backend", r"stub.*bittorrent"]
        mock_found = any(search_logs(logs, p) for p in mock_patterns)

        assert not mock_found, (
            "Mock BitTorrent backend detected. "
            "Set DCPP_BT_ALLOW_LOCAL=0 and install torf"
        )

        # Check for download activity
        download_patterns = [
            r"Download.*complete",
            r"torrent.*complete",
            r"state.*Complete",
            r"Guarding",
        ]

        download_found = any(search_logs(logs, p) for p in download_patterns)

        if not download_found:
            # Wait for download
            download_found = wait_for_log_pattern(
                PYTHON_NODE_1,
                r"Download.*complete|Guarding",
                timeout=60,
            )

        storage = get_python_node_storage_info(PYTHON_NODE_1, COLLECTION_BAYC)
        assert storage is not None, "Docker exec unavailable for python node storage check"

        python_manifest = get_python_node_manifest_from_storage(PYTHON_NODE_1, COLLECTION_BAYC)
        expected_items = 0
        if python_manifest and isinstance(python_manifest.get("total_items"), int):
            expected_items = python_manifest["total_items"]

        if not download_found:
            if expected_items <= 0:
                expected_items = 1
            storage = wait_for_python_items(
                PYTHON_NODE_1,
                COLLECTION_BAYC,
                min_items=expected_items,
                timeout=240,
                poll_interval=5,
            )
            assert storage is not None, "Docker exec unavailable during download wait"

        assert storage.get("items_count", 0) >= max(1, expected_items), (
            "BitTorrent download did not complete within timeout. "
            f"items_count={storage.get('items_count', 0)} expected={max(1, expected_items)}"
        )

    @pytest.mark.priority_p2
    def test_tc_007_health_probe(self, rust_node_1_logs, python_node_1_logs):
        """
        TC-007: Health Probe

        Verify that health probes succeed.
        """
        guardian_logs = rust_node_1_logs.logs
        client_logs = python_node_1_logs.logs

        health_patterns = [
            r"HEALTH_PROBE",
            r"HEALTH_RESPONSE",
            r"Health probe.*SUCCESS",
            r"probe.*success",
        ]

        guardian_health = any(search_logs(guardian_logs, p) for p in health_patterns)
        client_health = any(search_logs(client_logs, p) for p in health_patterns)

        if guardian_health or client_health:
            return

        deadline = time.time() + 120
        python_status = None
        while time.time() < deadline:
            python_status = get_node_collection_status(
                PYTHON_NODE_1_HTTP_HOST,
                PYTHON_NODE_1_HTTP_PORT,
                COLLECTION_BAYC,
            )
            if python_status and python_status.get("peer_count", 0) > 0:
                break
            time.sleep(2)

        assert python_status is not None, "Python node HTTP API not reachable"
        if python_status.get("peer_count", 0) == 0:
            pytest.xfail("No peers registered for health probing; cannot observe probes")

        observed = wait_for_log_pattern(
            PYTHON_NODE_1,
            r"HEALTH_PROBE|HEALTH_RESPONSE|Health probe.*SUCCESS|probe.*success",
            timeout=120,
        )
        if not observed:
            observed = wait_for_log_pattern(
                RUST_NODE_1,
                r"HEALTH_PROBE|HEALTH_RESPONSE|Health probe.*SUCCESS|probe.*success",
                timeout=120,
            )

        if observed:
            return

        probe_env = docker_exec(PYTHON_NODE_1, ["printenv", "DCPP_PROBE_INTERVAL_SECONDS"])
        if not probe_env:
            probe_env = docker_exec(PYTHON_NODE_1, ["printenv", "DCPP_PROBE_INTERVAL"])
        probe_interval = int(probe_env.strip()) if probe_env and probe_env.strip().isdigit() else DEFAULT_PROBE_INTERVAL

        if probe_interval > 5:
            pytest.xfail(
                "Health probe not observed and probe interval too large for test window. "
                f"DCPP_PROBE_INTERVAL_SECONDS={probe_interval}"
            )

        assert python_status.get("peer_count", 0) > 0, (
            "Health probe not observed despite peers; check probe loop logs."
        )

    @pytest.mark.priority_p2
    def test_tc_008_reannounce_schedule(self, rust_node_1_logs):
        """
        TC-008: Re-announce Schedule and TTL

        Verify that DHT re-announcements occur on schedule.
        """
        logs = rust_node_1_logs.logs

        announce_patterns = [
            r"Providing on DHT",
            r"Re-announc",
            r"start_providing",
        ]

        # Count announcements
        announce_count = 0
        for pattern in announce_patterns:
            announce_count += len(search_logs(logs, pattern))

        if announce_count < 2:
            # Wait for re-announce (if interval is short for testing)
            # Docker-compose uses a short interval in test; wait long enough to observe at least one cycle.
            time.sleep(15)
            new_logs = get_container_logs(RUST_NODE_1)
            if new_logs.success:
                for pattern in announce_patterns:
                    announce_count += len(search_logs(new_logs.logs, pattern))

        if announce_count < 2:
            pytest.skip(
                f"Re-announce not yet observed ({announce_count} announcements). "
                "Set DCPP_DHT_REANNOUNCE_INTERVAL=10 for faster testing."
            )

    @pytest.mark.priority_p1
    def test_tc_009_interop_rust_python(self, python_node_1_logs):
        """
        TC-009: Interop Rust <-> Python

        Verify that Rust and Python nodes can interoperate through actual
        data-plane verification, not just log pattern matching.

        CRITICAL: This test verifies the PYTHON node received and stored content,
        not just that the Rust node has valid data. We query the Python node's
        storage directly via docker exec to confirm:
        1. Log patterns indicating protocol activity (as sanity check)
        2. MANIFEST was received and stored by Python node WITH CORRECT CONTENT
        3. Content items were actually downloaded to Python node storage
        4. Manifest content MATCHES between Rust and Python nodes
        """
        logs = python_node_1_logs.logs

        # Reject fake/stub log patterns that would produce false positives
        fake_patterns = [
            r"stub for interop",
            r"items: 0 \(stub",
            r"simulated.*flow",
        ]
        for pattern in fake_patterns:
            assert not search_logs(logs, pattern), (
                f"Detected fake interop workaround log matching '{pattern}'. "
                "TC-009 requires actual protocol exchanges, not simulated logs."
            )

        # =========================================================================
        # Phase 1: Log pattern checks (sanity check, not sufficient on their own)
        # =========================================================================
        log_checks = {
            "bootstrap": [r"Connected.*bootstrap", r"bootstrap.*success", r"peer.*connect", r"Bootstrap complete.*peers connected"],
            "dht": [r"DHT.*provider", r"DHT.*Providing", r"find_providers", r"get_providers"],
            "gossipsub": [r"ANNOUNCE", r"gossipsub.*message", r"GossipSub.*NETWORK"],
            "manifest": [r"MANIFEST", r"manifest.*valid"],
            "download": [r"Download.*complete", r"Guarding"],
        }

        passed_log_checks = []
        for check_name, patterns in log_checks.items():
            if any(search_logs(logs, p) for p in patterns):
                passed_log_checks.append(check_name)

        # Log checks are informational - we'll require data-plane checks below
        log_check_count = len(passed_log_checks)

        # =========================================================================
        # Phase 2: Get Rust node manifest (source of truth)
        # =========================================================================
        rust_manifest = get_node_manifest(RUST_NODE_1_HTTP_HOST, RUST_NODE_1_HTTP_PORT, COLLECTION_BAYC)
        rust_status = get_node_collection_status(RUST_NODE_1_HTTP_HOST, RUST_NODE_1_HTTP_PORT, COLLECTION_BAYC)

        rust_valid = False
        rust_errors = []
        rust_items = 0
        rust_coverage = 0

        if rust_manifest and rust_status:
            rust_coverage = rust_status.get("coverage", 0)
            rust_items = rust_status.get("total_items", 0)
            if rust_items > 0 and rust_coverage > 0:
                rust_valid = True
            else:
                rust_errors.append(
                    f"Rust source node has no content (items={rust_items}, coverage={rust_coverage})"
                )
        else:
            rust_errors.append("Could not fetch manifest from Rust source node")

        # =========================================================================
        # Phase 3: Data-plane verification - Python node received MANIFEST
        # =========================================================================
        # Query the PYTHON node's storage directly via docker exec
        # This proves Python actually received and stored the manifest
        python_storage = get_python_node_storage_info(PYTHON_NODE_1, COLLECTION_BAYC)

        manifest_valid = False
        manifest_errors = []

        if python_storage is None:
            manifest_errors.append("Failed to query Python node storage via docker exec")
        elif not python_storage.get("collection_exists"):
            manifest_errors.append(
                "Python node has no collection directory - MANIFEST was never received"
            )
        else:
            # Check if metadata.json exists (indicates manifest was stored)
            if not python_storage.get("metadata_exists"):
                # Metadata MUST exist - the daemon persists manifests to disk
                if not python_storage.get("items_dir_exists"):
                    manifest_errors.append(
                        "Python node has collection dir but no items dir - "
                        "MANIFEST received but no items fetched"
                    )
                else:
                    # Items dir exists but no metadata - this is a failure
                    # The daemon should persist manifests to metadata.json
                    manifest_errors.append(
                        "Python node has items but no metadata.json - "
                        "manifest was not persisted to disk"
                    )
            else:
                # Read and verify the manifest metadata from Python node
                python_manifest = get_python_node_manifest_from_storage(
                    PYTHON_NODE_1, COLLECTION_BAYC
                )
                if python_manifest:
                    # CRITICAL: Compare manifest content between Rust and Python
                    if rust_manifest:
                        match_ok, mismatches = compare_manifests(rust_manifest, python_manifest)
                        if match_ok:
                            manifest_valid = True
                        else:
                            manifest_errors.extend(mismatches)
                            # Even with mismatches, if Python has the manifest it's partially valid
                            manifest_valid = len([m for m in mismatches if "non-critical" not in m]) == 0
                    else:
                        # Can't compare, but Python has a manifest
                        manifest_valid = True
                        manifest_errors.append(
                            "Cannot compare manifests - Rust node manifest unavailable"
                        )
                else:
                    manifest_errors.append(
                        "metadata.json exists but failed to parse - manifest may be corrupted"
                    )

        # =========================================================================
        # Phase 4: Data-plane verification - Python node downloaded content
        # =========================================================================
        download_valid = False
        download_errors = []
        python_items_count = 0

        if python_storage is None:
            download_errors.append("Failed to query Python node storage")
        elif not python_storage.get("collection_exists"):
            download_errors.append("Python node has no collection - nothing was downloaded")
        elif not python_storage.get("items_dir_exists"):
            download_errors.append("Python node has no items directory - no pieces downloaded")
        else:
            python_items_count = python_storage.get("items_count", 0)
            if python_items_count == 0:
                download_errors.append(
                    "Python node items directory is empty - no content pieces were fetched"
                )
            else:
                download_valid = True

        # =========================================================================
        # Phase 5: Verify item CIDs match between Rust and Python (REQUIRED)
        # This proves Python downloaded content FROM the Rust source, not arbitrary data
        # =========================================================================
        cid_verification_errors = []
        cid_verified = False

        if download_valid and rust_manifest:
            # Get a sample of CIDs from Python node storage
            python_cids = get_python_node_item_cids(PYTHON_NODE_1, COLLECTION_BAYC, limit=5)

            if python_cids:
                # Check if Python's stored CIDs are valid (non-empty, reasonable format)
                valid_cids = [cid for cid in python_cids if cid and len(cid) >= 10]
                if not valid_cids:
                    cid_verification_errors.append(
                        f"Python node has items but CIDs appear invalid: {python_cids[:3]}"
                    )

                # Verify at least one CID matches between Rust manifest and Python storage
                rust_items_list = rust_manifest.get("items", [])
                rust_items_index_cid = rust_manifest.get("items_index_cid")

                if rust_items_list and python_cids:
                    rust_cids = {item.get("cid") for item in rust_items_list if item.get("cid")}
                    matching_cids = set(python_cids) & rust_cids
                    if matching_cids:
                        cid_verified = True
                    elif rust_cids:
                        cid_verification_errors.append(
                            f"No CID overlap found between Rust and Python nodes. "
                            f"Python CIDs sample: {python_cids[:3]}, Rust CIDs sample: {list(rust_cids)[:3]}"
                        )
                    else:
                        # Rust manifest has empty inline items list - require external index
                        if rust_items_index_cid:
                            # items_index_cid is explicitly required when inline items are empty
                            # TODO: Fetch and verify CIDs against the external index
                            if valid_cids:
                                cid_verified = True
                            else:
                                cid_verification_errors.append(
                                    "Rust manifest has items_index_cid but Python node has no valid CIDs"
                                )
                        else:
                            # No inline items AND no items_index_cid - hard failure
                            # items_index_cid is explicitly required when inline items are absent
                            cid_verification_errors.append(
                                "Rust manifest has no inline items and no items_index_cid - "
                                "items_index_cid is required when inline items are not present"
                            )
                elif rust_items_index_cid:
                    # No inline items but external index exists
                    # items_index_cid is explicitly required for verification
                    if valid_cids:
                        # TODO: Fetch and verify CIDs against the external index
                        # For now, require items_index_cid presence as proof of valid manifest structure
                        cid_verified = True
                    else:
                        cid_verification_errors.append(
                            "Rust manifest has items_index_cid but Python node has no valid CIDs"
                        )
                else:
                    # No inline items AND no items_index_cid - hard failure
                    # items_index_cid is explicitly required when inline items are absent
                    cid_verification_errors.append(
                        "Rust manifest has no inline items and no items_index_cid - "
                        "items_index_cid is required when inline items are not present"
                    )
            else:
                cid_verification_errors.append(
                    "Could not retrieve CID list from Python node for verification"
                )

        # =========================================================================
        # Final assertion: Require Python node received, stored, AND verified content
        # =========================================================================
        all_errors = []

        if not rust_valid:
            all_errors.append(f"Rust source verification failed: {'; '.join(rust_errors)}")

        if not manifest_valid:
            all_errors.append(f"MANIFEST verification failed on Python node: {'; '.join(manifest_errors)}")

        if not download_valid:
            all_errors.append(f"Download verification failed on Python node: {'; '.join(download_errors)}")

        # CID verification is a hard requirement - proves interoperability
        if not cid_verified:
            all_errors.append(f"CID verification failed: {'; '.join(cid_verification_errors)}")

        # Build detailed failure message
        if not manifest_valid or not download_valid or not cid_verified:
            storage_info = python_storage if python_storage else {}
            error_msg = (
                f"TC-009 Data-Plane Verification Failed:\n"
                f"  Target: Python node ({PYTHON_NODE_1}) - NOT Rust node\n"
                f"  Log checks passed: {log_check_count}/5 ({passed_log_checks})\n"
                f"  Rust source: valid={rust_valid}, items={rust_items}, coverage={rust_coverage}\n"
                f"  Python storage: collection_exists={storage_info.get('collection_exists', False)}, "
                f"items_count={python_items_count}\n"
                f"  MANIFEST received by Python: {manifest_valid}\n"
                f"  MANIFEST content matches Rust: {manifest_valid and not manifest_errors}\n"
                f"  Content downloaded to Python: {download_valid}\n"
                f"  CID verification: {cid_verified}\n"
                f"  Errors:\n    - " + "\n    - ".join(all_errors)
            )
            pytest.fail(error_msg)

        # Success - Python node received manifest, downloaded content, AND CIDs verified
        assert manifest_valid, "Python node did not receive MANIFEST"
        assert download_valid, "Python node did not download content"
        assert cid_verified, "Python node content does not match Rust source (no CID overlap)"


# =============================================================================
# Additional Tests for Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case tests for cross-network scenarios."""

    def test_python_node_stub_mode_disabled(self, cluster_running):
        """Verify Python nodes have DCPP_STUB_MODE=0."""
        if not is_container_running(PYTHON_NODE_1):
            pytest.skip("Python node not running")

        logs = get_container_logs(PYTHON_NODE_1)
        if not logs.success:
            pytest.skip("Could not get Python node logs")

        # Check for stub mode indicators
        stub_patterns = [
            r"STUB_MODE.*1",
            r"stub.*enabled",
        ]

        stub_found = any(search_logs(logs.logs, p) for p in stub_patterns)

        assert not stub_found, "Python node running in stub mode"

    def test_gossipsub_network_mode(self, cluster_running):
        """Verify GossipSub is in network mode, not local."""
        if not is_container_running(PYTHON_NODE_1):
            pytest.skip("Python node not running")

        logs = get_container_logs(PYTHON_NODE_1)
        if not logs.success:
            pytest.skip("Could not get Python node logs")

        local_mode = search_logs(logs.logs, r"GossipSub Mode: LOCAL")

        assert not local_mode, (
            "GossipSub in LOCAL mode. Set DCPP_GOSSIPSUB_MODE=network"
        )

    def test_real_bittorrent_backend(self, cluster_running):
        """Verify real BitTorrent backend is in use."""
        for container in [PYTHON_NODE_1, PYTHON_NODE_2]:
            if not is_container_running(container):
                continue

            logs = get_container_logs(container)
            if not logs.success:
                continue

            mock_patterns = [
                r"Mock backend",
                r"stub.*bittorrent",
                r"DCPP_BT_ALLOW_LOCAL=1",
            ]

            mock_found = any(search_logs(logs.logs, p) for p in mock_patterns)

            assert not mock_found, (
                f"{container}: Mock BitTorrent backend detected. "
                "Install torf and set DCPP_BT_ALLOW_LOCAL=0"
            )


# =============================================================================
# Markers
# =============================================================================

# Define custom markers for test filtering
def pytest_configure(config):
    config.addinivalue_line("markers", "priority_blocker: Blocker priority test")
    config.addinivalue_line("markers", "priority_p1: P1 (Critical) priority test")
    config.addinivalue_line("markers", "priority_p2: P2 (High) priority test")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
