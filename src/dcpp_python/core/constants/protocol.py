"""Protocol constants, limits, and configuration."""

from __future__ import annotations

import logging
from dataclasses import dataclass

# Protocol identifiers
# PROTOCOL_ID: libp2p protocol negotiation string (Section 4.1)
PROTOCOL_ID = "/dcpp/1.0.0"
# PROTOCOL_VERSION: Manifest protocol field value (Section 8.1)
# Note: This is different from PROTOCOL_ID - manifests use "dcpp/1.0" format
PROTOCOL_VERSION = "dcpp/1.0"

# Magic bytes for Profile 1 framing (0x44435050 = "DCPP" in ASCII)
MAGIC_BYTES = b"DCPP"
MAGIC_INT = 0x44435050

# Message size limits
MAX_MESSAGE_SIZE = 33_554_432  # 32 MB
MAX_CHALLENGE_LENGTH = 1024

# Rate limiting defaults
MAX_REQUESTS_PER_MINUTE = 100
MAX_RESPONSE_DATA_PER_MINUTE = 10 * 1024 * 1024  # 10 MB
ANNOUNCE_INTERVAL_SECONDS = 300  # 5 minutes
MIN_PROBE_INTERVAL_SECONDS = 60

# Timeout defaults (in seconds)
HELLO_TIMEOUT = 10
REQUEST_TIMEOUT = 30
HEALTH_PROBE_TIMEOUT = 5
CONNECTION_IDLE_TIMEOUT = 300  # 5 minutes
PEER_STALENESS_TIMEOUT = 3600  # 1 hour

# Clock skew tolerance (Section 13.2 - Replay Protection & Time)
# Messages with timestamps deviating more than this from local time MUST be rejected
CLOCK_SKEW_TOLERANCE_SECONDS = 300  # 5 minutes

# Connection limits (global)
MAX_PEERS_PER_COLLECTION = 50
MAX_TOTAL_CONNECTIONS = 200
MAX_STREAMS_PER_PEER = 10


@dataclass
class PeerLimits:
    """Per-peer resource limits.

    These limits are enforced independently per peer to prevent
    a single malicious peer from exhausting node resources.
    """

    # Maximum concurrent streams from a single peer
    max_concurrent_streams: int = 10
    # Maximum requests per minute from a single peer
    max_requests_per_minute: int = 100
    # Maximum response data per minute to a single peer (bytes)
    max_response_data_per_minute: int = 10 * 1024 * 1024  # 10 MB
    # Maximum ANNOUNCE messages per 5 minutes per collection
    max_announces_per_5min: int = 1

    @classmethod
    def high_trust(cls) -> "PeerLimits":
        """Create limits for high-trust peers (e.g., known guardians)."""
        return cls(
            max_concurrent_streams=50,
            max_requests_per_minute=500,
            max_response_data_per_minute=100 * 1024 * 1024,  # 100 MB
            max_announces_per_5min=5,
        )

    @classmethod
    def restrictive(cls) -> "PeerLimits":
        """Create restrictive limits for unknown peers."""
        return cls(
            max_concurrent_streams=3,
            max_requests_per_minute=30,
            max_response_data_per_minute=1 * 1024 * 1024,  # 1 MB
            max_announces_per_5min=1,
        )


@dataclass
class RetryConfig:
    """Retry configuration with exponential backoff (Section 13.2.6).

    Used for connection retries, request retries, and reconnection attempts.
    """

    # Initial delay before first retry (milliseconds)
    initial_delay_ms: int = 100
    # Maximum delay between retries (milliseconds)
    max_delay_ms: int = 30_000
    # Multiplier for exponential backoff
    multiplier: float = 2.0
    # Maximum number of retry attempts
    max_attempts: int = 5
    # Add jitter to prevent thundering herd
    add_jitter: bool = True

    def delay_for_attempt(self, attempt: int) -> int:
        """Calculate delay for a given attempt number (0-indexed)."""
        import random

        if attempt >= self.max_attempts:
            return self.max_delay_ms

        delay = self.initial_delay_ms * (self.multiplier**attempt)
        clamped = min(int(delay), self.max_delay_ms)

        if self.add_jitter:
            # Add up to 25% jitter
            jitter = int(clamped * 0.25 * random.random())
            return clamped + jitter
        return clamped

    def should_retry(self, attempt: int) -> bool:
        """Check if more retries are allowed."""
        return attempt < self.max_attempts

    @classmethod
    def aggressive(cls) -> "RetryConfig":
        """Create aggressive retry config for critical operations."""
        return cls(
            initial_delay_ms=50,
            max_delay_ms=5_000,
            multiplier=1.5,
            max_attempts=10,
            add_jitter=True,
        )

    @classmethod
    def conservative(cls) -> "RetryConfig":
        """Create conservative retry config for non-critical operations."""
        return cls(
            initial_delay_ms=500,
            max_delay_ms=60_000,
            multiplier=2.0,
            max_attempts=3,
            add_jitter=True,
        )


@dataclass
class ConnectionHealth:
    """Connection health tracking (Section 13.2.6).

    Monitors connection quality and detects unhealthy connections.
    """

    # Timestamp of last successful message (Unix timestamp)
    last_success_timestamp: float = 0.0
    # Number of consecutive failures
    consecutive_failures: int = 0
    # Total messages sent/received
    total_messages: int = 0
    # Total failed messages
    total_failures: int = 0
    # Estimated round-trip time in milliseconds
    rtt_estimate_ms: float = 100.0

    def is_healthy(self, current_timestamp: "float | None" = None) -> bool:
        """Check if connection is healthy.

        A connection is unhealthy if:
        - No successful message in the last 5 minutes, OR
        - 3 or more consecutive failures
        """
        import time

        if current_timestamp is None:
            current_timestamp = time.time()

        time_since_success = current_timestamp - self.last_success_timestamp
        return time_since_success < 300 and self.consecutive_failures < 3

    def record_success(self, rtt_ms: float, timestamp: "float | None" = None) -> None:
        """Record a successful message."""
        import time

        if timestamp is None:
            timestamp = time.time()

        self.last_success_timestamp = timestamp
        self.consecutive_failures = 0
        self.total_messages += 1

        # Update RTT estimate using exponential moving average
        self.rtt_estimate_ms = (self.rtt_estimate_ms * 7 + rtt_ms) / 8

    def record_failure(self) -> None:
        """Record a failed message."""
        self.consecutive_failures += 1
        self.total_failures += 1
        self.total_messages += 1

    def success_rate(self) -> float:
        """Get success rate as a fraction (0.0 to 1.0)."""
        if self.total_messages == 0:
            return 1.0
        return (self.total_messages - self.total_failures) / self.total_messages

    def adaptive_timeout_ms(self) -> int:
        """Calculate adaptive timeout based on RTT."""
        # Timeout = RTT + 4 * RTT_variance (simplified: use 4x RTT)
        timeout = int(self.rtt_estimate_ms * 4)
        return max(1000, min(timeout, 60_000))  # Between 1s and 60s


# DHT defaults
DHT_REANNOUNCE_INTERVAL = 3600  # 1 hour
DHT_RECORD_TTL = 86400  # 24 hours

# Field limits
MAX_HELLO_COLLECTIONS = 100
MAX_ANNOUNCE_COLLECTIONS = 50
MAX_PEERS_RESPONSE = 100
MAX_ADDRS_PER_PEER = 10
MAX_INLINE_ITEMS = 10000
MAX_MANIFEST_SIZE = 1 * 1024 * 1024  # 1 MB
MAX_MEMBERS_RESPONSE = 1000

# Sharding defaults
DEFAULT_SHARD_SIZE_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB
SHARDING_THRESHOLD_BYTES = 1 * 1024 * 1024 * 1024  # 1 GB

# Probe defaults
DEFAULT_PROBE_INTERVAL = 86400  # 24 hours
MAX_CHALLENGES_PER_PROBE = 10
MAX_PROBES_PER_MINUTE_PER_PEER = 5
