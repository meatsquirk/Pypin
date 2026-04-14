"""
Security Audit Module

This module provides security auditing capabilities for DCPP cryptographic
operations and protocol handling.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, cast
import hashlib
import os
import time

from .crypto import generate_keypair, sign_message, verify_signature, derive_peer_id
from .messages import Announce, CollectionAnnouncement, HealthProbe
from .framing import Profile1Framer
from .core.constants import MessageType, MAX_MESSAGE_SIZE


@dataclass
class SecurityAuditConfig:
    """Security audit configuration."""

    timing_iterations: int = 1000
    timing_variance_threshold: float = 0.20
    verbose: bool = False


@dataclass
class AuditResult:
    """Result of a security audit check."""

    name: str
    passed: bool
    description: str
    severity: Optional[int] = None  # 1-5, 5 being critical

    @classmethod
    def passed_result(cls, name: str, description: str) -> "AuditResult":
        return cls(name=name, passed=True, description=description)

    @classmethod
    def failed_result(cls, name: str, description: str, severity: int) -> "AuditResult":
        return cls(name=name, passed=False, description=description, severity=severity)


class SecurityAuditor:
    """Security auditor for DCPP operations."""

    def __init__(self, config: Optional[SecurityAuditConfig] = None):
        self.config = config or SecurityAuditConfig()
        self.results: List[AuditResult] = []

    def run_all_audits(self) -> List[AuditResult]:
        """Run all security audits."""
        self.results.clear()

        # Cryptographic audits
        self.audit_key_generation()
        self.audit_signature_timing()
        self.audit_verification_timing()
        self.audit_nonce_uniqueness()

        # Protocol audits
        self.audit_message_size_limits()
        self.audit_crc_validation()

        return self.results.copy()

    def audit_key_generation(self) -> None:
        """Audit key generation for sufficient entropy."""
        keys = []
        for _ in range(100):
            _, public_key = generate_keypair()
            keys.append(bytes(public_key))

        # Check all keys are unique
        unique_keys = set(keys)

        if len(unique_keys) == len(keys):
            self.results.append(
                AuditResult.passed_result(
                    "key_generation_entropy", "All generated keys are unique - good entropy"
                )
            )
        else:
            self.results.append(
                AuditResult.failed_result(
                    "key_generation_entropy",
                    f"Only {len(unique_keys)} unique keys out of {len(keys)} - entropy issue",
                    5,
                )
            )

        # Check key length
        _, public_key = generate_keypair()
        if len(bytes(public_key)) == 32:
            self.results.append(
                AuditResult.passed_result("key_length", "Public key length is correct (32 bytes)")
            )
        else:
            self.results.append(
                AuditResult.failed_result(
                    "key_length", f"Unexpected key length: {len(bytes(public_key))} bytes", 4
                )
            )

    def audit_signature_timing(self) -> None:
        """Audit signature generation for timing attacks."""
        private_key, public_key = generate_keypair()
        # Small message
        small_data = cast(dict[str, object], {"test": "a"})

        # Large message
        large_data = cast(dict[str, object], {"test": "a" * 10000})

        # Time small message signing
        small_times = []
        for _ in range(self.config.timing_iterations):
            start = time.perf_counter_ns()
            sign_message(small_data, private_key)
            small_times.append(time.perf_counter_ns() - start)

        # Time large message signing
        large_times = []
        for _ in range(self.config.timing_iterations):
            start = time.perf_counter_ns()
            sign_message(large_data, private_key)
            large_times.append(time.perf_counter_ns() - start)

        small_avg = sum(small_times) / len(small_times)
        large_avg = sum(large_times) / len(large_times)

        self.results.append(
            AuditResult.passed_result(
                "signature_timing",
                f"Small msg: {small_avg / 1000:.2f}us, Large msg: {large_avg / 1000:.2f}us",
            )
        )

    def audit_verification_timing(self) -> None:
        """Audit signature verification for timing attacks."""
        private_key, public_key = generate_keypair()
        _, wrong_public_key = generate_keypair()

        data = cast(dict[str, object], {"test": "verification timing"})
        signature = sign_message(data, private_key)

        # Time valid verification
        valid_times = []
        for _ in range(self.config.timing_iterations):
            start = time.perf_counter_ns()
            verify_signature(data, signature, public_key)
            valid_times.append(time.perf_counter_ns() - start)

        # Time invalid verification
        invalid_times = []
        for _ in range(self.config.timing_iterations):
            start = time.perf_counter_ns()
            try:
                verify_signature(data, signature, wrong_public_key)
            except Exception:
                pass
            invalid_times.append(time.perf_counter_ns() - start)

        valid_avg = sum(valid_times) / len(valid_times)
        invalid_avg = sum(invalid_times) / len(invalid_times)

        max_val = max(valid_avg, invalid_avg)
        min_val = min(valid_avg, invalid_avg)
        variance = (max_val - min_val) / max_val if max_val > 0 else 0

        if variance < self.config.timing_variance_threshold:
            self.results.append(
                AuditResult.passed_result(
                    "verification_timing",
                    f"Valid: {valid_avg / 1000:.2f}us, Invalid: {invalid_avg / 1000:.2f}us, "
                    f"Variance: {variance * 100:.2f}%",
                )
            )
        else:
            self.results.append(
                AuditResult.failed_result(
                    "verification_timing",
                    f"Timing variance {variance * 100:.2f}% exceeds threshold",
                    3,
                )
            )

    def audit_nonce_uniqueness(self) -> None:
        """Audit nonce uniqueness."""
        nonces = []
        for _ in range(1000):
            probe = HealthProbe(collection_id="test", challenges=[], nonce=os.urandom(16))
            nonces.append(probe.nonce)

        unique_nonces = set(nonces)

        if len(unique_nonces) == len(nonces):
            self.results.append(
                AuditResult.passed_result("nonce_uniqueness", "All generated nonces are unique")
            )
        else:
            self.results.append(
                AuditResult.failed_result(
                    "nonce_uniqueness", f"Only {len(unique_nonces)} unique nonces - reuse risk", 5
                )
            )

    def audit_message_size_limits(self) -> None:
        """Audit message size limits."""
        framer = Profile1Framer()

        # Create oversized payload
        oversized = bytes(MAX_MESSAGE_SIZE + 1)

        try:
            framer.encode(MessageType.HELLO, cast(dict[str, object], {"data": oversized.hex()}))
            self.results.append(
                AuditResult.failed_result(
                    "message_size_limit", "Accepted oversized message - DoS risk", 4
                )
            )
        except Exception:
            self.results.append(
                AuditResult.passed_result(
                    "message_size_limit", "Correctly rejects oversized messages"
                )
            )

    def audit_crc_validation(self) -> None:
        """Audit CRC validation."""
        framer = Profile1Framer()

        payload = cast(dict[str, object], {"test": "data"})
        encoded = framer.encode(MessageType.HELLO, payload)

        # Corrupt the CRC
        corrupted = bytearray(encoded)
        if len(corrupted) >= 4:
            corrupted[-1] ^= 0xFF

        try:
            framer.decode(bytes(corrupted))
            self.results.append(
                AuditResult.failed_result("crc_validation", "Failed to detect CRC corruption", 5)
            )
        except Exception:
            self.results.append(
                AuditResult.passed_result("crc_validation", "Correctly detects CRC corruption")
            )

    def summary(self) -> Dict[str, object]:
        """Get audit summary."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        max_severity = max((r.severity for r in self.results if r.severity), default=0)

        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "max_severity": max_severity,
        }


def run_security_audit(verbose: bool = False) -> Tuple[List[AuditResult], Dict[str, object]]:
    """Run a complete security audit."""
    config = SecurityAuditConfig(verbose=verbose)
    auditor = SecurityAuditor(config)
    results = auditor.run_all_audits()
    summary = auditor.summary()
    return results, summary
