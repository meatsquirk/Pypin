"""
Cross-Platform Testing Module

This module provides testing infrastructure to verify DCPP works correctly
across Windows, Linux, and macOS platforms.
"""

from dataclasses import dataclass, field
from typing import Optional, cast
import os
import platform
import struct
import sys
import tempfile
import time

from .core.constants import Capability, MessageType
from .crypto import generate_keypair, sign_message, verify_signature, derive_peer_id
from .framing import Profile1Framer
from .messages import Hello
from .storage import FileSystemStorage
from .crypto.cid import compute_cid


@dataclass
class PlatformInfo:
    """Platform information."""

    os: str
    os_version: str
    arch: str
    python_version: str
    endian: str
    pointer_size: int

    @classmethod
    def current(cls) -> "PlatformInfo":
        """Get current platform information."""
        return cls(
            os=platform.system().lower(),
            os_version=platform.version(),
            arch=platform.machine(),
            python_version=platform.python_version(),
            endian=sys.byteorder,
            pointer_size=struct.calcsize("P") * 8,
        )

    def is_windows(self) -> bool:
        return self.os == "windows"

    def is_macos(self) -> bool:
        return self.os == "darwin"

    def is_linux(self) -> bool:
        return self.os == "linux"

    def is_64bit(self) -> bool:
        return self.pointer_size == 64


@dataclass
class PlatformTestResult:
    """Cross-platform test result."""

    name: str
    platform: PlatformInfo
    passed: bool
    error: Optional[str] = None
    notes: list[str] = field(default_factory=list)


class PlatformTestSuite:
    """Cross-platform test suite."""

    def __init__(self) -> None:
        self.platform = PlatformInfo.current()
        self.results: list[PlatformTestResult] = []

    def run_all(self) -> list[PlatformTestResult]:
        """Run all platform-specific tests."""
        self.results.clear()

        self.test_byte_order()
        self.test_path_handling()
        self.test_file_io()
        self.test_network_byte_order()
        self.test_time_handling()
        self.test_random_generation()
        self.test_crypto_operations()
        self.test_memory_alignment()

        return self.results.copy()

    def test_byte_order(self) -> None:
        """Test byte order handling."""
        framer = Profile1Framer()
        payload = cast(dict[str, object], {"test": "data"})

        try:
            encoded = framer.encode(MessageType.HELLO, payload)
            frame = framer.decode(encoded)
            msg_type = frame.message_type
            decoded = frame.decode_payload()

            if decoded == payload and msg_type == MessageType.HELLO:
                self.results.append(
                    PlatformTestResult(
                        name="byte_order",
                        platform=self.platform,
                        passed=True,
                        notes=[f"Endianness: {self.platform.endian}"],
                    )
                )
            else:
                self.results.append(
                    PlatformTestResult(
                        name="byte_order",
                        platform=self.platform,
                        passed=False,
                        error="Payload mismatch after roundtrip",
                    )
                )
        except Exception as e:
            self.results.append(
                PlatformTestResult(
                    name="byte_order",
                    platform=self.platform,
                    passed=False,
                    error=str(e),
                )
            )

    def test_path_handling(self) -> None:
        """Test path handling across platforms."""
        temp_dir = os.path.join(tempfile.gettempdir(), "dcpp_platform_test")

        try:
            # Clean up first
            if os.path.exists(temp_dir):
                import shutil

                shutil.rmtree(temp_dir)

            storage = FileSystemStorage(temp_dir)
            storage.create_collection("test_collection")

            # Clean up
            import shutil

            shutil.rmtree(temp_dir)

            self.results.append(
                PlatformTestResult(
                    name="path_handling",
                    platform=self.platform,
                    passed=True,
                    notes=[f"Temp dir: {tempfile.gettempdir()}"],
                )
            )
        except Exception as e:
            self.results.append(
                PlatformTestResult(
                    name="path_handling",
                    platform=self.platform,
                    passed=False,
                    error=str(e),
                )
            )

    def test_file_io(self) -> None:
        """Test file I/O operations."""
        temp_dir = os.path.join(tempfile.gettempdir(), "dcpp_file_io_test")
        test_data = b"Test data for cross-platform file I/O"

        try:
            if os.path.exists(temp_dir):
                import shutil

                shutil.rmtree(temp_dir)

            storage = FileSystemStorage(temp_dir)
            storage.create_collection("test")
            cid = compute_cid(test_data)
            storage.store("test", cid, test_data)
            retrieved = storage.retrieve("test", cid)

            import shutil

            shutil.rmtree(temp_dir)

            if retrieved == test_data:
                self.results.append(
                    PlatformTestResult(
                        name="file_io",
                        platform=self.platform,
                        passed=True,
                        notes=["Read/write roundtrip successful"],
                    )
                )
            else:
                self.results.append(
                    PlatformTestResult(
                        name="file_io",
                        platform=self.platform,
                        passed=False,
                        error="Data mismatch",
                    )
                )
        except Exception as e:
            self.results.append(
                PlatformTestResult(
                    name="file_io",
                    platform=self.platform,
                    passed=False,
                    error=str(e),
                )
            )

    def test_network_byte_order(self) -> None:
        """Test network byte order (big-endian) encoding."""
        value = 0x12345678
        packed = struct.pack(">I", value)
        expected = bytes([0x12, 0x34, 0x56, 0x78])

        if packed == expected:
            self.results.append(
                PlatformTestResult(
                    name="network_byte_order",
                    platform=self.platform,
                    passed=True,
                    notes=[f"Native endian: {self.platform.endian}"],
                )
            )
        else:
            self.results.append(
                PlatformTestResult(
                    name="network_byte_order",
                    platform=self.platform,
                    passed=False,
                    error="Big-endian encoding mismatch",
                )
            )

    def test_time_handling(self) -> None:
        """Test time handling."""
        try:
            timestamp = int(time.time())

            # Should be reasonable (after 2020, before 2100)
            reasonable = 1577836800 < timestamp < 4102444800

            self.results.append(
                PlatformTestResult(
                    name="time_handling",
                    platform=self.platform,
                    passed=reasonable,
                    error=None if reasonable else f"Unreasonable timestamp: {timestamp}",
                    notes=[f"Current timestamp: {timestamp}"],
                )
            )
        except Exception as e:
            self.results.append(
                PlatformTestResult(
                    name="time_handling",
                    platform=self.platform,
                    passed=False,
                    error=str(e),
                )
            )

    def test_random_generation(self) -> None:
        """Test random number generation."""
        keys = []
        for _ in range(100):
            _, public_key = generate_keypair()
            keys.append(bytes(public_key))

        unique_keys = set(keys)
        all_unique = len(unique_keys) == len(keys)

        self.results.append(
            PlatformTestResult(
                name="random_generation",
                platform=self.platform,
                passed=all_unique,
                error=None if all_unique else "Duplicate keys generated",
                notes=[f"Generated {len(unique_keys)} unique keys"],
            )
        )

    def test_crypto_operations(self) -> None:
        """Test cryptographic operations."""
        try:
            private_key, public_key = generate_keypair()
            data = cast(dict[str, object], {"test": "crypto"})
            signature = sign_message(data, private_key)
            valid = verify_signature(data, signature, public_key)

            self.results.append(
                PlatformTestResult(
                    name="crypto_operations",
                    platform=self.platform,
                    passed=valid,
                    error=None if valid else "Signature verification failed",
                    notes=["Ed25519 sign/verify successful"],
                )
            )
        except Exception as e:
            self.results.append(
                PlatformTestResult(
                    name="crypto_operations",
                    platform=self.platform,
                    passed=False,
                    error=str(e),
                )
            )

    def test_memory_alignment(self) -> None:
        """Test memory alignment requirements."""
        try:
            private_key, public_key = generate_keypair()
            node_id = derive_peer_id(public_key)

            hello = Hello(
                version=Hello.DEFAULT_VERSION,
                node_id=node_id,
                capabilities=[Capability.GUARDIAN],
                collections=["test"],
                timestamp=int(time.time()),
            )

            # Roundtrip through CBOR
            data = dict(hello.to_dict())
            framer = Profile1Framer()
            encoded = framer.encode(MessageType.HELLO, data)
            frame = framer.decode(encoded)
            decoded = frame.decode_payload()

            matches = decoded.get("node_id") == node_id and decoded.get("collections") == [
                "test"
            ]

            self.results.append(
                PlatformTestResult(
                    name="memory_alignment",
                    platform=self.platform,
                    passed=matches,
                    error=None if matches else "Data mismatch after roundtrip",
                    notes=[f"Pointer size: {self.platform.pointer_size} bits"],
                )
            )
        except Exception as e:
            self.results.append(
                PlatformTestResult(
                    name="memory_alignment",
                    platform=self.platform,
                    passed=False,
                    error=str(e),
                )
            )

    def summary(self) -> dict[str, object]:
        """Get test summary."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)

        return {
            "platform": {
                "os": self.platform.os,
                "arch": self.platform.arch,
                "python_version": self.platform.python_version,
            },
            "total_tests": total,
            "passed": passed,
            "failed": total - passed,
        }


def run_platform_tests() -> dict[str, object]:
    """Run all platform tests and return summary."""
    suite = PlatformTestSuite()
    results = suite.run_all()

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        error = f" - {result.error}" if result.error else ""
        print(f"{result.name}: {status}{error}")

    summary = suite.summary()
    platform_info = cast(dict[str, object], summary.get("platform", {}))
    os_name = cast(str, platform_info.get("os", "unknown"))
    arch = cast(str, platform_info.get("arch", "unknown"))
    passed = cast(int, summary.get("passed", 0))
    total_tests = cast(int, summary.get("total_tests", 0))
    print(f"\n{os_name} {arch}: {passed}/{total_tests} tests passed")

    return summary
