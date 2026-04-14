"""
Manifest Verification Pipeline.

Implements RFC Sections 7.4, 7.5, 7.5.1: UCI-based manifest verification with
scheme-specific verifiers for key, hash, uuid, dns, and chain schemes.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, TYPE_CHECKING, TypedDict, cast
from typing_extensions import NotRequired

import cbor2
from nacl.signing import VerifyKey

from dcpp_python.core.uci import UCI, UCIScheme, parse_uci, UCIConfig

if TYPE_CHECKING:
    from dcpp_python.manifest.manifest import Manifest
    from dcpp_python.storage.genesis import GenesisStore


logger = logging.getLogger("dcpp.manifest_verify")


# =============================================================================
# Chain Verification Configuration
# =============================================================================


def is_chain_verification_enabled() -> bool:
    """
    Check if chain verification is enabled.

    Returns True if DCPP_VERIFY_CHAIN environment variable is set to "1".
    Default is "0" (disabled) since chain verification requires external adapters.

    When enabled, chain: and dns: scheme verifiers will attempt actual verification.
    When disabled, they return "skipped" status (safe for testing).
    """
    import os

    return os.environ.get("DCPP_VERIFY_CHAIN", "0") == "1"


class VerificationStatus(Enum):
    """Verification result status."""

    VERIFIED = "verified"  # Successfully verified
    FAILED = "failed"  # Verification failed
    TOFU_ACCEPTED = "tofu_accepted"  # First-seen, trust established
    TOFU_CONFLICT = "tofu_conflict"  # Conflicts with previous genesis
    SKIPPED = "skipped"  # Verification skipped (unknown scheme, etc.)


@dataclass
class VerificationResult:
    """Result of manifest verification."""

    status: VerificationStatus
    scheme: UCIScheme
    message: str = ""
    genesis_cid: Optional[str] = None

    @property
    def is_success(self) -> bool:
        """Return True if verification was successful."""
        return self.status in {VerificationStatus.VERIFIED, VerificationStatus.TOFU_ACCEPTED}

    @property
    def is_conflict(self) -> bool:
        """Return True if this is a TOFU conflict."""
        return self.status == VerificationStatus.TOFU_CONFLICT

    @property
    def is_skipped(self) -> bool:
        """Return True if verification was skipped (unverifiable scheme)."""
        return self.status == VerificationStatus.SKIPPED

    def to_dict(self) -> VerificationResultPayload:
        """Serialize verification result to a dictionary."""
        result: VerificationResultPayload = {
            "status": self.status.value,
            "scheme": self.scheme.value,
        }
        if self.message:
            result["message"] = self.message
        if self.genesis_cid is not None:
            result["genesis_cid"] = self.genesis_cid
        return result

    @classmethod
    def verified(cls, scheme: UCIScheme, message: str = "") -> "VerificationResult":
        """Create a successful verification result."""
        return cls(VerificationStatus.VERIFIED, scheme, message)

    @classmethod
    def failed(cls, scheme: UCIScheme, message: str) -> "VerificationResult":
        """Create a failed verification result."""
        return cls(VerificationStatus.FAILED, scheme, message)

    @classmethod
    def tofu_accepted(
        cls, scheme: UCIScheme, genesis_cid: str, message: str = ""
    ) -> "VerificationResult":
        """Create a TOFU acceptance result."""
        return cls(VerificationStatus.TOFU_ACCEPTED, scheme, message, genesis_cid)

    @classmethod
    def tofu_conflict(
        cls, scheme: UCIScheme, genesis_cid: str, message: str = ""
    ) -> "VerificationResult":
        """Create a TOFU conflict result."""
        return cls(VerificationStatus.TOFU_CONFLICT, scheme, message, genesis_cid)

    @classmethod
    def skipped(cls, scheme: UCIScheme, message: str = "") -> "VerificationResult":
        """Create a skipped verification result."""
        return cls(VerificationStatus.SKIPPED, scheme, message)


class VerificationResultPayload(TypedDict):
    status: str
    scheme: str
    message: NotRequired[str]
    genesis_cid: NotRequired[str | None]


class SchemeVerifier(ABC):
    """Abstract base class for scheme-specific verifiers."""

    @abstractmethod
    async def verify(
        self,
        uci: UCI,
        manifest: "Manifest",
        manifest_cid: str,
        signature: Optional[bytes] = None,
    ) -> VerificationResult:
        """
        Verify a manifest against the UCI scheme.

        Args:
            uci: Parsed UCI
            manifest: The manifest to verify
            manifest_cid: CID of the manifest
            signature: Optional signature for key: scheme

        Returns:
            VerificationResult indicating success or failure
        """
        pass


class KeyVerifier(SchemeVerifier):
    """
    Verifier for key: scheme.

    Manifest MUST be signed by the public key specified in the UCI.
    """

    async def verify(
        self,
        uci: UCI,
        manifest: "Manifest",
        manifest_cid: str,
        signature: Optional[bytes] = None,
    ) -> VerificationResult:
        """Verify that manifest is signed by the key in UCI."""
        if signature is None:
            return VerificationResult.failed(
                UCIScheme.KEY, "Signature required for key: scheme verification"
            )

        if uci.pubkey_bytes is None:
            return VerificationResult.failed(UCIScheme.KEY, "Public key not parsed from UCI")

        # Import crypto functions
        try:
            from dcpp_python.crypto.signing import verify_signature
        except ImportError:
            return VerificationResult.failed(UCIScheme.KEY, "Crypto module not available")

        # Verify the signature against the manifest
        try:
            algorithm = uci.algorithm or "ed25519"

            if algorithm == "ed25519":
                public_key = VerifyKey(uci.pubkey_bytes)
                payload = cast(dict[str, object], manifest.to_dict())
                is_valid = verify_signature(payload, signature, public_key)
            else:
                return VerificationResult.failed(
                    UCIScheme.KEY, f"Unsupported key algorithm: {algorithm}"
                )

            if is_valid:
                return VerificationResult.verified(
                    UCIScheme.KEY, f"Manifest signed by {uci.algorithm} key"
                )
            else:
                return VerificationResult.failed(UCIScheme.KEY, "Signature verification failed")
        except Exception as e:
            return VerificationResult.failed(UCIScheme.KEY, f"Signature verification error: {e}")


class HashVerifier(SchemeVerifier):
    """
    Verifier for hash: scheme.

    Manifest merkle_root MUST equal the hash value in the UCI.
    """

    async def verify(
        self,
        uci: UCI,
        manifest: "Manifest",
        manifest_cid: str,
        signature: Optional[bytes] = None,
    ) -> VerificationResult:
        """Verify that manifest merkle_root matches the hash in UCI."""
        if uci.hash_bytes is None:
            return VerificationResult.failed(UCIScheme.HASH, "Hash value not parsed from UCI")

        # Get the merkle_root from manifest
        merkle_root = getattr(manifest, "merkle_root", None)
        if merkle_root is None:
            return VerificationResult.failed(
                UCIScheme.HASH, "Manifest does not contain merkle_root"
            )

        # Handle CID format hashes (stored as UTF-8 bytes)
        try:
            hash_str = uci.hash_bytes.decode("utf-8")
            if hash_str.startswith("bafy") or hash_str.startswith("bafk"):
                # CID format - compare directly
                if merkle_root == hash_str:
                    return VerificationResult.verified(
                        UCIScheme.HASH, "Merkle root matches UCI hash (CID)"
                    )
                else:
                    return VerificationResult.failed(
                        UCIScheme.HASH,
                        f"Merkle root mismatch: expected {hash_str}, got {merkle_root}",
                    )
        except UnicodeDecodeError:
            pass

        # Binary hash comparison
        # Convert merkle_root to bytes for comparison
        try:
            from dcpp_python.crypto.cid import parse_cid

            cid_info = parse_cid(merkle_root)
            if cid_info.digest == uci.hash_bytes:
                return VerificationResult.verified(
                    UCIScheme.HASH, "Merkle root digest matches UCI hash"
                )
        except Exception:
            pass

        # Try hex comparison
        try:
            merkle_hex = merkle_root.encode("utf-8").hex()
            hash_hex = uci.hash_bytes.hex()
            if merkle_hex == hash_hex or merkle_root == hash_hex:
                return VerificationResult.verified(
                    UCIScheme.HASH, "Merkle root matches UCI hash (hex)"
                )
        except Exception:
            pass

        return VerificationResult.failed(
            UCIScheme.HASH, f"Merkle root mismatch: {merkle_root} != UCI hash"
        )


class UuidVerifier(SchemeVerifier):
    """
    Verifier for uuid: scheme.

    Trust-On-First-Use (TOFU): Accept the first manifest seen for a UUID,
    reject any subsequent manifests with different CIDs.
    """

    def __init__(self, genesis_store: "GenesisStore"):
        """
        Initialize UUID verifier.

        Args:
            genesis_store: Store for genesis records
        """
        self.genesis_store = genesis_store

    async def verify(
        self,
        uci: UCI,
        manifest: "Manifest",
        manifest_cid: str,
        signature: Optional[bytes] = None,
    ) -> VerificationResult:
        """Verify using TOFU (Trust-On-First-Use)."""
        collection_id = uci.raw

        # Check for existing genesis record
        genesis = await self.genesis_store.get_genesis(collection_id)

        if genesis is None:
            # First time seeing this collection - record genesis
            try:
                version = getattr(manifest, "version", 1)
                genesis = await self.genesis_store.record_genesis(
                    collection_id, manifest_cid, version
                )
                return VerificationResult.tofu_accepted(
                    UCIScheme.UUID,
                    manifest_cid,
                    "First-seen manifest recorded as genesis",
                )
            except Exception as e:
                return VerificationResult.failed(UCIScheme.UUID, f"Failed to record genesis: {e}")

        # Check if this is the same manifest
        if genesis.manifest_cid == manifest_cid:
            return VerificationResult.verified(UCIScheme.UUID, "Manifest matches genesis record")

        # Check if this is a known conflict
        if manifest_cid in genesis.conflict_cids:
            return VerificationResult.tofu_conflict(
                UCIScheme.UUID,
                genesis.manifest_cid,
                "Known conflict with genesis manifest",
            )

        # New conflict detected - record it
        try:
            await self.genesis_store.record_conflict(collection_id, manifest_cid)
            return VerificationResult.tofu_conflict(
                UCIScheme.UUID,
                genesis.manifest_cid,
                f"Conflict: different manifest than genesis ({genesis.manifest_cid})",
            )
        except Exception as e:
            logger.error(f"Failed to record conflict: {e}")
            return VerificationResult.tofu_conflict(
                UCIScheme.UUID,
                genesis.manifest_cid,
                f"Conflict detected but failed to record: {e}",
            )


class DnsVerifier(SchemeVerifier):
    """
    Verifier for dns: scheme.

    Fetch manifest from https://{domain}/dcpp-manifest.json and compare.
    """

    def __init__(self, http_timeout: float = 30.0):
        """
        Initialize DNS verifier.

        Args:
            http_timeout: Timeout for HTTP requests in seconds
        """
        self.http_timeout = http_timeout

    async def verify(
        self,
        uci: UCI,
        manifest: "Manifest",
        manifest_cid: str,
        signature: Optional[bytes] = None,
    ) -> VerificationResult:
        """Verify by fetching manifest from DNS-specified URL."""
        url = uci.dns_manifest_url
        if url is None:
            return VerificationResult.failed(UCIScheme.DNS, "DNS domain not parsed from UCI")

        try:
            import aiohttp  # type: ignore[import-not-found]

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.http_timeout) as response:
                    if response.status != 200:
                        return VerificationResult.failed(
                            UCIScheme.DNS,
                            f"HTTP {response.status} fetching {url}",
                        )

                    # Parse the fetched manifest
                    content = await response.json()

                    # Compare key fields
                    if content.get("collection_id") != manifest.collection_id:
                        return VerificationResult.failed(
                            UCIScheme.DNS, "Collection ID mismatch with DNS manifest"
                        )

                    # Check merkle_root if present
                    fetched_root = content.get("merkle_root")
                    if fetched_root and fetched_root != manifest.merkle_root:
                        return VerificationResult.failed(
                            UCIScheme.DNS,
                            f"Merkle root mismatch: DNS has {fetched_root}",
                        )

                    return VerificationResult.verified(
                        UCIScheme.DNS, f"Manifest verified against {url}"
                    )

        except ImportError:
            return VerificationResult.failed(
                UCIScheme.DNS, "aiohttp not available for DNS verification"
            )
        except Exception as e:
            return VerificationResult.failed(UCIScheme.DNS, f"DNS fetch failed: {e}")


class ChainVerifier(SchemeVerifier):
    """
    Verifier for chain: scheme.

    Stub implementation - actual blockchain verification requires external adapters.

    Enable with DCPP_VERIFY_CHAIN=1 environment variable (when implemented).
    Currently always returns "skipped" status.
    """

    async def verify(
        self,
        uci: UCI,
        manifest: "Manifest",
        manifest_cid: str,
        signature: Optional[bytes] = None,
    ) -> VerificationResult:
        """
        Verify against blockchain state.

        Behavior depends on DCPP_VERIFY_CHAIN environment variable:
        - "0" (default): Returns "skipped" status (safe for testing)
        - "1": Attempts actual verification (requires chain adapters)

        This is currently a stub - actual implementation requires:
        - Ethereum: ENS resolution + contract state verification
        - Other chains: Chain-specific adapters
        """
        chain_id = uci.chain_id or "unknown"
        network = uci.network or "unknown"

        if not is_chain_verification_enabled():
            logger.debug(
                f"Chain verification disabled (DCPP_VERIFY_CHAIN=0). "
                f"Skipping verification for {chain_id}:{network}"
            )
            return VerificationResult.skipped(
                UCIScheme.CHAIN,
                f"Chain verification disabled (set DCPP_VERIFY_CHAIN=1 to enable). "
                f"Chain: {chain_id}:{network}",
            )

        # Chain verification enabled but not implemented - log at ERROR level
        # to make it clear this is a compliance gap, not a normal skip
        logger.error(
            f"CHAIN VERIFICATION NOT IMPLEMENTED: DCPP_VERIFY_CHAIN=1 is set but "
            f"no adapter exists for {chain_id}:{network}. "
            f"RFC Section 8.5 requires chain: scheme verification. "
            f"Returning SKIPPED - manifests will NOT be verified against chain state. "
            f"Install chain-specific adapters to enable verification."
        )
        return VerificationResult.skipped(
            UCIScheme.CHAIN,
            f"Chain verification not implemented for {chain_id}:{network}. "
            f"DCPP_VERIFY_CHAIN=1 is set but adapter missing. "
            f"RFC compliance requires chain-specific adapter (ETH: ENS resolver, etc.).",
        )


class ManifestVerificationPipeline:
    """
    Main verification pipeline that routes to scheme-specific verifiers.

    Usage:
        pipeline = ManifestVerificationPipeline(genesis_store)
        result = await pipeline.verify(collection_id, manifest, manifest_cid)
    """

    def __init__(
        self,
        genesis_store: Optional["GenesisStore"] = None,
        uci_config: Optional[UCIConfig] = None,
        http_timeout: float = 30.0,
    ):
        """
        Initialize the verification pipeline.

        Args:
            genesis_store: Store for genesis records (required for uuid: scheme)
            uci_config: Configuration for UCI parsing
            http_timeout: Timeout for HTTP requests (dns: scheme)
        """
        self.genesis_store = genesis_store
        self.uci_config = uci_config or UCIConfig()
        self.http_timeout = http_timeout

        # Initialize verifiers
        self._key_verifier = KeyVerifier()
        self._hash_verifier = HashVerifier()
        self._dns_verifier = DnsVerifier(http_timeout)
        self._chain_verifier = ChainVerifier()
        self._uuid_verifier: Optional[UuidVerifier] = None

        if genesis_store is not None:
            self._uuid_verifier = UuidVerifier(genesis_store)

    def _get_verifier(self, scheme: UCIScheme) -> Optional[SchemeVerifier]:
        """Get the appropriate verifier for a scheme."""
        if scheme == UCIScheme.KEY:
            return self._key_verifier
        elif scheme == UCIScheme.HASH:
            return self._hash_verifier
        elif scheme == UCIScheme.UUID:
            return self._uuid_verifier
        elif scheme == UCIScheme.DNS:
            return self._dns_verifier
        elif scheme == UCIScheme.CHAIN:
            return self._chain_verifier
        return None

    async def verify(
        self,
        collection_id: str,
        manifest: "Manifest",
        manifest_cid: str,
        signature: Optional[bytes] = None,
    ) -> VerificationResult:
        """
        Verify a manifest against its collection ID's UCI scheme.

        Args:
            collection_id: The collection identifier (UCI format)
            manifest: The manifest to verify
            manifest_cid: CID of the manifest
            signature: Optional signature for key: scheme

        Returns:
            VerificationResult indicating success or failure
        """
        # Parse UCI
        try:
            uci = parse_uci(collection_id, self.uci_config)
        except Exception as e:
            return VerificationResult.failed(UCIScheme.UNKNOWN, f"Failed to parse UCI: {e}")

        # Get verifier for scheme
        verifier = self._get_verifier(uci.scheme)

        if verifier is None:
            if uci.scheme == UCIScheme.UUID and self._uuid_verifier is None:
                return VerificationResult.failed(
                    UCIScheme.UUID, "Genesis store required for UUID verification"
                )
            return VerificationResult.skipped(
                uci.scheme, f"No verifier available for scheme: {uci.scheme.value}"
            )

        # Run verification
        try:
            result = await verifier.verify(uci, manifest, manifest_cid, signature)
            logger.debug(
                f"Verification for {collection_id}: {result.status.value} - {result.message}"
            )
            return result
        except Exception as e:
            logger.error(f"Verification error for {collection_id}: {e}")
            return VerificationResult.failed(uci.scheme, f"Verification error: {e}")

    async def verify_signature_only(
        self,
        collection_id: str,
        data: bytes | dict[str, object],
        signature: bytes,
    ) -> VerificationResult:
        """
        Verify only the signature for a key: scheme UCI.

        This is useful for verifying signed messages without the full manifest.

        Args:
            collection_id: The collection identifier (must be key: scheme)
            data: The data that was signed
            signature: The signature to verify

        Returns:
            VerificationResult indicating success or failure
        """
        try:
            uci = parse_uci(collection_id, self.uci_config)
        except Exception as e:
            return VerificationResult.failed(UCIScheme.UNKNOWN, f"Failed to parse UCI: {e}")

        if uci.scheme != UCIScheme.KEY:
            return VerificationResult.failed(
                uci.scheme, "Signature verification only supported for key: scheme"
            )

        if uci.pubkey_bytes is None:
            return VerificationResult.failed(UCIScheme.KEY, "Public key not parsed from UCI")

        try:
            from dcpp_python.crypto.signing import verify_signature

            algorithm = uci.algorithm or "ed25519"
            if algorithm == "ed25519":
                public_key = VerifyKey(uci.pubkey_bytes)
                if isinstance(data, (bytes, bytearray)):
                    try:
                        data_dict = cbor2.loads(data)
                    except Exception as e:
                        return VerificationResult.failed(
                            UCIScheme.KEY, f"Invalid CBOR payload for signature check: {e}"
                        )
                else:
                    data_dict = data

                is_valid = verify_signature(data_dict, signature, public_key)
                if is_valid:
                    return VerificationResult.verified(UCIScheme.KEY, "Signature verified")
                else:
                    return VerificationResult.failed(UCIScheme.KEY, "Signature verification failed")
            else:
                return VerificationResult.failed(
                    UCIScheme.KEY, f"Unsupported algorithm: {algorithm}"
                )
        except Exception as e:
            return VerificationResult.failed(UCIScheme.KEY, f"Signature verification error: {e}")
