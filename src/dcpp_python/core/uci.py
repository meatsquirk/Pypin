"""
UCI (Universal Collection Identifier) parsing and validation.

Implements RFC Section 4.3: Collection Identifier Format
UCIs follow the format: {scheme}:{value}

Supported schemes:
- chain:{chain_id}:{contract} - Verify against blockchain state
- key:{algorithm}:{pubkey} - Manifest MUST be signed by the specified key
- hash:{algorithm}:{hash} - Manifest merkle_root MUST equal the hash
- uuid:{uuid} - Trust-on-first-use (TOFU)
- dns:{domain} - Fetch from https://{domain}/dcpp-manifest.json
"""

from __future__ import annotations

import re
import uuid as uuid_lib
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class UCIScheme(Enum):
    """UCI scheme types per RFC Section 4.3."""

    CHAIN = "chain"  # Verify against chain state
    KEY = "key"  # Manifest MUST be signed by key
    HASH = "hash"  # Manifest root MUST equal hash
    UUID = "uuid"  # Trust-on-first-use (TOFU)
    DNS = "dns"  # Fetch from https://{domain}/dcpp-manifest.json
    UNKNOWN = "unknown"  # Unrecognized scheme


class UCIError(Exception):
    """Base exception for UCI parsing errors."""

    pass


class InvalidUCIError(UCIError):
    """Raised when UCI format is invalid (error code 0x0100)."""

    ERROR_CODE = 0x0100

    def __init__(self, message: str, raw: str = ""):
        super().__init__(message)
        self.raw = raw


class UnknownUCISchemeError(UCIError):
    """Raised when UCI scheme is unrecognized (error code 0x0101)."""

    ERROR_CODE = 0x0101

    def __init__(self, scheme: str, raw: str = ""):
        super().__init__(f"Unknown UCI scheme: {scheme}")
        self.scheme = scheme
        self.raw = raw


# Supported algorithms per scheme
SUPPORTED_KEY_ALGORITHMS = {"ed25519", "secp256k1"}
SUPPORTED_HASH_ALGORITHMS = {"sha256", "sha3-256", "blake3"}
SUPPORTED_CHAIN_IDS = {"eth", "polygon", "arbitrum", "optimism", "base", "solana"}

# Base58 alphabet for key decoding
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Regex patterns
# DNS domain: standard domain name pattern
DNS_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
# UUID: standard UUID format
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
# Ethereum address: 0x followed by 40 hex chars
ETH_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
# Solana address: Base58 string, typically 32-44 characters
SOLANA_ADDRESS_PATTERN = re.compile(r"^[" + BASE58_ALPHABET + r"]{32,44}$")


@dataclass
class UCI:
    """
    Parsed Universal Collection Identifier.

    Attributes:
        scheme: The UCI scheme (chain, key, hash, uuid, dns, unknown)
        value: The scheme-specific value (everything after scheme:)
        raw: The original unparsed UCI string

        # Scheme-specific parsed components
        chain_id: For chain: scheme - the blockchain identifier
        network: For chain: scheme - mainnet, testnet, etc.
        contract: For chain: scheme - the contract address
        algorithm: For key/hash: scheme - the algorithm name
        pubkey_bytes: For key: scheme - decoded public key bytes
        hash_bytes: For hash: scheme - decoded hash bytes
        domain: For dns: scheme - the domain name
        uuid_value: For uuid: scheme - the parsed UUID
    """

    scheme: UCIScheme
    value: str
    raw: str

    # Chain scheme components
    chain_id: Optional[str] = None
    network: Optional[str] = None
    contract: Optional[str] = None

    # Key/Hash scheme components
    algorithm: Optional[str] = None
    pubkey_bytes: Optional[bytes] = None
    hash_bytes: Optional[bytes] = None

    # DNS scheme components
    domain: Optional[str] = None

    # UUID scheme components
    uuid_value: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate that the UCI was properly constructed."""
        if not self.raw:
            raise InvalidUCIError("UCI cannot be empty")

    @property
    def is_verifiable(self) -> bool:
        """Return True if this UCI scheme can be verified."""
        return self.scheme in {
            UCIScheme.KEY,
            UCIScheme.HASH,
            UCIScheme.UUID,
            UCIScheme.DNS,
        }

    @property
    def requires_signature(self) -> bool:
        """Return True if this UCI scheme requires a signature."""
        return self.scheme == UCIScheme.KEY

    @property
    def is_tofu(self) -> bool:
        """Return True if this UCI uses trust-on-first-use."""
        return self.scheme == UCIScheme.UUID

    @property
    def dns_manifest_url(self) -> Optional[str]:
        """Return the manifest URL for DNS scheme, None for others."""
        if self.scheme == UCIScheme.DNS and self.domain:
            return f"https://{self.domain}/dcpp-manifest.json"
        return None


@dataclass
class UCIConfig:
    """Configuration for UCI parsing and validation."""

    # Allowed schemes (empty = all schemes allowed)
    allowed_schemes: set[UCIScheme] = field(default_factory=set)

    # Whether to reject unknown schemes (vs. parsing as UNKNOWN)
    strict_scheme: bool = False

    # Supported key algorithms
    key_algorithms: set[str] = field(default_factory=lambda: SUPPORTED_KEY_ALGORITHMS.copy())

    # Supported hash algorithms
    hash_algorithms: set[str] = field(default_factory=lambda: SUPPORTED_HASH_ALGORITHMS.copy())

    # Supported chain IDs
    chain_ids: set[str] = field(default_factory=lambda: SUPPORTED_CHAIN_IDS.copy())


def _base58_decode(encoded: str) -> bytes:
    """Decode a Base58 encoded string to bytes."""
    num = 0
    for char in encoded:
        if char not in BASE58_ALPHABET:
            raise InvalidUCIError(f"Invalid Base58 character: {char}")
        num = num * 58 + BASE58_ALPHABET.index(char)

    # Convert to bytes
    result = []
    while num > 0:
        result.append(num % 256)
        num //= 256
    result.reverse()

    # Handle leading zeros
    leading_zeros = 0
    for char in encoded:
        if char == "1":
            leading_zeros += 1
        else:
            break

    return bytes([0] * leading_zeros + result)


def _hex_decode(encoded: str) -> bytes:
    """Decode a hex encoded string to bytes."""
    # Remove 0x prefix if present
    if encoded.startswith("0x") or encoded.startswith("0X"):
        encoded = encoded[2:]
    try:
        return bytes.fromhex(encoded)
    except ValueError as e:
        raise InvalidUCIError(f"Invalid hex encoding: {e}")


def _base32_decode(encoded: str) -> bytes:
    """Decode a base32 encoded string (lowercase, no padding) to bytes."""
    import base64

    # Convert to uppercase and add padding
    encoded_upper = encoded.upper()
    padding = (8 - len(encoded_upper) % 8) % 8
    encoded_padded = encoded_upper + "=" * padding
    try:
        return base64.b32decode(encoded_padded)
    except Exception as e:
        raise InvalidUCIError(f"Invalid base32 encoding: {e}")


def parse_chain_value(value: str, config: UCIConfig) -> tuple[str, str, str]:
    """
    Parse a chain: scheme value.

    Format: {chain_id}:{network}:{contract}
    Example: eth:mainnet:0x1234...

    Returns: (chain_id, network, contract)
    """
    parts = value.split(":", 2)
    if len(parts) < 3:
        raise InvalidUCIError(
            f"chain: scheme requires format chain_id:network:contract, got: {value}"
        )

    chain_id, network, contract = parts

    # Validate chain ID
    if config.chain_ids and chain_id.lower() not in {c.lower() for c in config.chain_ids}:
        raise InvalidUCIError(f"Unsupported chain ID: {chain_id}")

    # Validate contract address format based on chain
    chain_lower = chain_id.lower()
    if chain_lower in {"eth", "polygon", "arbitrum", "optimism", "base"}:
        if not ETH_ADDRESS_PATTERN.match(contract):
            raise InvalidUCIError(f"Invalid Ethereum-style address: {contract}")
    elif chain_lower == "solana":
        if not SOLANA_ADDRESS_PATTERN.match(contract):
            raise InvalidUCIError(f"Invalid Solana address: {contract}")

    return chain_id.lower(), network.lower(), contract


def parse_key_value(value: str, config: UCIConfig) -> tuple[str, bytes]:
    """
    Parse a key: scheme value.

    Format: {algorithm}:{pubkey}
    Example: ed25519:5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY

    The pubkey can be:
    - Base58 encoded (default for ed25519)
    - Hex encoded (with 0x prefix)

    Returns: (algorithm, pubkey_bytes)
    """
    parts = value.split(":", 1)
    if len(parts) < 2:
        raise InvalidUCIError(f"key: scheme requires format algorithm:pubkey, got: {value}")

    algorithm, pubkey_encoded = parts
    algorithm = algorithm.lower()

    # Validate algorithm
    if config.key_algorithms and algorithm not in config.key_algorithms:
        raise InvalidUCIError(f"Unsupported key algorithm: {algorithm}")

    # Decode public key
    if pubkey_encoded.startswith("0x"):
        pubkey_bytes = _hex_decode(pubkey_encoded)
    else:
        # Assume Base58
        pubkey_bytes = _base58_decode(pubkey_encoded)

    # Validate key length
    if algorithm == "ed25519" and len(pubkey_bytes) != 32:
        raise InvalidUCIError(f"ed25519 public key must be 32 bytes, got {len(pubkey_bytes)}")
    elif algorithm == "secp256k1" and len(pubkey_bytes) not in (33, 65):
        raise InvalidUCIError(
            f"secp256k1 public key must be 33 or 65 bytes, got {len(pubkey_bytes)}"
        )

    return algorithm, pubkey_bytes


def parse_hash_value(value: str, config: UCIConfig) -> tuple[str, bytes]:
    """
    Parse a hash: scheme value.

    Format: {algorithm}:{hash}
    Example: sha256:bafy...

    The hash can be:
    - CID format (bafybeig...)
    - Hex encoded (with or without 0x prefix)
    - Base32 lowercase

    Returns: (algorithm, hash_bytes)
    """
    parts = value.split(":", 1)
    if len(parts) < 2:
        raise InvalidUCIError(f"hash: scheme requires format algorithm:hash, got: {value}")

    algorithm, hash_encoded = parts
    algorithm = algorithm.lower()

    # Validate algorithm
    if config.hash_algorithms and algorithm not in config.hash_algorithms:
        raise InvalidUCIError(f"Unsupported hash algorithm: {algorithm}")

    # Decode hash
    if hash_encoded.startswith("0x"):
        hash_bytes = _hex_decode(hash_encoded)
    elif hash_encoded.startswith("bafy") or hash_encoded.startswith("bafk"):
        # CID format - extract the hash portion
        # CIDv1: version (1 byte) + codec (varint) + multihash
        # For now, accept as-is and let verification handle it
        hash_bytes = hash_encoded.encode("utf-8")
    elif all(c in "0123456789abcdefABCDEF" for c in hash_encoded):
        # Plain hex
        hash_bytes = _hex_decode(hash_encoded)
    else:
        # Assume base32 lowercase
        hash_bytes = _base32_decode(hash_encoded)

    return algorithm, hash_bytes


def parse_uuid_value(value: str) -> str:
    """
    Parse a uuid: scheme value.

    Format: {uuid}
    Example: 123e4567-e89b-12d3-a456-426614174000

    Returns: normalized UUID string (lowercase with dashes)
    """
    # Normalize: remove any existing dashes, convert to lowercase
    normalized = value.lower().replace("-", "")

    if len(normalized) != 32:
        raise InvalidUCIError(f"UUID must be 32 hex characters, got: {value}")

    if not all(c in "0123456789abcdef" for c in normalized):
        raise InvalidUCIError(f"UUID must contain only hex characters: {value}")

    # Validate as UUID
    try:
        parsed = uuid_lib.UUID(normalized)
        return str(parsed)
    except ValueError as e:
        raise InvalidUCIError(f"Invalid UUID format: {e}")


def parse_dns_value(value: str) -> str:
    """
    Parse a dns: scheme value.

    Format: {domain}
    Example: archive.org

    Returns: normalized domain (lowercase)
    """
    domain = value.lower().strip()

    if not domain:
        raise InvalidUCIError("DNS domain cannot be empty")

    if not DNS_PATTERN.match(domain):
        raise InvalidUCIError(f"Invalid DNS domain: {domain}")

    return domain


def validate_uci_scheme(scheme: str, config: UCIConfig) -> UCIScheme:
    """
    Validate and convert a scheme string to UCIScheme enum.

    Args:
        scheme: The scheme string to validate
        config: UCI configuration

    Returns:
        UCIScheme enum value

    Raises:
        UnknownUCISchemeError: If scheme is unknown and strict mode is enabled
    """
    scheme_lower = scheme.lower()

    # Map to enum
    scheme_map = {
        "chain": UCIScheme.CHAIN,
        "key": UCIScheme.KEY,
        "hash": UCIScheme.HASH,
        "uuid": UCIScheme.UUID,
        "dns": UCIScheme.DNS,
    }

    uci_scheme = scheme_map.get(scheme_lower, UCIScheme.UNKNOWN)

    # Check if unknown scheme
    if uci_scheme == UCIScheme.UNKNOWN and config.strict_scheme:
        raise UnknownUCISchemeError(scheme)

    # Check if scheme is allowed
    if config.allowed_schemes and uci_scheme not in config.allowed_schemes:
        if uci_scheme != UCIScheme.UNKNOWN:
            raise UnknownUCISchemeError(scheme, f"Scheme {scheme} is not in allowed list")

    return uci_scheme


def parse_uci(collection_id: str, config: Optional[UCIConfig] = None) -> UCI:
    """
    Parse a Universal Collection Identifier string.

    Args:
        collection_id: The UCI string to parse (format: scheme:value)
        config: Optional configuration for parsing

    Returns:
        Parsed UCI object

    Raises:
        InvalidUCIError: If the UCI format is invalid (0x0100)
        UnknownUCISchemeError: If the scheme is unknown in strict mode (0x0101)
    """
    if config is None:
        config = UCIConfig()

    if not collection_id:
        raise InvalidUCIError("Collection ID cannot be empty", collection_id)

    # Split scheme and value
    parts = collection_id.split(":", 1)
    if len(parts) < 2:
        raise InvalidUCIError(
            f"UCI must contain scheme:value format, got: {collection_id}",
            collection_id,
        )

    scheme_str, value = parts

    if not scheme_str:
        raise InvalidUCIError("UCI scheme cannot be empty", collection_id)

    if not value:
        raise InvalidUCIError("UCI value cannot be empty", collection_id)

    # Validate and get scheme
    scheme = validate_uci_scheme(scheme_str, config)

    # Create base UCI
    uci = UCI(
        scheme=scheme,
        value=value,
        raw=collection_id,
    )

    # Parse scheme-specific components
    if scheme == UCIScheme.CHAIN:
        chain_id, network, contract = parse_chain_value(value, config)
        uci.chain_id = chain_id
        uci.network = network
        uci.contract = contract

    elif scheme == UCIScheme.KEY:
        algorithm, pubkey_bytes = parse_key_value(value, config)
        uci.algorithm = algorithm
        uci.pubkey_bytes = pubkey_bytes

    elif scheme == UCIScheme.HASH:
        algorithm, hash_bytes = parse_hash_value(value, config)
        uci.algorithm = algorithm
        uci.hash_bytes = hash_bytes

    elif scheme == UCIScheme.UUID:
        uuid_value = parse_uuid_value(value)
        uci.uuid_value = uuid_value

    elif scheme == UCIScheme.DNS:
        domain = parse_dns_value(value)
        uci.domain = domain

    return uci


def derive_storage_path(uci: UCI) -> str:
    """
    Derive a filesystem-safe storage path from a UCI.

    Replaces colons and slashes with underscores, similar to
    existing storage.py behavior.

    Args:
        uci: Parsed UCI object

    Returns:
        Filesystem-safe path string
    """
    # Replace special characters
    path = uci.raw.replace(":", "_").replace("/", "_")
    return path


def format_uci(scheme: UCIScheme, **kwargs: str) -> str:
    """
    Format a UCI string from components.

    Args:
        scheme: The UCI scheme
        **kwargs: Scheme-specific components

    Returns:
        Formatted UCI string

    Examples:
        format_uci(UCIScheme.KEY, algorithm="ed25519", pubkey="...")
        format_uci(UCIScheme.UUID, uuid="123e4567-...")
        format_uci(UCIScheme.DNS, domain="archive.org")
    """
    if scheme == UCIScheme.CHAIN:
        chain_id = kwargs.get("chain_id", "")
        network = kwargs.get("network", "")
        contract = kwargs.get("contract", "")
        return f"chain:{chain_id}:{network}:{contract}"

    elif scheme == UCIScheme.KEY:
        algorithm = kwargs.get("algorithm", "ed25519")
        pubkey = kwargs.get("pubkey", "")
        return f"key:{algorithm}:{pubkey}"

    elif scheme == UCIScheme.HASH:
        algorithm = kwargs.get("algorithm", "sha256")
        hash_value = kwargs.get("hash", "")
        return f"hash:{algorithm}:{hash_value}"

    elif scheme == UCIScheme.UUID:
        uuid_value = kwargs.get("uuid", "")
        return f"uuid:{uuid_value}"

    elif scheme == UCIScheme.DNS:
        domain = kwargs.get("domain", "")
        return f"dns:{domain}"

    else:
        raise ValueError(f"Cannot format unknown scheme: {scheme}")


# Error codes for use in error messages
UCI_ERROR_CODES = {
    0x0100: "INVALID_UCI",
    0x0101: "UNKNOWN_UCI_SCHEME",
}
