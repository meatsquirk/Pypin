"""
DCPP Bootstrap Discovery

Implements bootstrap peer discovery via DNS TXT and IPNS per RFC Section 9.3.

Bootstrap node addresses are published at (implementations SHOULD check in order):
1. DNS TXT record: _dcpp-bootstrap.dcpp.network
2. IPNS: /ipns/bootstrap.dcpp.network

Implementations MUST NOT hardcode bootstrap node addresses.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, Optional

logger = logging.getLogger("dcpp.discovery")

# Default bootstrap discovery endpoints (RFC Section 9.3)
DNS_BOOTSTRAP_DOMAIN = "_dcpp-bootstrap.dcpp.network"
IPNS_BOOTSTRAP_NAME = "/ipns/bootstrap.dcpp.network"

# Timeout for discovery operations
DISCOVERY_TIMEOUT = 10.0  # seconds


async def discover_bootstrap_peers(
    enable_dns: bool = True,
    enable_ipns: bool = True,
    dns_domain: str = DNS_BOOTSTRAP_DOMAIN,
    ipns_name: str = IPNS_BOOTSTRAP_NAME,
) -> List[str]:
    """
    Discover bootstrap peers via DNS TXT and IPNS (RFC Section 9.3).

    Checks sources in order (if enabled):
    1. DNS TXT record: _dcpp-bootstrap.dcpp.network
    2. IPNS: /ipns/bootstrap.dcpp.network

    Args:
        enable_dns: Whether to try DNS TXT discovery (default: True)
        enable_ipns: Whether to try IPNS discovery (default: True)
        dns_domain: DNS domain for TXT lookup (default: _dcpp-bootstrap.dcpp.network)
        ipns_name: IPNS name to resolve (default: /ipns/bootstrap.dcpp.network)

    Returns:
        List of multiaddr strings for bootstrap peers.
    """
    if not enable_dns and not enable_ipns:
        logger.debug("Bootstrap discovery disabled")
        return []

    peers: List[str] = []

    # Try DNS TXT first (if enabled)
    if enable_dns:
        dns_peers = await discover_via_dns_txt(domain=dns_domain)
        if dns_peers:
            logger.info(f"Found {len(dns_peers)} bootstrap peer(s) via DNS TXT")
            peers.extend(dns_peers)

    # Try IPNS second (if enabled and DNS didn't yield results or for additional peers)
    if enable_ipns and not peers:
        ipns_peers = await discover_via_ipns(ipns_name=ipns_name)
        if ipns_peers:
            logger.info(f"Found {len(ipns_peers)} bootstrap peer(s) via IPNS")
            peers.extend(ipns_peers)

    if not peers and (enable_dns or enable_ipns):
        logger.warning(
            "No bootstrap peers discovered via DNS TXT or IPNS. "
            "Network may be unavailable or use --bootstrap to specify manually."
        )

    return peers


async def discover_via_dns_txt(
    domain: str = DNS_BOOTSTRAP_DOMAIN,
    timeout: float = DISCOVERY_TIMEOUT,
) -> List[str]:
    """
    Discover bootstrap peers via DNS TXT record.

    Args:
        domain: DNS domain to query (default: _dcpp-bootstrap.dcpp.network)
        timeout: Timeout for DNS query in seconds

    Returns:
        List of multiaddr strings parsed from TXT records.
    """
    try:
        import dns.resolver  # type: ignore[import-not-found]
        import dns.exception  # type: ignore[import-not-found]

        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout

        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: resolver.resolve(domain, "TXT"),
            )

            peers = []
            for rdata in answers:
                # TXT records contain quoted strings
                for txt_string in rdata.strings:
                    if isinstance(txt_string, bytes):
                        txt_string = txt_string.decode("utf-8")

                    # Parse multiaddr from TXT record
                    # Format: "addr=/ip4/1.2.3.4/tcp/4001" or just "/ip4/1.2.3.4/tcp/4001"
                    multiaddr = _parse_txt_multiaddr(txt_string)
                    if multiaddr:
                        peers.append(multiaddr)

            return peers

        except dns.resolver.NXDOMAIN:
            logger.debug(f"DNS TXT record not found: {domain}")
            return []
        except dns.resolver.NoAnswer:
            logger.debug(f"DNS TXT record has no answer: {domain}")
            return []
        except dns.exception.Timeout:
            logger.warning(f"DNS TXT query timed out: {domain}")
            return []

    except ImportError:
        logger.debug("dnspython not installed. Install with: pip install dnspython")
        # Fallback to system DNS resolver if dnspython not available
        return await _discover_dns_txt_fallback(domain, timeout)


async def _discover_dns_txt_fallback(domain: str, timeout: float) -> List[str]:
    """Fallback DNS TXT discovery using system dig command."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            "TXT",
            domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning(f"DNS TXT fallback query timed out: {domain}")
            return []

        if proc.returncode != 0:
            return []

        peers = []
        for line in stdout.decode("utf-8").strip().split("\n"):
            # Remove quotes from TXT record
            line = line.strip().strip('"')
            multiaddr = _parse_txt_multiaddr(line)
            if multiaddr:
                peers.append(multiaddr)

        return peers

    except FileNotFoundError:
        logger.debug("dig command not available for DNS fallback")
        return []
    except Exception as e:
        logger.debug(f"DNS TXT fallback failed: {e}")
        return []


def _parse_txt_multiaddr(txt: str) -> Optional[str]:
    """
    Parse a multiaddr from a TXT record value.

    Accepts formats:
    - "/ip4/1.2.3.4/tcp/4001"
    - "addr=/ip4/1.2.3.4/tcp/4001"
    - "/ip4/1.2.3.4/tcp/4001/p2p/QmPeerId"
    """
    txt = txt.strip()

    # Handle "addr=" prefix
    if txt.startswith("addr="):
        txt = txt[5:]

    # Validate it looks like a multiaddr
    if txt.startswith("/ip4/") or txt.startswith("/ip6/") or txt.startswith("/dns"):
        # Basic validation: should have /tcp/ or /udp/
        if "/tcp/" in txt or "/udp/" in txt:
            return txt

    return None


async def discover_via_ipns(
    ipns_name: str = IPNS_BOOTSTRAP_NAME,
    timeout: float = DISCOVERY_TIMEOUT,
) -> List[str]:
    """
    Discover bootstrap peers via IPNS.

    Args:
        ipns_name: IPNS name to resolve (default: /ipns/bootstrap.dcpp.network)
        timeout: Timeout for IPNS resolution in seconds

    Returns:
        List of multiaddr strings from IPNS-resolved content.
    """
    # Try using ipfs command if available
    try:
        proc = await asyncio.create_subprocess_exec(
            "ipfs",
            "name",
            "resolve",
            ipns_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.debug(f"IPNS resolution timed out: {ipns_name}")
            return []

        if proc.returncode != 0:
            logger.debug(f"IPNS resolution failed: {ipns_name}")
            return []

        cid = stdout.decode("utf-8").strip()
        if not cid:
            return []

        # Fetch the content from IPFS
        cat_proc = await asyncio.create_subprocess_exec(
            "ipfs",
            "cat",
            cid,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            content, _ = await asyncio.wait_for(cat_proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            cat_proc.kill()
            await cat_proc.wait()
            logger.debug(f"IPFS cat timed out: {cid}")
            return []

        if cat_proc.returncode != 0:
            return []

        # Parse multiaddrs from content (one per line or JSON)
        return _parse_bootstrap_content(content.decode("utf-8"))

    except FileNotFoundError:
        logger.debug("ipfs command not available for IPNS discovery")
        return await _discover_ipns_via_gateway(ipns_name, timeout)
    except Exception as e:
        logger.debug(f"IPNS discovery failed: {e}")
        return []


async def _discover_ipns_via_gateway(ipns_name: str, timeout: float) -> List[str]:
    """Fallback IPNS discovery via public gateway."""
    try:
        import aiohttp  # type: ignore[import-not-found]

        # Try public IPFS gateways
        gateways = [
            "https://ipfs.io",
            "https://dweb.link",
            "https://cloudflare-ipfs.com",
        ]

        for gateway in gateways:
            url = f"{gateway}{ipns_name}"
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url, timeout=aiohttp.ClientTimeout(total=timeout)
                    ) as response:
                        if response.status == 200:
                            content = await response.text()
                            peers = _parse_bootstrap_content(content)
                            if peers:
                                return peers
            except Exception as e:
                logger.debug(f"Gateway {gateway} failed: {e}")
                continue

        return []

    except ImportError:
        logger.debug("aiohttp not installed for IPNS gateway fallback")
        return []


def _parse_bootstrap_content(content: str) -> List[str]:
    """
    Parse bootstrap peer list from content.

    Accepts formats:
    - One multiaddr per line
    - JSON array of multiaddrs
    - JSON object with "peers" array
    """
    content = content.strip()
    peers = []

    # Try JSON first
    try:
        import json

        data = json.loads(content)

        if isinstance(data, list):
            # JSON array of multiaddrs
            for item in data:
                if isinstance(item, str) and _parse_txt_multiaddr(item):
                    peers.append(item)
                elif isinstance(item, dict) and "addr" in item:
                    addr = item["addr"]
                    if _parse_txt_multiaddr(addr):
                        peers.append(addr)
        elif isinstance(data, dict):
            # JSON object with "peers" or "bootstrap" key
            peer_list = data.get("peers") or data.get("bootstrap") or []
            for item in peer_list:
                if isinstance(item, str) and _parse_txt_multiaddr(item):
                    peers.append(item)
                elif isinstance(item, dict) and "addr" in item:
                    addr = item["addr"]
                    if _parse_txt_multiaddr(addr):
                        peers.append(addr)

        if peers:
            return peers
    except (json.JSONDecodeError, ImportError):
        pass

    # Fallback: parse as line-separated multiaddrs
    for line in content.split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):  # Skip comments
            multiaddr = _parse_txt_multiaddr(line)
            if multiaddr:
                peers.append(multiaddr)

    return peers
