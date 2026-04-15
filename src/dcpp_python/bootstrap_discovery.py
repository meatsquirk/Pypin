"""Compatibility shim for dcpp_python.network.dht.bootstrap_discovery."""

from __future__ import annotations

from dcpp_python.network.dht import bootstrap_discovery as _impl

DNS_BOOTSTRAP_DOMAIN = _impl.DNS_BOOTSTRAP_DOMAIN
IPNS_BOOTSTRAP_NAME = _impl.IPNS_BOOTSTRAP_NAME
DISCOVERY_TIMEOUT = _impl.DISCOVERY_TIMEOUT


def _sync_impl(name: str) -> None:
    """Keep shim-overridden helpers in sync with the implementation module."""
    setattr(_impl, name, globals()[name])


async def discover_bootstrap_peers(
    enable_dns: bool = True,
    enable_ipns: bool = True,
    dns_domain: str = DNS_BOOTSTRAP_DOMAIN,
    ipns_name: str = IPNS_BOOTSTRAP_NAME,
) -> list[str]:
    return await _impl.discover_bootstrap_peers(
        enable_dns=enable_dns,
        enable_ipns=enable_ipns,
        dns_domain=dns_domain,
        ipns_name=ipns_name,
    )


async def discover_via_dns_txt(
    domain: str = DNS_BOOTSTRAP_DOMAIN,
    timeout: float = DISCOVERY_TIMEOUT,
) -> list[str]:
    _sync_impl("_discover_dns_txt_fallback")
    return await _impl.discover_via_dns_txt(domain=domain, timeout=timeout)


async def discover_via_ipns(
    ipns_name: str = IPNS_BOOTSTRAP_NAME,
    timeout: float = DISCOVERY_TIMEOUT,
) -> list[str]:
    _sync_impl("_discover_ipns_via_gateway")
    return await _impl.discover_via_ipns(ipns_name=ipns_name, timeout=timeout)


async def _discover_dns_txt_fallback(domain: str, timeout: float) -> list[str]:
    return await _impl._discover_dns_txt_fallback(domain, timeout)


async def _discover_ipns_via_gateway(ipns_name: str, timeout: float) -> list[str]:
    return await _impl._discover_ipns_via_gateway(ipns_name, timeout)


def _parse_txt_multiaddr(txt: str) -> str | None:
    return _impl._parse_txt_multiaddr(txt)


def _parse_bootstrap_content(content: str) -> list[str]:
    return _impl._parse_bootstrap_content(content)


__all__ = [
    "DNS_BOOTSTRAP_DOMAIN",
    "IPNS_BOOTSTRAP_NAME",
    "DISCOVERY_TIMEOUT",
    "discover_bootstrap_peers",
    "discover_via_dns_txt",
    "discover_via_ipns",
    "_discover_dns_txt_fallback",
    "_discover_ipns_via_gateway",
    "_parse_txt_multiaddr",
    "_parse_bootstrap_content",
]
