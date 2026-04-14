import asyncio
import builtins

import pytest

from dcpp_python import bootstrap_discovery as bd


@pytest.mark.asyncio
async def test_discover_via_dns_txt_falls_back_when_dnspython_missing(monkeypatch):
    async def fake_fallback(domain: str, timeout: float):
        return ["/ip4/1.2.3.4/tcp/4001"]

    monkeypatch.setattr(bd, "_discover_dns_txt_fallback", fake_fallback)

    original_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name.startswith("dns"):
            raise ImportError("forced")
        return original_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    result = await bd.discover_via_dns_txt(domain="example.com", timeout=0.1)

    assert result == ["/ip4/1.2.3.4/tcp/4001"]


@pytest.mark.asyncio
async def test_discover_via_ipns_falls_back_when_ipfs_missing(monkeypatch):
    async def fake_gateway(ipns_name: str, timeout: float):
        return ["/ip4/5.6.7.8/tcp/4001"]

    async def fake_create_subprocess_exec(*args, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr(bd, "_discover_ipns_via_gateway", fake_gateway)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = await bd.discover_via_ipns(ipns_name="/ipns/test", timeout=0.1)

    assert result == ["/ip4/5.6.7.8/tcp/4001"]
