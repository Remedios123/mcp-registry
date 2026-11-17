"""The UC bridge only vends to an approved target for the verified employee."""

import json
from unittest.mock import AsyncMock

import httpx
import pytest


@pytest.fixture
def enterprise_config(monkeypatch):
    monkeypatch.setenv("ENTERPRISE_CREDENTIAL_PROFILES", json.dumps([
        {"id": "uc", "label": "UC", "issuer": "uc", "upstreams": ["https://hr.example.test/mcp"]},
    ]))
    monkeypatch.setenv("ENTERPRISE_CREDENTIAL_SHIM_URL", "http://127.0.0.1:8085")
    monkeypatch.setenv("ENTERPRISE_CREDENTIAL_SHIM_PUBLIC_URL", "https://consent.example.test")
    monkeypatch.setenv("SHIM_INTERNAL_TOKEN", "TEST_" + "x" * 40)


@pytest.mark.asyncio
async def test_enterprise_lookup_does_not_read_credentials_for_another_target(
    enterprise_config, monkeypatch,
):
    from registry.egress_auth import enterprise

    request = AsyncMock()
    monkeypatch.setattr(enterprise, "shared_guarded_async_client", lambda **_: request)
    with pytest.raises(enterprise.EnterpriseCredentialDenied):
        await enterprise.vend("enterprise/uc", "EMP01", "https://other.example.test/mcp")
    request.get.assert_not_awaited()


@pytest.mark.asyncio
async def test_enterprise_lookup_returns_only_the_requested_employees_token(
    enterprise_config, monkeypatch,
):
    from registry.egress_auth import enterprise

    reply = httpx.Response(200, json={"account": "EMP01", "profile": "uc", "token": "fixture-uc-token"})
    request = AsyncMock()
    request.get.return_value = reply
    monkeypatch.setattr(enterprise, "shared_guarded_async_client", lambda **_: request)
    result = await enterprise.vend("enterprise/uc", "EMP01", "https://hr.example.test/mcp")
    assert result.token == "fixture-uc-token"
    assert request.get.await_args.args == ("http://127.0.0.1:8085/internal/business-token/EMP01",)


@pytest.mark.asyncio
async def test_missing_credentials_yield_only_a_link_on_the_configured_origin(
    enterprise_config, monkeypatch,
):
    from registry.egress_auth import enterprise

    request = AsyncMock()
    monkeypatch.setattr(enterprise, "shared_guarded_async_client", lambda **_: request)
    request.get.return_value = httpx.Response(404, json={
        "account": "EMP01", "profile": "uc",
        "authorization_url": "https://consent.example.test/renew?intent=opaque-fixture",
    })
    result = await enterprise.vend("enterprise/uc", "EMP01", "https://hr.example.test/mcp")
    assert result.authorization_url == "https://consent.example.test/renew?intent=opaque-fixture"
    assert result.token is None

    request.get.return_value = httpx.Response(404, json={
        "account": "EMP01", "profile": "uc",
        "authorization_url": "https://other.example.test/renew?intent=opaque-fixture",
    })
    with pytest.raises(enterprise.EnterpriseCredentialUnavailable):
        await enterprise.vend("enterprise/uc", "EMP01", "https://hr.example.test/mcp")


@pytest.mark.asyncio
async def test_second_profile_is_isolated_from_working_uc(enterprise_config, monkeypatch):
    from registry.egress_auth import enterprise

    hr = "https://hr.example.test/mcp"
    cd = "https://cd.example.test/mcp"
    monkeypatch.setenv("ENTERPRISE_CREDENTIAL_PROFILES", json.dumps([
        {"id": "uc", "label": "UC", "issuer": "uc", "upstreams": [hr]},
        {"id": "cd", "label": "CD Mock", "issuer": "cd", "upstreams": [cd]},
    ]))
    replies = {
        "uc": httpx.Response(200, json={"account": "EMP01", "profile": "uc", "token": "uc-fixture"}),
        "cd": httpx.Response(200, json={"account": "EMP01", "profile": "cd", "token": "cd-fixture"}),
    }

    async def reply(url, *, params, **kwargs):
        assert url.endswith("/EMP01")
        return replies[params["profile"]]

    adapter = AsyncMock()
    adapter.get.side_effect = reply
    monkeypatch.setattr(enterprise, "shared_guarded_async_client", lambda **_: adapter)

    assert (await enterprise.vend("enterprise/uc", "EMP01", hr)).token == "uc-fixture"
    assert (await enterprise.vend("enterprise/cd", "EMP01", cd)).token == "cd-fixture"

    replies["cd"] = replies["uc"]
    with pytest.raises(enterprise.EnterpriseCredentialUnavailable):
        await enterprise.vend("enterprise/cd", "EMP01", cd)

    renewal = "https://consent.example.test/renew?intent=cd-fixture"
    replies["cd"] = httpx.Response(404, json={
        "account": "EMP01", "profile": "cd", "authorization_url": renewal,
    })
    missing = await enterprise.vend("enterprise/cd", "EMP01", cd)
    assert missing.token is None and missing.authorization_url == renewal
    assert (await enterprise.vend("enterprise/uc", "EMP01", hr)).token == "uc-fixture"
