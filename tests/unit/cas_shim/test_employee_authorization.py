"""CAS reauthorization stays bound to the employee that requested it."""

import asyncio
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import app as shim


def test_callback_for_another_account_cannot_write_a_uc_token(monkeypatch):
    link = shim._authorization_url("EMP001", "uc")
    intent = parse_qs(urlsplit(link).query)["intent"][0]
    monkeypatch.setattr(shim, "_exchange_st", lambda ticket: {"account": "EMP002", "token": "fixture"})

    def unexpected_write(*args, **kwargs):
        raise AssertionError("a different employee's token must never be saved")

    monkeypatch.setattr(shim, "_store_business_token", unexpected_write)
    response = shim._finish_renew(intent, "fixture-service-ticket")
    assert "员工账号不匹配" in response.body.decode()


def test_oidc_rejects_an_unregistered_redirect_uri():
    request = SimpleNamespace(query_params={
        "client_id": shim.SHIM_CLIENT_ID,
        "redirect_uri": "https://unregistered.example.test/callback",
    })
    response = asyncio.run(shim.authorize(request))
    assert response.status_code == 400


def test_no_email_or_display_name_fallback_for_the_employee_id():
    assert shim._verified_account({"username": "EMP001"}) is None


def test_database_record_seals_the_token_to_its_employee(fake_vault):
    shim.vault_put("EMP001", "Employee", "test-user", "fixture-uc-token", 1000000)
    stored = fake_vault.docs["EMP001"]
    assert "fixture-uc-token" not in stored["token"]
    assert shim.vault_get("EMP001")["token"] == "fixture-uc-token"
    fake_vault.docs["EMP002"] = {**stored, "account": "EMP002"}
    assert shim.vault_get("EMP002") is None


def test_cas_callback_does_not_log_the_service_ticket(caplog):
    request = SimpleNamespace(
        query_params={"ticket": "ST-sensitive-fixture"}, cookies={"unrelated": "value"}, headers={},
    )
    with caplog.at_level("INFO", logger="uvicorn.error"):
        asyncio.run(shim.cas_callback(request))
    assert "ST-sensitive-fixture" not in caplog.text


def test_insecure_uc_exchange_is_rejected_before_network(monkeypatch):
    import pytest

    monkeypatch.setattr(shim, "MOCK_MODE", False)
    monkeypatch.setattr(shim, "UC_AUTH_URL", "http://uc.example.test/exchange")

    def unexpected_request(*args, **kwargs):
        raise AssertionError("an unverified endpoint cannot receive a service ticket")

    monkeypatch.setattr(shim.httpx, "get", unexpected_request)
    with pytest.raises(ValueError, match="require HTTPS"):
        shim._exchange_st("ST-fixture")


def test_whitelist_will_not_link_an_existing_local_account():
    import runpy
    from pathlib import Path

    import pytest

    script = Path(__file__).resolve().parents[3] / "keycloak" / "setup" / "configure-cas.py"
    bind = runpy.run_path(str(script))["bind_employee"]

    def admin_api(method, endpoint, payload=None):
        assert method == "GET", "a local user without a protected employee ID cannot be linked"
        if endpoint.startswith("/users?"):
            return [{"id": "local-user", "username": "emp001"}]
        if endpoint.endswith("/federated-identity"):
            return []
        assert endpoint == "/users/local-user"
        return {"email": "admin@example.test", "attributes": {}}

    with pytest.raises(ValueError, match="matching protected employee ID"):
        bind(SimpleNamespace(call=admin_api), "EMP001", "Example employee")
