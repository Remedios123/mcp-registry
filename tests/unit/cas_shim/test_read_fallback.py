"""读时兜底: 令牌临近过期时读取即触发续期(批量空档自愈)。"""

import asyncio
import json

from starlette.requests import Request

import app as shim

NOW = 1_800_000_000


def _request(token: str = "test-internal-token") -> Request:
    return Request({"type": "http", "headers": [(b"x-internal-token", token.encode())]})


def _get(account: str):
    return asyncio.run(shim.internal_business_token(account, _request()))


def _seed(coll, account: str, *, expires_at: int, last_used_at: int = NOW - 60):
    coll.docs[account] = {
        "account": account,
        "name": "测试用户",
        "uc_user_id": "u-1",
        "token": f"tok-{account}",
        "expires_at": expires_at,
        "last_used_at": last_used_at,
    }


def _spy_renew(monkeypatch, coll, outcome=True):
    calls = []

    async def fake_renew(account):
        calls.append(account)
        if outcome and account in coll.docs:
            coll.docs[account]["token"] = "refreshed-tok"
            coll.docs[account]["expires_at"] = NOW + 90000
        return outcome

    monkeypatch.setattr(shim, "_renew_account", fake_renew)
    return calls


def test_near_expiry_token_refreshed_on_read(fake_vault, reset_locks, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    _seed(fake_vault, "100001", expires_at=NOW + 7200)
    calls = _spy_renew(monkeypatch, fake_vault)

    resp = _get("100001")

    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["token"] == "refreshed-tok"
    assert body["expired"] is False
    assert fake_vault.docs["100001"]["expires_at"] == NOW + 90000
    assert calls == ["100001"]


def test_far_from_expiry_skips_renewal(fake_vault, reset_locks, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    _seed(fake_vault, "100001", expires_at=NOW + 20 * 3600)
    calls = _spy_renew(monkeypatch, fake_vault)

    resp = _get("100001")

    assert resp.status_code == 200
    assert json.loads(resp.body)["token"] == "tok-100001"
    assert calls == []


def test_refresh_failure_serves_old_value(fake_vault, reset_locks, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    _seed(fake_vault, "100001", expires_at=NOW + 7200)
    _spy_renew(monkeypatch, fake_vault, outcome=False)

    resp = _get("100001")

    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["token"] == "tok-100001"
    assert body["expired"] is False


def test_expired_token_with_failed_renewal_returns_expired_flag(
    fake_vault, reset_locks, monkeypatch
):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    _seed(fake_vault, "100001", expires_at=NOW - 100)
    _spy_renew(monkeypatch, fake_vault, outcome=False)

    resp = _get("100001")

    assert resp.status_code == 200
    assert json.loads(resp.body)["expired"] is True


def test_idle_expired_gate_preempts_renewal(fake_vault, reset_locks, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    _seed(fake_vault, "100001", expires_at=NOW + 90000, last_used_at=NOW - 73 * 3600)
    calls = _spy_renew(monkeypatch, fake_vault)

    resp = _get("100001")

    assert resp.status_code == 403
    assert json.loads(resp.body) == {"error": "idle_expired"}
    assert calls == []
