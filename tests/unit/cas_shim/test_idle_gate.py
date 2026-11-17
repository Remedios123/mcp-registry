"""72h 硬闸与活跃记录: /internal/business-token 的门卫行为。"""

import asyncio
import json

from starlette.requests import Request

import app as shim

NOW = 1_800_000_000


def _request(token: str = "test-internal-token") -> Request:
    return Request({"type": "http", "headers": [(b"x-internal-token", token.encode())]})


def _get(account: str, token: str = "test-internal-token"):
    return asyncio.run(shim.internal_business_token(account, _request(token)))


def _seed(coll, account: str, *, last_used_at=None, updated_at=None, expires_in=3600):
    doc = {
        "account": account,
        "name": "测试用户",
        "uc_user_id": "u-1",
        "token": f"tok-{account}",
        "expires_at": int(NOW + expires_in),
    }
    if updated_at is not None:
        doc["updated_at"] = updated_at
    if last_used_at is not None:
        doc["last_used_at"] = last_used_at
    coll.docs[account] = doc
    return doc


def test_serves_fresh_account_and_touches_last_used(fake_vault, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    _seed(fake_vault, "100001", last_used_at=int(NOW - 3600))

    resp = _get("100001")

    assert resp.status_code == 200
    body = json.loads(resp.body)
    assert body["token"] == "tok-100001"
    assert body["expired"] is False
    assert fake_vault.docs["100001"].get("last_used_at") == NOW


def test_idle_expired_account_refused_without_touch(fake_vault, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    stale = int(NOW - 73 * 3600)
    _seed(fake_vault, "100001", last_used_at=stale)

    resp = _get("100001")

    assert resp.status_code == 403
    body = json.loads(resp.body)
    assert body == {"error": "idle_expired"}
    assert "token" not in body
    assert fake_vault.docs["100001"].get("last_used_at") == stale


def test_missing_last_used_at_falls_back_to_updated_at(fake_vault, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    _seed(fake_vault, "100001", updated_at=int(NOW - 3600))

    resp = _get("100001")

    assert resp.status_code == 200
    assert fake_vault.docs["100001"].get("last_used_at") == NOW


def test_stale_row_without_last_used_at_gated_by_updated_at(fake_vault, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    _seed(fake_vault, "100001", updated_at=int(NOW - 73 * 3600))

    resp = _get("100001")

    assert resp.status_code == 403
    assert json.loads(resp.body) == {"error": "idle_expired"}


def test_unknown_account_still_404(fake_vault):
    resp = _get("nobody")

    assert resp.status_code == 404
    assert json.loads(resp.body) == {"error": "not_found"}


def test_bad_internal_token_still_forbidden(fake_vault):
    _seed(fake_vault, "100001", last_used_at=int(NOW - 60))

    resp = _get("100001", token="wrong")

    assert resp.status_code == 403
    assert json.loads(resp.body) == {"error": "forbidden"}
