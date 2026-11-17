"""续期写库与"锁内重读"并发协议(UC 侧刷新即替换旧 token)。"""

import asyncio

import app as shim

NOW = 1_800_000_000


def _seed(coll, account: str = "100001", expires_at: int = NOW + 3600):
    coll.docs[account] = {
        "account": account,
        "name": "测试用户",
        "uc_user_id": "u-1",
        "token": f"tok-{account}",
        "expires_at": expires_at,
        "last_used_at": NOW,
    }
    return coll.docs[account]


def test_success_updates_token_and_expires_at_preserving_identity(
    fake_vault, reset_locks, monkeypatch
):
    doc = _seed(fake_vault)
    monkeypatch.setattr(shim, "_call_uc_refresh", lambda tok, acct: ("new-tok", NOW + 90000))

    assert asyncio.run(shim._renew_account("100001")) is True

    assert shim.vault_get("100001")["token"] == "new-tok"
    assert fake_vault.docs["100001"]["expires_at"] == NOW + 90000
    assert fake_vault.docs["100001"]["name"] == doc["name"]
    assert fake_vault.docs["100001"]["uc_user_id"] == doc["uc_user_id"]
    set_keys = set(fake_vault.update_calls[-1]["update"]["$set"])
    assert "name" not in set_keys and "uc_user_id" not in set_keys


def test_concurrent_renewal_skips_second_uc_call(fake_vault, reset_locks, monkeypatch):
    _seed(fake_vault, expires_at=NOW + 100)
    real_vault_get = shim.vault_get

    def mutating_get(account):
        doc = real_vault_get(account)
        if doc and doc.get("expires_at") == NOW + 100:
            # 模拟另一进程在锁外读取之后、锁内重读之前完成续期。
            # 返回读到时的旧值副本, 锁外读必须看到旧 exp。
            fake_vault.docs[account]["expires_at"] = NOW + 90000
            fake_vault.docs[account]["token"] = "other-process-token"
        return doc

    monkeypatch.setattr(shim, "vault_get", mutating_get)
    uc_calls = []
    monkeypatch.setattr(shim, "_call_uc_refresh", lambda tok, acct: uc_calls.append(tok))

    assert asyncio.run(shim._renew_account("100001")) is True
    assert uc_calls == []
    assert fake_vault.docs["100001"]["token"] == "other-process-token"


def test_conditional_write_race_does_not_overwrite(fake_vault, reset_locks, monkeypatch):
    _seed(fake_vault, expires_at=NOW + 100)

    def racing_refresh(tok, acct):
        # 模拟另一进程在锁内读取之后、写回之前抢先把新令牌写入(跨进程无锁)。
        fake_vault.docs[acct]["expires_at"] = NOW + 50000
        fake_vault.docs[acct]["token"] = "other-tok"
        return "raced-tok", NOW + 90000

    monkeypatch.setattr(shim, "_call_uc_refresh", racing_refresh)

    assert asyncio.run(shim._renew_account("100001")) is False
    assert fake_vault.docs["100001"]["token"] == "other-tok"
    assert fake_vault.docs["100001"]["expires_at"] == NOW + 50000


def test_uc_failure_makes_no_write(fake_vault, reset_locks, monkeypatch):
    _seed(fake_vault)
    monkeypatch.setattr(shim, "_call_uc_refresh", lambda tok, acct: None)

    assert asyncio.run(shim._renew_account("100001")) is False
    assert fake_vault.docs["100001"]["token"] == "tok-100001"
    assert fake_vault.update_calls == []


def test_missing_account_returns_false(fake_vault, reset_locks):
    assert asyncio.run(shim._renew_account("nobody")) is False


def test_disabled_without_url(fake_vault, reset_locks, monkeypatch):
    _seed(fake_vault)
    monkeypatch.setattr(shim, "UC_REFRESH_URL", "")

    # 真实客户端在 URL 为空时直接返回 None(功能惰性关闭), 不写库。
    assert asyncio.run(shim._renew_account("100001")) is False
    assert fake_vault.update_calls == []
