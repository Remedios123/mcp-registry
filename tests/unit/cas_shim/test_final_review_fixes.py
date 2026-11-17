"""终审修复回归: C1 活跃信号自污染 / I1 批量异常隔离 / I2 不阻塞事件循环。"""

import asyncio
import time as _time

import app as shim

NOW = 1_800_000_000


def _fresh(coll, account: str, *, last_used_at: int = NOW - 3600):
    coll.docs[account] = {
        "account": account,
        "name": "n",
        "uc_user_id": "u",
        "token": f"tok-{account}",
        "expires_at": NOW + 7200,
        "last_used_at": last_used_at,
    }


# ── C1: 活跃信号不被续期污染(login/renewal 两个写点都要守) ──────────

def test_vault_put_writes_last_used_at(fake_vault, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)

    shim.vault_put("100001", "测试用户", "u-1", "tok", NOW + 86400)

    assert fake_vault.docs["100001"]["last_used_at"] == NOW


def test_renewal_preserves_activity_clock_of_legacy_row(
    fake_vault, reset_locks, monkeypatch
):
    # 存量行: 无 last_used_at, 真实活跃 = updated_at(1h 前)。
    # 续期只换令牌, 不得把活跃时钟顶到当前, 否则硬闸对它永久失效。
    fake_vault.docs["100001"] = {
        "account": "100001",
        "name": "n",
        "uc_user_id": "u",
        "token": "tok",
        "expires_at": NOW + 7200,
        "updated_at": NOW - 3600,
    }
    monkeypatch.setattr(shim, "_call_uc_refresh", lambda tok, acct: ("new", NOW + 90000))

    assert asyncio.run(shim._renew_account("100001")) is True

    doc = fake_vault.docs["100001"]
    assert doc["last_used_at"] == NOW - 3600
    assert shim._is_idle_expired(doc, NOW + 73 * 3600) is True


def test_legacy_row_stops_being_renewed_after_idle_window(
    fake_vault, reset_locks, monkeypatch
):
    # 连续 12h 一批的网格: 修复前每批都把 updated_at 顶高, 永远在窗内被续;
    # 修复后活跃时钟钉在真实值, 72h 后的批次必须 skipped_idle。
    monkeypatch.setattr(shim, "UC_REFRESH_URL", "https://uc.example/uc/refresh")
    fake_vault.docs["100001"] = {
        "account": "100001",
        "name": "n",
        "uc_user_id": "u",
        "token": "tok",
        "expires_at": NOW + 7200,
        "updated_at": NOW - 3600,
    }
    renew_calls = []

    async def fake_renew(account):
        renew_calls.append(account)
        fake_vault.docs[account].update({"token": "new", "expires_at": NOW + 90000})
        return True

    monkeypatch.setattr(shim, "_renew_account", fake_renew)

    for offset in (0, 12, 24, 36, 48, 60, 72):
        asyncio.run(shim._run_batch(NOW + offset * 3600))

    assert len(renew_calls) == 6, f"应只续前 6 批, 实际 {renew_calls}"


# ── I1: 批量单账号异常不中止整批 ────────────────────────────────────

def test_batch_isolates_per_account_exception(fake_vault, batch_env, monkeypatch):
    for i in range(3):
        _fresh(fake_vault, f"u{i}")

    calls = []

    async def flaky_renew(account):
        calls.append(account)
        if account == "u1":
            raise RuntimeError("boom")
        return True

    monkeypatch.setattr(shim, "_renew_account", flaky_renew)

    stats = asyncio.run(shim._run_batch(NOW))

    assert calls == ["u0", "u1", "u2"]
    assert stats == {"renewed": 2, "skipped_idle": 0, "failed": 1}


def test_uc_refresh_non_dict_json_returns_none(monkeypatch):
    from types import SimpleNamespace

    monkeypatch.setattr(shim, "UC_REFRESH_URL", "https://uc.example/uc/refresh")
    monkeypatch.setattr(
        shim.httpx, "post", lambda url, **kw: SimpleNamespace(json=lambda: "not-a-dict")
    )

    assert shim._call_uc_refresh("old", "100001") is None


# ── I2: 续期的 UC 调用不得阻塞事件循环 ──────────────────────────────

def test_renewal_does_not_block_event_loop(fake_vault, reset_locks, monkeypatch):
    _fresh(fake_vault, "a")
    _fresh(fake_vault, "b")

    def slow_refresh(tok, acct):
        _time.sleep(0.4)  # 真实睡眠: 经 to_thread 并行, 阻塞实现则串行
        return f"t-{acct}", NOW + 90000

    monkeypatch.setattr(shim, "_call_uc_refresh", slow_refresh)

    async def run_both():
        await asyncio.gather(shim._renew_account("a"), shim._renew_account("b"))

    start = _time.perf_counter()
    asyncio.run(run_both())
    elapsed = _time.perf_counter() - start

    assert elapsed < 0.75, f"两账号续期耗时 {elapsed:.2f}s, 疑似阻塞事件循环"
