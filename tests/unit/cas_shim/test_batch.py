"""定点批量续期: 网格数学、批量判定三分支与分片限速。"""

import asyncio
from datetime import datetime

import pytest

import app as shim

NOW = 1_800_000_000


def _seed(coll, account: str, *, last_used_at: int, expires_at: int = NOW + 90000):
    coll.docs[account] = {
        "account": account,
        "name": "用户" + account,
        "uc_user_id": "u-" + account,
        "token": f"tok-{account}",
        "expires_at": expires_at,
        "last_used_at": last_used_at,
    }


def test_parse_cron_sorted_and_deduped():
    assert shim._parse_cron("03:00,15:00") == [(3, 0), (15, 0)]
    assert shim._parse_cron("15:00,03:00,15:00") == [(3, 0), (15, 0)]
    assert shim._parse_cron("3:00,abc") == [(3, 0)]
    assert shim._parse_cron("") == []


def test_next_batch_time_grid_math():
    base = datetime(2026, 11, 9, 10, 0).timestamp()
    assert shim._next_batch_time(base, "03:00,15:00") == datetime(
        2026, 11, 9, 15, 0
    ).timestamp()

    after_last = datetime(2026, 11, 9, 16, 0).timestamp()
    assert shim._next_batch_time(after_last, "03:00,15:00") == datetime(
        2026, 11, 10, 3, 0
    ).timestamp()

    # 严格大于: 恰好落在网格时刻时取下一格
    assert shim._next_batch_time(base, "10:00") == datetime(2026, 11, 10, 10, 0).timestamp()


def _spy_renew(monkeypatch, outcomes: dict):
    calls = []

    async def fake_renew(account):
        calls.append(account)
        return outcomes.get(account, False)

    monkeypatch.setattr(shim, "_renew_account", fake_renew)
    return calls


async def _collect(aws):
    return await asyncio.gather(*aws)


def test_run_batch_three_branches(fake_vault, batch_env, monkeypatch):
    _seed(fake_vault, "stale", last_used_at=NOW - 73 * 3600)
    _seed(fake_vault, "fresh", last_used_at=NOW - 12 * 3600)
    _seed(fake_vault, "broken", last_used_at=NOW - 12 * 3600)
    calls = _spy_renew(monkeypatch, {"fresh": True, "broken": False})

    stats = asyncio.run(shim._run_batch(NOW))

    assert stats == {"renewed": 1, "skipped_idle": 1, "failed": 1}
    assert "fresh" in calls and "broken" in calls and "stale" not in calls


def test_batch_rate_limit_sleeps_every_rate_calls(fake_vault, batch_env, monkeypatch):
    monkeypatch.setattr(shim, "REFRESH_BATCH_RATE_PER_MINUTE", 2)
    for i in range(3):
        _seed(fake_vault, f"u{i}", last_used_at=NOW - 3600)
    _spy_renew(monkeypatch, {f"u{i}": True for i in range(3)})

    stats = asyncio.run(shim._run_batch(NOW))

    assert stats["renewed"] == 3
    assert batch_env.sleeps == [60]


def test_batch_disabled_without_url(fake_vault, batch_env, monkeypatch):
    monkeypatch.setattr(shim, "UC_REFRESH_URL", "")
    _seed(fake_vault, "100001", last_used_at=NOW - 3600)
    calls = _spy_renew(monkeypatch, {"100001": True})

    stats = asyncio.run(shim._run_batch(NOW))

    assert stats == {"renewed": 0, "skipped_idle": 0, "failed": 0}
    assert calls == []


def test_batch_uses_current_time_when_not_given(fake_vault, batch_env, monkeypatch):
    monkeypatch.setattr(shim.time, "time", lambda: NOW)
    _seed(fake_vault, "100001", last_used_at=NOW - 12 * 3600)
    _spy_renew(monkeypatch, {"100001": True})

    stats = asyncio.run(shim._run_batch())

    assert stats["renewed"] == 1


def test_loop_function_exists_and_is_coroutine():
    import inspect

    assert inspect.iscoroutinefunction(shim._renewal_loop)
    assert inspect.iscoroutinefunction(shim._run_batch)
