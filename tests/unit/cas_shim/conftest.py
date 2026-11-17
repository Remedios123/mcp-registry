"""cas-shim 单元测试基建。

把 cas-shim 目录加入导入路径并以受控环境导入 app 模块;
提供内存版 vault 集合替身, 测试不依赖真实 Mongo。
"""

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
CAS_SHIM_DIR = REPO_ROOT / "cas-shim"
sys.path.insert(0, str(CAS_SHIM_DIR))

# app.py 在 import 时读取以下变量, 必须先就位:
# 签名密钥落到测试专用文件, 不碰真实 signing_key.pem, 也不进 git(cas-shim/keys/ 已 ignore)。
os.environ.setdefault("SHIM_SIGNING_SECRET", "test-signing-secret-0123456789abcdef")
os.environ.setdefault(
    "SHIM_SIGNING_KEY_PATH", str(CAS_SHIM_DIR / "keys" / "test-signing_key.pem")
)
os.environ.setdefault("SHIM_INTERNAL_TOKEN", "test-internal-token")
os.environ.setdefault("BUSINESS_TOKEN_IDLE_LIMIT_HOURS", "72")
# 封死环境泄漏: 开发机若导出过 UC_REFRESH_URL, 测试会打到真实 UC。
os.environ["UC_REFRESH_URL"] = ""
os.environ["SHIM_ALLOW_LEGACY_VAULT"] = "true"
os.makedirs(CAS_SHIM_DIR / "keys", exist_ok=True)

import app as shim  # noqa: E402


class FakeCollection:
    """内存版 vault 集合: 实现本套测试用到的 find_one / update_one 子集。

    update_one 的 filter 除 account 外的其余键视为条件字段(必须与现值全等
    才应用 $set), 覆盖 Task 3 的"条件更新防竞态"; 每次调用记入 update_calls。
    """

    def __init__(self) -> None:
        self.docs: dict[str, dict] = {}
        self.update_calls: list[dict] = []

    def find_one(self, flt, projection=None):
        doc = self.docs.get(flt.get("account"))
        return dict(doc) if doc else None

    def find(self, flt, projection=None):
        return [dict(doc) for doc in self.docs.values()]

    def update_one(self, flt, update, upsert=False):
        self.update_calls.append({"flt": dict(flt), "update": update})
        key = flt.get("account")
        doc = self.docs.get(key)
        if doc is None:
            if not upsert:
                return SimpleNamespace(modified_count=0, matched_count=0)
            doc = {"account": key}
            self.docs[key] = doc
        for cond_key, cond_val in flt.items():
            if cond_key != "account" and doc.get(cond_key) != cond_val:
                return SimpleNamespace(modified_count=0, matched_count=0)
        doc.update(update.get("$set", {}))
        return SimpleNamespace(modified_count=1, matched_count=1)


@pytest.fixture
def fake_vault(monkeypatch):
    coll = FakeCollection()
    monkeypatch.setattr(shim, "_vault_collection", lambda: coll)
    return coll


@pytest.fixture
def reset_locks():
    """Task 3 起使用: 每个 asyncio.run 都是新事件循环, 锁字典必须清空。"""
    getattr(shim, "_account_locks", {}).clear()
    yield
    getattr(shim, "_account_locks", {}).clear()


@pytest.fixture
def batch_env(monkeypatch):
    """批量测试基建: URL 打开、限速 100、_batch_sleep 可观测。"""
    monkeypatch.setattr(shim, "UC_REFRESH_URL", "https://uc.example/uc/refresh")
    monkeypatch.setattr(shim, "REFRESH_BATCH_RATE_PER_MINUTE", 100)
    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(shim, "_batch_sleep", fake_sleep)
    return SimpleNamespace(sleeps=sleeps)
