"""UC 刷新客户端: 规格(2026-11-09 实测口径)的成功/失败/惰性关闭行为。"""


import time
from types import SimpleNamespace

import jwt as pyjwt
import pytest

import app as shim

NOW = 1_800_000_000
ACCOUNT = "100002"


def _biz_jwt(sub: str = ACCOUNT, exp: int = NOW + 86400) -> str:
    return pyjwt.encode(
        {"sub": sub, "tenantId": None, "exp": exp, "iat": NOW}, "k" * 64, algorithm="HS512"
    )


def _uc_ok(token: str) -> dict:
    return {"token": token, "username": "", "account": "", "userId": "",
            "loginStatus": True, "clientIp": "192.168.37.132", "userAttrs": {}}


def _uc_fail() -> dict:
    return {"state": False, "message": "JWT expired at 2026-10-31T09:35:35Z",
            "value": None, "errorCode": None}


@pytest.fixture
def refresh_env(monkeypatch):
    """可编程的 httpx 替身: 记录每次调用, 响应体由测试注入。"""
    monkeypatch.setattr(shim, "UC_REFRESH_URL", "https://uc.example/uc/refresh")
    monkeypatch.setattr(shim, "UC_REFRESH_METHOD", "post")
    state = {"calls": [], "responder": lambda: SimpleNamespace(json=lambda: {}, raise_for_status=lambda: None)}

    def respond(payload):
        state["responder"] = lambda: SimpleNamespace(json=lambda: payload, raise_for_status=lambda: None)

    def _recorder(method):
        def fn(url, **kw):
            state["calls"].append((method, url, kw))
            return state["responder"]()
        return fn

    monkeypatch.setattr(shim.httpx, "get", _recorder("GET"))
    monkeypatch.setattr(shim.httpx, "post", _recorder("POST"))
    return SimpleNamespace(calls=state["calls"], respond=respond)


def test_success_returns_token_and_exp(refresh_env):
    tok = _biz_jwt()
    refresh_env.respond(_uc_ok(tok))

    got = shim._call_uc_refresh("old-token", ACCOUNT)

    assert got == (tok, NOW + 86400)
    method, url, kw = refresh_env.calls[0]
    assert method == "POST"
    assert url == "https://uc.example/uc/refresh"
    assert kw["headers"]["Authorization"] == "Bearer old-token"
    assert kw["verify"] is shim.TLS_VERIFY


def test_failure_state_false_returns_none(refresh_env):
    refresh_env.respond(_uc_fail())

    assert shim._call_uc_refresh("old-token", ACCOUNT) is None


def test_sub_mismatch_rejected(refresh_env):
    refresh_env.respond(_uc_ok(_biz_jwt(sub="999999")))

    assert shim._call_uc_refresh("old-token", ACCOUNT) is None


def test_refresh_disabled_without_url(refresh_env, monkeypatch):
    monkeypatch.setattr(shim, "UC_REFRESH_URL", "")

    assert shim._call_uc_refresh("old-token", ACCOUNT) is None
    assert refresh_env.calls == []


def test_method_get_when_configured(refresh_env, monkeypatch):
    monkeypatch.setattr(shim, "UC_REFRESH_METHOD", "get")
    refresh_env.respond(_uc_ok(_biz_jwt()))

    shim._call_uc_refresh("old-token", ACCOUNT)

    assert refresh_env.calls[0][0] == "GET"


def test_mock_mode_returns_synthetic_token(monkeypatch):
    monkeypatch.setattr(shim, "UC_REFRESH_URL", "https://uc.example/uc/refresh")
    monkeypatch.setattr(shim, "MOCK_MODE", True)

    got = shim._call_uc_refresh("old-token", ACCOUNT)

    assert got is not None
    assert got[0].startswith("mock-biz-token-")
    assert got[1] > int(time.time())


def test_default_method_is_get():
    """用户 2026-11-09 确认 UC 刷新接口为 GET, 默认值随之固定。"""
    assert shim.UC_REFRESH_METHOD == "get"


def test_jwt_exp_helper():
    assert shim._jwt_exp(_biz_jwt()) == NOW + 86400
    assert shim._jwt_exp("not-a-jwt") is None
