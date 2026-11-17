"""CAS 回调按 Sec-Fetch-Dest 分类: iframe 那条挂住不响应, 顶层导航照常兑换。

背景(2026-11-09 Edge 实测 + breakout 页源码): 公司 CAS 的 post-login
breakout 页把同一个 service URL 放了两处 —— <meta http-equiv="refresh">
(跳承载它的隐藏 iframe 自己) 和 window.top.location.replace()(跳顶层)。
iframe 那条在第三方上下文里设不上会话 cookie, 却会再兑换一次 ST 冲进
Keycloak broker 顶掉顶层刚签的 code(8888 换令牌 400, "页面已过期")。
CAS 登录页还要等 iframe onload 才走收尾(XHR sso-agreement/status 再自己
跳 /cas/login), 会取消顶层在途跳转 —— 所以 iframe 那条必须挂住连接,
既不兑换也不立刻响应。
"""

import asyncio
import base64
import json
from urllib.parse import urlencode

from starlette.requests import Request

import app as shim

KC_BROKER = "http://127.0.0.1:8080/realms/mcp-gateway/broker/cas/endpoint"


def _make_ctx(state: str = "s1") -> str:
    ctx = {
        "client_id": "mcp-gateway-keycloak",
        "redirect_uri": KC_BROKER,
        "state": state,
        "nonce": "n1",
        "scope": "openid profile",
        "code_challenge": "",
        "code_challenge_method": "",
        "ts": int(shim.time.time()),
    }
    ctx_b64 = base64.urlsafe_b64encode(json.dumps(ctx).encode()).decode()
    return shim._cookie_sign(ctx_b64)


def _callback(ctx_token: str, ticket: str = "ST-1", dest: str | None = None):
    headers = [(b"host", b"127.0.0.1:8085")]
    if dest is not None:
        headers.append((b"sec-fetch-dest", dest.encode()))
    request = Request({
        "type": "http",
        "method": "GET",
        "scheme": "http",
        "server": ("127.0.0.1", 8085),
        "path": "/cas/callback",
        "headers": headers,
        "query_string": urlencode({"ctx": ctx_token, "ticket": ticket}).encode(),
    })
    return asyncio.run(shim.cas_callback(request))


def _stub_exchange(monkeypatch):
    calls = []

    def fake_exchange(ticket, service=""):
        calls.append(ticket)
        return {"token": f"tok-{ticket}", "account": "100001",
                "username": "测试用户", "userId": "u-1", "expiration": 86400}

    monkeypatch.setattr(shim, "_exchange_st", fake_exchange)
    return calls


def _stub_hold(monkeypatch):
    holds = []

    async def fake_hold(request, seconds):
        holds.append(seconds)

    monkeypatch.setattr(shim, "_hold_until_disconnect", fake_hold)
    return holds


def test_iframe_callback_is_held_without_exchange(fake_vault, monkeypatch):
    calls = _stub_exchange(monkeypatch)
    holds = _stub_hold(monkeypatch)

    resp = _callback(_make_ctx(), dest="iframe")

    assert resp.status_code == 200
    assert holds == [shim.IFRAME_HOLD_SECONDS], "iframe 回调必须挂住, 不能立刻响应"
    assert calls == [], "iframe 回调不得兑换 ST"


def test_document_callback_exchanges(fake_vault, monkeypatch):
    calls = _stub_exchange(monkeypatch)
    _stub_hold(monkeypatch)

    resp = _callback(_make_ctx(), dest="document")

    assert resp.status_code == 302
    assert resp.headers["location"].startswith(KC_BROKER)
    assert len(calls) == 1


def test_iframe_first_then_document_still_completes(fake_vault, monkeypatch):
    calls = _stub_exchange(monkeypatch)
    _stub_hold(monkeypatch)
    ctx = _make_ctx()

    iframe = _callback(ctx, dest="iframe")
    document = _callback(ctx, dest="document")

    assert iframe.status_code == 200
    assert document.status_code == 302
    assert document.headers["location"].startswith(KC_BROKER)
    assert len(calls) == 1, "只有顶层导航兑换, iframe 挂住"


def test_missing_sec_fetch_dest_keeps_legacy_behavior(fake_vault, monkeypatch):
    calls = _stub_exchange(monkeypatch)
    _stub_hold(monkeypatch)

    resp = _callback(_make_ctx(), dest=None)

    assert resp.status_code == 302
    assert len(calls) == 1


def test_iframe_with_forged_ctx_not_held(fake_vault, monkeypatch):
    """伪造 ctx + 伪造 Sec-Fetch-Dest 不得占住连接(防连接耗尽 DoS)。"""
    calls = _stub_exchange(monkeypatch)
    holds = _stub_hold(monkeypatch)

    resp = _callback("forged-ctx-token", dest="iframe")

    assert holds == [], "签名无效的 iframe 请求不得挂住"
    assert calls == []
    assert resp.status_code == 200
