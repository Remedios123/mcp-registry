"""WorkBuddy discovery and invocation regression tests."""

import json
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

# tool_access 与 server.py 同目录,平铺导入 http_pool 需要 servers/mcpgw 在 sys.path。
_mcpgw_path = str(Path(__file__).resolve().parents[4] / "servers" / "mcpgw")
if _mcpgw_path not in sys.path:
    sys.path.insert(0, _mcpgw_path)

from servers.mcpgw import tool_access  # noqa: E402
from servers.mcpgw.tool_access import (  # noqa: E402
    SEARCH_MAX_RESULTS,
    ToolAccessError,
    _schema_version,
    get_caller_mcp_token,
    invoke_tool,
    search_registry_tools,
)

MINTED = "minted-registry-ui-token"
MCP_TOKEN = "employee-mcp-jwt"


def _mk_ctx(headers: dict[str, str] | None = None):
    """构造形似 FastMCP Context 的最小对象(request_context.request.headers)。"""
    return SimpleNamespace(
        request_context=SimpleNamespace(
            request=SimpleNamespace(headers=dict(headers or {}))
        )
    )


def _mk_response(status_code: int = 200, payload: dict | None = None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = payload if payload is not None else {}
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        import httpx

        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "err", request=MagicMock(), response=MagicMock(status_code=status_code)
        )
    return resp


@pytest.fixture
def identity_ctx() -> SimpleNamespace:
    return _mk_ctx({
        "x-authorization": f"Bearer {MCP_TOKEN}",
    })


@pytest.fixture
def pooled_http(monkeypatch: pytest.MonkeyPatch) -> dict:
    """打桩共享连接池的 request_with_reconnect,捕获调用并回放队列。"""
    captured: dict = {}
    queue: list = []

    async def fake_request(client, method, url, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured["kwargs"] = kwargs
        item = queue.pop(0) if queue else _mk_response(500, {})
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(tool_access, "request_with_reconnect", fake_request)
    holder = SimpleNamespace(captured=captured, queue=queue)
    return holder


# ── 身份提取 ─────────────────────────────────────────────────────────


class TestIdentityExtraction:
    def test_authorization_token_read(self):
        assert get_caller_mcp_token(_mk_ctx({"Authorization": f"Bearer {MCP_TOKEN}"})) == MCP_TOKEN

    def test_missing_token_raises_identity(self):
        with pytest.raises(ToolAccessError) as exc:
            get_caller_mcp_token(_mk_ctx({}))
        assert exc.value.category == "identity"

    def test_caller_mcp_token_from_x_authorization(self, identity_ctx):
        assert get_caller_mcp_token(identity_ctx) == MCP_TOKEN

    def test_caller_mcp_token_missing_raises_identity(self):
        with pytest.raises(ToolAccessError) as exc:
            get_caller_mcp_token(_mk_ctx({"x-forwarded-registry-token": MINTED}))
        assert exc.value.category == "identity"


# ── search_registry_tools ────────────────────────────────────────────


class TestSearchRegistryTools:
    async def test_happy_path_assembles_tool_candidates(
        self, identity_ctx, pooled_http
    ):
        schema = {"type": "object", "properties": {"name": {"type": "string"}},
                  "required": ["name"]}
        pooled_http.queue.append(_mk_response(200, {
            "servers": [{
                "path": "/hr-mcp", "server_name": "hr",
                "matching_tools": [
                    {"tool_name": "query_employee", "description": "查员工",
                     "relevance_score": 0.9},
                ],
            }],
            "tools": [{
                "server_path": "/data-mcp", "tool_name": "run_report",
                "description": "跑报表", "inputSchema": schema,
                "relevance_score": 0.8,
            }],
            "virtual_servers": [{
                "path": "/vs-hr", "matching_tools": [
                    {"tool_name": "vs_tool", "inputSchema": schema,
                     "relevance_score": 0.7},
                ],
            }],
            "agents": [{"path": "/agent-1", "agent_name": "an-agent",
                        "relevance_score": 0.99}],
            "skills": [{"path": "/skill-1", "skill_name": "a-skill",
                        "relevance_score": 0.99}],
        }))

        result = await search_registry_tools("员工 查询", ctx=identity_ctx)

        # 请求打到 /api/search/semantic,带员工 registry-ui Token,不带服务凭据。
        assert pooled_http.captured["url"].endswith("/api/search/semantic")
        headers = pooled_http.captured["kwargs"]["headers"]
        assert headers == {"Authorization": f"Bearer {MCP_TOKEN}"}
        assert pooled_http.captured["kwargs"]["json"]["query"] == "员工 查询"
        # 候选池大于 5:不把全局 Top-5 直接当工具预算。
        assert pooled_http.captured["kwargs"]["json"]["max_results"] >= 20

        assert result["status"] == "success"
        names = [(r["server_path"], r["tool_name"]) for r in result["results"]]
        # agents/skills 不进工具检索结果;server_path 是定位键(去斜杠形态,
        # 评审 Finding 1:search 结果直接可喂 invoke)。
        assert ("hr-mcp", "query_employee") in names
        assert ("data-mcp", "run_report") in names
        assert ("vs-hr", "vs_tool") in names
        assert len(result["results"]) == 3
        # 按分数降序。
        scores = [r["relevance_score"] for r in result["results"]]
        assert scores == sorted(scores, reverse=True)
        # inputSchema 原样透传,带 schema 版本哈希;有 Schema 才可调用。
        by_name = {r["tool_name"]: r for r in result["results"]}
        assert by_name["run_report"]["inputSchema"] == schema
        assert by_name["run_report"]["callable"] is True
        assert by_name["run_report"]["schema_version"] == _schema_version(schema)
        # 直连服务 matching_tools 不带 Schema:如实标注不可调用,不假装能调。
        assert by_name["query_employee"]["callable"] is False
        assert by_name["query_employee"]["inputSchema"] is None
        assert by_name["query_employee"]["schema_version"] is None

    async def test_dedupes_by_server_path_and_tool_name(self, identity_ctx, pooled_http):
        schema = {"type": "object"}
        pooled_http.queue.append(_mk_response(200, {
            "servers": [{
                "path": "/hr-mcp", "server_name": "hr",
                "matching_tools": [{"tool_name": "dup", "description": "s",
                                    "relevance_score": 0.9}],
            }],
            "tools": [{"server_path": "/hr-mcp", "tool_name": "dup",
                       "description": "t", "inputSchema": schema,
                       "relevance_score": 0.6}],
        }))

        result = await search_registry_tools("dup", ctx=identity_ctx)

        assert len(result["results"]) == 1
        # 同键保留高分者(servers 分支 0.9 > tools 分支 0.6),分数不因去重而虚增。
        assert result["results"][0]["relevance_score"] == 0.9

    async def test_truncates_to_five(self, identity_ctx, pooled_http):
        tools = [{"server_path": f"/s{i}", "tool_name": "t",
                  "relevance_score": 0.5 - i * 0.01} for i in range(8)]
        pooled_http.queue.append(_mk_response(200, {"tools": tools}))

        result = await search_registry_tools("x", ctx=identity_ctx)

        assert len(result["results"]) == SEARCH_MAX_RESULTS
        assert result["total_candidates"] == 8

    async def test_no_match_status(self, identity_ctx, pooled_http):
        pooled_http.queue.append(_mk_response(200, {"servers": [], "tools": []}))

        result = await search_registry_tools("不存在的东西", ctx=identity_ctx)

        assert result["status"] == "no_match"
        assert result["results"] == []

    async def test_identity_missing_is_auth_failed_not_no_match(self):
        """身份缺失不得包装成"正常无结果"(V7:不包装成正常无结果)。"""
        result = await search_registry_tools("x", ctx=_mk_ctx({}))

        assert result["status"] == "auth_failed"
        assert result["results"] == []

    async def test_api_401_maps_to_auth_failed(self, identity_ctx, pooled_http):
        pooled_http.queue.append(_mk_response(401, {}))

        result = await search_registry_tools("x", ctx=identity_ctx)

        assert result["status"] == "auth_failed"

    async def test_registry_500_maps_to_registry_error(self, identity_ctx, pooled_http):
        pooled_http.queue.append(_mk_response(500, {}))

        result = await search_registry_tools("x", ctx=identity_ctx)

        assert result["status"] == "registry_error"

    async def test_max_results_is_locked_to_five(self, identity_ctx, pooled_http):
        pooled_http.queue.append(_mk_response(200, {"tools": []}))

        with pytest.raises(ValueError):
            await search_registry_tools("x", max_results=3, ctx=identity_ctx)

    async def test_query_validation(self, identity_ctx):
        with pytest.raises(ValueError):
            await search_registry_tools("   ", ctx=identity_ctx)


# ── invoke_tool ──────────────────────────────────────────────────────


class _InvokeHarness:
    """invoke_tool 的公共打桩:目录读取走 pooled_http,执行走 backend_exec。"""

    def __init__(self, pooled_http, monkeypatch):
        self.pooled_http = pooled_http
        self.backend_calls: list[dict] = []
        self.backend_result = MagicMock(is_error=False, content=[], structured_content=None)

        # 模块默认 REGISTRY_BASE_URL 是 http://localhost(生产 :80);
        # 本地启动脚本导出 :7860,测试按本地形态断言。
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")

        async def fake_backend_call(url, headers, tool_name, arguments, timeout):
            self.backend_calls.append({
                "url": url, "headers": dict(headers or {}),
                "tool_name": tool_name, "arguments": arguments,
                "timeout": timeout,
            })
            if isinstance(self.backend_result, Exception):
                raise self.backend_result
            return self.backend_result

        monkeypatch.setattr(tool_access, "_call_tool_via_data_plane", fake_backend_call)


@pytest.fixture
def invoke_harness(identity_ctx, pooled_http, monkeypatch):
    return _InvokeHarness(pooled_http, monkeypatch)


def _catalog_response(schema, tool_name="query_employee", server_path="/hr-mcp"):
    return _mk_response(200, {
        "path": server_path,
        "server_name": "hr",
        "tool_list": [{
            "name": tool_name,
            "description": "查询员工信息",
            "schema": schema,
        }],
    })


class TestInvokeTool:
    async def test_executes_original_tool_via_data_plane(
        self, identity_ctx, invoke_harness
    ):
        schema = {"type": "object", "properties": {"id": {"type": "string"}},
                  "required": ["id"]}
        invoke_harness.pooled_http.queue.append(_catalog_response(schema))
        invoke_harness.backend_result = MagicMock(
            is_error=False, content=[MagicMock(model_dump=lambda: {"type": "text", "text": "ok"})],
            structured_content={"answer": "ok"},
        )

        result = await invoke_tool("hr-mcp", "query_employee", {"id": "800311"},
                                   ctx=identity_ctx)

        assert result["status"] == "success"
        call = invoke_harness.backend_calls[0]
        # 目标只从网关 origin + 注册路径构造,不接受模型传入 URL。
        assert call["url"] == "http://localhost:7860/hr-mcp/mcp"
        # 调用者原始 MCP 令牌回显,数据面按 params.name 再次授权。
        assert call["headers"]["X-Authorization"] == f"Bearer {MCP_TOKEN}"
        assert call["tool_name"] == "query_employee"
        assert call["arguments"] == {"id": "800311"}
        assert result["content"] == [{"type": "text", "text": "ok"}]
        assert result["structured"] == {"answer": "ok"}

    async def test_rejects_path_traversal(self, identity_ctx, invoke_harness):
        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("../hr", "t", {}, ctx=identity_ctx)
        assert exc.value.category == "bad_target"
        assert invoke_harness.backend_calls == []

    async def test_rejects_url_and_scheme_in_server_path(
        self, identity_ctx, invoke_harness
    ):
        for bad in ("http://evil/x", "hr/mcp", "hr:8000", "", "hr mcp"):
            with pytest.raises(ToolAccessError) as exc:
                await invoke_tool(bad, "t", {}, ctx=identity_ctx)
            assert exc.value.category == "bad_target", bad
        assert invoke_harness.backend_calls == []

    async def test_rejects_self_path_recursion(self, identity_ctx, invoke_harness,
                                               monkeypatch):
        monkeypatch.setattr(tool_access, "MCPGW_REGISTERED_PATH", "airegistry-tools")
        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("airegistry-tools", "invoke_tool", {}, ctx=identity_ctx)
        assert exc.value.category == "bad_target"

    async def test_no_catalog_access_maps_to_permission(
        self, identity_ctx, invoke_harness
    ):
        """员工读不到目标服务(403)→ 无权限,且不执行。"""
        invoke_harness.pooled_http.queue.append(_mk_response(403, {}))

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "permission"
        assert invoke_harness.backend_calls == []

    async def test_unknown_tool_maps_to_not_found(self, identity_ctx, invoke_harness):
        invoke_harness.pooled_http.queue.append(_catalog_response(
            {"type": "object"}, tool_name="other"))

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "not_found"
        assert invoke_harness.backend_calls == []

    async def test_schema_version_mismatch_refuses_execution(
        self, identity_ctx, invoke_harness
    ):
        schema = {"type": "object", "properties": {"id": {"type": "string"}}}
        invoke_harness.pooled_http.queue.append(_catalog_response(schema))

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {"id": "x"},
                              expected_schema_version="deadbeef0000",
                              ctx=identity_ctx)
        assert exc.value.category == "schema_changed"
        assert invoke_harness.backend_calls == []

    async def test_invalid_arguments_refuses_execution(self, identity_ctx, invoke_harness):
        schema = {"type": "object", "properties": {"id": {"type": "string"}},
                  "required": ["id"]}
        invoke_harness.pooled_http.queue.append(_catalog_response(schema))

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {"id": 123},
                              ctx=identity_ctx)
        assert exc.value.category == "invalid_arguments"
        assert invoke_harness.backend_calls == []

    async def test_definition_missing_refuses_execution(self, identity_ctx, invoke_harness):
        resp = _mk_response(200, {
            "path": "/hr-mcp", "server_name": "hr",
            "tool_list": [{"name": "query_employee", "description": "无 Schema"}],
        })
        invoke_harness.pooled_http.queue.append(resp)

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "definition_missing"
        assert invoke_harness.backend_calls == []

    async def test_backend_is_error_raises_upstream(self, identity_ctx, invoke_harness):
        invoke_harness.pooled_http.queue.append(_catalog_response({"type": "object"}))
        text_block = MagicMock(model_dump=lambda: {"type": "text", "text": "业务失败"})
        invoke_harness.backend_result = MagicMock(is_error=True, content=[text_block],
                                                  structured_content=None)

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "upstream"
        assert "业务失败" in str(exc.value)

    async def test_renewal_hint_maps_to_renewal_required(
        self, identity_ctx, invoke_harness
    ):
        """数据面 /renew 文案(业务令牌缺失/过期)单独归类,不复用 /renew 之外的上游错。"""
        invoke_harness.pooled_http.queue.append(_catalog_response({"type": "object"}))
        text_block = MagicMock(
            model_dump=lambda: {"type": "text", "text": "业务令牌已过期, 请打开 http://x/renew 续期"})
        invoke_harness.backend_result = MagicMock(is_error=True, content=[text_block],
                                                  structured_content=None)

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "renewal_required"

    async def test_timeout_maps_to_timeout(self, identity_ctx, invoke_harness):
        import asyncio

        invoke_harness.pooled_http.queue.append(_catalog_response({"type": "object"}))
        invoke_harness.backend_result = asyncio.TimeoutError()

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "timeout"

    async def test_identity_missing_refuses(self):
        ctx = _mk_ctx({"x-forwarded-registry-token": MINTED})
        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "t", {}, ctx=ctx)
        assert exc.value.category == "identity"


# ── schema 版本哈希 ──────────────────────────────────────────────────


class TestSchemaVersion:
    def test_stable_hash(self):
        s = {"type": "object", "properties": {"a": {"type": "string"}}}
        assert _schema_version(s) == _schema_version(dict(reversed(list(s.items()))))

    def test_none_schema_has_no_version(self):
        assert _schema_version(None) is None

    def test_different_schemas_differ(self):
        assert _schema_version({"type": "object"}) != _schema_version({"type": "array"})


# ── 评审修复回归:search→invoke 交接与错误归类 ────────────────────────


class TestReviewFindings:
    """独立评审(2026-11-06)的 Critical/Important 修复回归。"""

    async def test_search_result_server_path_feeds_invoke_round_trip(
        self, identity_ctx, pooled_http, monkeypatch
    ):
        """评审 Finding 1:search 返回的 server_path(带前导斜杠)必须能直接
        喂给 invoke_tool;注册路径以 /hr-mcp 形态存储,交接不允许手工去斜杠。"""
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")
        schema = {"type": "object", "properties": {"id": {"type": "string"}}}
        pooled_http.queue.append(_mk_response(200, {
            "tools": [{"server_path": "/hr-mcp", "tool_name": "query_employee",
                       "description": "查", "inputSchema": schema,
                       "relevance_score": 0.9}],
        }))
        search_result = await search_registry_tools("查", ctx=identity_ctx)
        assert search_result["results"][0]["server_path"] == "hr-mcp"

        harness = _InvokeHarness(pooled_http, monkeypatch)
        harness.pooled_http.queue.append(_catalog_response(schema))
        harness.backend_result = MagicMock(is_error=False, content=[],
                                           structured_content=None)
        result = await invoke_tool(search_result["results"][0]["server_path"],
                                   "query_employee", {"id": "x"}, ctx=identity_ctx)
        assert result["status"] == "success"
        assert harness.backend_calls[0]["url"] == "http://localhost:7860/hr-mcp/mcp"

    @pytest.mark.parametrize("path", ["/hr-mcp", "hr-mcp/", "/hr-mcp/"])
    async def test_invoke_accepts_leading_trailing_slash(
        self, path, identity_ctx, invoke_harness
    ):
        """评审 Finding 1(纵深):_validate_server_path 容忍首尾斜杠并归一化。"""
        invoke_harness.pooled_http.queue.append(
            _catalog_response({"type": "object"}))
        result = await invoke_tool(path, "query_employee", {}, ctx=identity_ctx)
        assert result["status"] == "success"
        assert invoke_harness.backend_calls[0]["url"] == "http://localhost:7860/hr-mcp/mcp"

    async def test_invoke_rejects_traversal_even_with_slashes(
        self, identity_ctx, invoke_harness
    ):
        for bad in ("/../evil", "../evil/", "hr/mcp/"):
            with pytest.raises(ToolAccessError) as exc:
                await invoke_tool(bad, "t", {}, ctx=identity_ctx)
            assert exc.value.category == "bad_target", bad

    async def test_unresolvable_ref_schema_is_definition_missing(
        self, identity_ctx, invoke_harness
    ):
        """评审 Finding 2:目录里的坏 Schema(外链 $ref)不逃逸错误契约。"""
        resp = _mk_response(200, {
            "path": "/hr-mcp", "server_name": "hr",
            "tool_list": [{"name": "query_employee", "description": "查",
                           "schema": {"$ref": "http://evil.example/x.json"}}],
        })
        invoke_harness.pooled_http.queue.append(resp)

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "definition_missing"
        assert invoke_harness.backend_calls == []

    async def test_unknown_type_schema_is_definition_missing(
        self, identity_ctx, invoke_harness
    ):
        """评审 Finding 2:未知 type 的 Schema 在 check_schema 阶段拒绝。"""
        resp = _mk_response(200, {
            "path": "/hr-mcp", "server_name": "hr",
            "tool_list": [{"name": "query_employee", "description": "查",
                           "schema": {"type": "bogus"}}],
        })
        invoke_harness.pooled_http.queue.append(resp)

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "definition_missing"

    async def test_data_plane_tool_denial_maps_to_permission(
        self, identity_ctx, invoke_harness
    ):
        """评审 Finding 3:数据面工具级拒绝(PermissionError 文案)归类 permission,
        不伪装成 upstream 让模型误重试。"""
        invoke_harness.pooled_http.queue.append(
            _catalog_response({"type": "object"}))
        text_block = MagicMock(model_dump=lambda: {
            "type": "text", "text": "无权调用工具 query_employee: 未分配给当前用户"})
        invoke_harness.backend_result = MagicMock(is_error=True, content=[text_block],
                                                  structured_content=None)

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "permission"

    async def test_catalog_401_maps_to_identity(self, identity_ctx, invoke_harness):
        """评审 Finding 4a:invoke 目录读取 401 = 检索身份失效,与 search 的
        auth_failed 同义,不再伪装成 upstream。"""
        invoke_harness.pooled_http.queue.append(_mk_response(401, {}))

        with pytest.raises(ToolAccessError) as exc:
            await invoke_tool("hr-mcp", "query_employee", {}, ctx=identity_ctx)
        assert exc.value.category == "identity"


class TestMinorHardening:
    """缓办 Minors 修复回归(评审 Finding 4b/5,2026-11-06 用户批准顺手修)。"""

    async def test_search_403_is_registry_error_not_auth_failed(
        self, identity_ctx, pooled_http
    ):
        """评审 Finding 4b:403 可能是 registry-mode 过滤(非身份决策),不报登录问题。"""
        pooled_http.queue.append(_mk_response(403, {}))

        result = await search_registry_tools("x", ctx=identity_ctx)

        assert result["status"] == "registry_error"


# ── P3-A 兜底:中文查询"服务命中但工具层空"时的服务级扫描 ─────────────


class TestServerScanFallback:
    """dev-plan P3-A 第 2 条:薄封装遇空不得直接回 no_match。

    中文查询在关键词层塌 token("员工 查询 人力"命中 /hr-mcp 但
    matching_tools 为空)。兜底:对语义命中的服务(预算内)读授权目录
    全量工具,按查询词重叠本地重匹配,如实标注 match_basis=server_scan。
    """

    async def test_fallback_scans_matched_server_catalog(
        self, identity_ctx, pooled_http, monkeypatch
    ):
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")
        schema = {"type": "object", "properties": {"name_like": {"type": "string"}}}
        # 第一跳:语义命中 /hr-mcp,但工具层为空(中文塌 token 的常态)
        pooled_http.queue.append(_mk_response(200, {
            "servers": [{"path": "/hr-mcp", "server_name": "hr",
                         "relevance_score": 1.0, "matching_tools": []}],
            "tools": [],
        }))
        # 第二跳:该服务的授权目录全量工具
        pooled_http.queue.append(_catalog_response(schema, tool_name="search_employees"))

        result = await search_registry_tools("员工 查询 人力", ctx=identity_ctx)

        # 确实发起了目录读(GET /api/servers/hr-mcp)
        assert pooled_http.captured["method"] == "GET"
        assert pooled_http.captured["url"].endswith("/api/servers/hr-mcp")
        assert result["status"] == "success"
        assert result["fallback"]["reason"] == "server_matched_tool_layer_empty"
        item = result["results"][0]
        assert (item["server_path"], item["tool_name"]) == ("hr-mcp", "search_employees")
        assert item["match_basis"] == "server_scan"
        # 目录读取带 Schema:兜底候选是可调用的,版本号齐备
        assert item["callable"] is True
        assert item["inputSchema"] == schema
        assert item["schema_version"] == _schema_version(schema)

    async def test_fallback_ranks_by_query_overlap(
        self, identity_ctx, pooled_http, monkeypatch
    ):
        """本地匹配按查询词重叠度排序,不相关工具沉底或被过滤。"""
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")
        schema = {"type": "object"}
        pooled_http.queue.append(_mk_response(200, {
            "servers": [{"path": "/hr-mcp", "server_name": "hr",
                         "relevance_score": 1.0, "matching_tools": []}],
        }))
        pooled_http.queue.append(_mk_response(200, {
            "path": "/hr-mcp", "server_name": "hr",
            "tool_list": [
                {"name": "search_employees", "description": "按姓名或账号查询员工信息",
                 "schema": schema},
                {"name": "export_audit_log", "description": "导出审计日志到文件",
                 "schema": schema},
            ],
        }))

        result = await search_registry_tools("查询员工", ctx=identity_ctx)

        names = [r["tool_name"] for r in result["results"]]
        assert names[0] == "search_employees"
        # "导出审计日志"与查询无词重叠:不进结果(漏而非滥)
        assert "export_audit_log" not in names

    async def test_no_server_matched_skips_fallback(
        self, identity_ctx, pooled_http, monkeypatch
    ):
        """服务都没命中时不扩展全授权集(避免"查无此物"被兜成噪声列表)。"""
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")
        pooled_http.queue.append(_mk_response(200, {"servers": [], "tools": []}))

        result = await search_registry_tools("完全无关的东西", ctx=identity_ctx)

        assert result["status"] == "no_match"
        assert "fallback" not in result

    async def test_fallback_budget_cap_reports_truncation(
        self, identity_ctx, pooled_http, monkeypatch
    ):
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")
        monkeypatch.setattr(tool_access, "FALLBACK_SERVER_BUDGET", 2)
        schema = {"type": "object"}
        pooled_http.queue.append(_mk_response(200, {
            "servers": [{"path": f"/s{i}", "server_name": f"s{i}",
                         "relevance_score": 0.5, "matching_tools": []}
                        for i in range(4)],
        }))
        for i in range(2):
            pooled_http.queue.append(_mk_response(200, {
                "path": f"/s{i}", "server_name": f"s{i}",
                "tool_list": [{"name": f"tool_{i}", "description": "查询员工信息",
                               "schema": schema}],
            }))

        result = await search_registry_tools("员工 查询", ctx=identity_ctx)

        assert result["fallback"]["servers_matched"] == 4
        assert result["fallback"]["servers_scanned"] == 2
        assert result["truncated"] is True

    async def test_fallback_catalog_403_skips_server(
        self, identity_ctx, pooled_http, monkeypatch
    ):
        """目录读 403(员工无权读该服务目录)跳过该服务,不炸不伪装。"""
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")
        pooled_http.queue.append(_mk_response(200, {
            "servers": [{"path": "/hr-mcp", "server_name": "hr",
                         "relevance_score": 1.0, "matching_tools": []}],
        }))
        pooled_http.queue.append(_mk_response(403, {}))

        result = await search_registry_tools("员工 查询", ctx=identity_ctx)

        assert result["status"] == "no_match"
        assert result["results"] == []
        # "服务命中但工具未选出"如实上报(dev-plan P3-A),只报服务名不漏工具名。
        assert result["fallback"]["reason"] == "server_matched_tool_layer_empty"
        assert result["fallback"]["scanned"] == []
        assert result["fallback"]["candidates"] == 0

    async def test_fallback_reports_when_employee_has_no_visible_tools(
        self, identity_ctx, pooled_http, monkeypatch
    ):
        """服务命中但员工可见目录为空/无词重叠:no_match + 如实说明,不伪装也不泄漏。"""
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")
        pooled_http.queue.append(_mk_response(200, {
            "servers": [{"path": "/hr-mcp", "server_name": "hr",
                         "relevance_score": 1.0, "matching_tools": []}],
        }))
        # 可见目录里只有与查询无词重叠的工具(未授权工具本就不在其中)。
        pooled_http.queue.append(_mk_response(200, {
            "path": "/hr-mcp", "server_name": "hr",
            "tool_list": [{"name": "export_audit_log", "description": "导出审计日志",
                           "schema": {"type": "object"}}],
        }))

        result = await search_registry_tools("绩效考核", ctx=identity_ctx)

        assert result["status"] == "no_match"
        assert result["results"] == []
        assert result["fallback"]["servers_scanned"] == 1
        assert result["fallback"]["candidates"] == 0
        assert "export_audit_log" not in json.dumps(result, ensure_ascii=False)


class TestFallbackLeakGuard:
    """冒烟发现:无关查询靠单个高频词("查询")与描述重叠混进兜底结果。
    规则:重叠 ≥2 个查询词,或包含度 ≥ FALLBACK_MIN_SCORE,二者其一才收。"""

    async def test_single_common_word_low_ratio_filtered(
        self, identity_ctx, pooled_http, monkeypatch
    ):
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")
        pooled_http.queue.append(_mk_response(200, {
            "servers": [{"path": "/hr-mcp", "server_name": "hr",
                         "relevance_score": 0.4, "matching_tools": []}],
        }))
        pooled_http.queue.append(_mk_response(200, {
            "path": "/hr-mcp", "server_name": "hr",
            "tool_list": [{"name": "search_employees",
                           "description": "按条件搜索员工, 返回摘要",
                           "schema": {"type": "object"}}],
        }))

        # "完全无关的词组" 含"查询"?不含——用与描述仅共享一个低区分度词的查询。
        # 描述含"搜索":查询"系统设置 权限" 与其零重叠;再构造仅共享"搜索"一词、
        # 包含度 1/4 的查询。
        result = await search_registry_tools("系统设置 搜索 主题", ctx=identity_ctx)

        assert result["status"] == "no_match"
        assert result["results"] == []

    async def test_two_word_overlap_still_passes(
        self, identity_ctx, pooled_http, monkeypatch
    ):
        """长查询只命中 2 个词(包含度低于阈值)仍应返回,防兜底变过严。"""
        monkeypatch.setattr(tool_access, "REGISTRY_URL", "http://localhost:7860")
        pooled_http.queue.append(_mk_response(200, {
            "servers": [{"path": "/hr-mcp", "server_name": "hr",
                         "relevance_score": 1.0, "matching_tools": []}],
        }))
        pooled_http.queue.append(_mk_response(200, {
            "path": "/hr-mcp", "server_name": "hr",
            "tool_list": [{"name": "search_employees",
                           "description": "按条件搜索员工, 返回摘要(姓名/工号/部门)",
                           "schema": {"type": "object"}}],
        }))

        # 查询 5 个词元,其中"员工""部门"命中 → matched=2,包含度 2/5 < 0.25
        result = await search_registry_tools("帮我 查 员工 的 部门", ctx=identity_ctx)

        assert result["status"] == "success"
        assert result["results"][0]["tool_name"] == "search_employees"



@pytest.mark.parametrize("value", ["//other.example", "/hr-mcp//", "/hr-mcp\\n"])
async def test_invoke_rejects_non_route_targets(value, identity_ctx, invoke_harness):
    with pytest.raises(ToolAccessError) as exc:
        await invoke_tool(value, "query_employee", ctx=identity_ctx)
    assert exc.value.category == "bad_target"


async def test_gateway_catalog_origin_cannot_supply_subpath(identity_ctx, monkeypatch):
    monkeypatch.setattr(tool_access, "REGISTRY_URL", "https://gateway.example/prefix")
    result = await search_registry_tools("employees", ctx=identity_ctx)
    assert result["status"] == "registry_error"


def test_forwarding_uses_same_precedence_as_gateway():
    ctx = _mk_ctx({
        "authorization": "Bearer backend-authority",
        "x-authorization": f"Bearer {MCP_TOKEN}",
    })
    assert get_caller_mcp_token(ctx) == MCP_TOKEN



@pytest.mark.parametrize("status, category", [(401, "identity"), (403, "permission")])
async def test_sdk_preserves_gateway_auth_denial(status, category, monkeypatch):
    import httpx2

    async def reject(request):
        assert request.headers["x-authorization"] == f"Bearer {MCP_TOKEN}"
        return httpx2.Response(status)

    async_client = httpx2.AsyncClient
    monkeypatch.setattr(
        tool_access.httpx2,
        "AsyncClient",
        lambda **kwargs: async_client(transport=httpx2.MockTransport(reject), **kwargs),
    )

    with pytest.raises(ToolAccessError) as exc:
        await tool_access._call_tool_via_data_plane(
            "http://gateway.test/hr/mcp",
            {"X-Authorization": f"Bearer {MCP_TOKEN}"},
            "query_employee",
            {},
            5.0,
        )
    assert exc.value.category == category


async def test_sdk_preserves_business_renewal_link(monkeypatch):
    import json

    import httpx2

    renewal = "https://shim.example.test/renew?intent=test"

    async def respond(request):
        assert request.headers["x-authorization"] == f"Bearer {MCP_TOKEN}"
        message = json.loads(request.content)
        if "id" not in message:
            return httpx2.Response(202)
        if message["method"] == "server/discover":
            return httpx2.Response(200, json={
                "jsonrpc": "2.0", "id": message["id"],
                "error": {"code": -32601, "message": "Method not found"},
            })
        if message["method"] == "initialize":
            result = {
                "protocolVersion": message["params"]["protocolVersion"],
                "serverInfo": {"name": "HR", "version": "1.0"},
                "capabilities": {"tools": {}},
            }
        elif message["method"] == "tools/list":
            result = {"tools": []}
        else:
            assert message["method"] == "tools/call"
            assert message["params"]["name"] == "query_employee"
            result = {
                "isError": True,
                "content": [{"type": "text", "text": f"Authorize HR at {renewal} and retry."}],
            }
        return httpx2.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})

    async_client = httpx2.AsyncClient
    monkeypatch.setattr(
        tool_access.httpx2,
        "AsyncClient",
        lambda **kwargs: async_client(transport=httpx2.MockTransport(respond), **kwargs),
    )
    result = await tool_access._call_tool_via_data_plane(
        "http://gateway.test/hr/mcp",
        {"X-Authorization": f"Bearer {MCP_TOKEN}"},
        "query_employee",
        {},
        5.0,
    )
    assert result.is_error
    assert renewal in result.content[0].text
