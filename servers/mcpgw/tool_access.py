"""Employee-scoped discovery and invocation through the registry gateway."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from typing import Any

import httpx
import httpx2
from jsonschema import SchemaError, ValidationError
from jsonschema.validators import validator_for
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult
from referencing import Registry

from http_pool import (
    DEFAULT_REGISTRY_BASE_URL,
    request_with_reconnect,
    shared_async_client,
)

logger = logging.getLogger(__name__)

REGISTRY_URL = os.getenv("REGISTRY_BASE_URL", DEFAULT_REGISTRY_BASE_URL).rstrip("/")
# mcpgw 自己的登记路径:递归防护(invoke_tool 不把入口自己当业务目标)。
MCPGW_REGISTERED_PATH = os.getenv("MCPGW_REGISTERED_PATH", "airegistry-tools").strip("/")
# 业务工具执行预算;超时不重试,按 timeout 类别返回(V7 §5)。
INVOKE_TIMEOUT_SECONDS = float(os.getenv("MCPGW_INVOKE_TIMEOUT_SECONDS", "60"))

# V7 §5:首期 max_results 默认与对外允许值都是 5;放开其他数量另行调整契约。
SEARCH_MAX_RESULTS: int = 5
# 传给 /api/search/semantic 的候选池:大于工具预算,避免服务/技能占位挤掉工具。
CANDIDATE_POOL: int = 20

# P3-A 兜底预算:语义命中的服务里最多扫描几个的授权目录(超出如实报 truncated)。
FALLBACK_SERVER_BUDGET: int = 3
# 兜底收词下限:重叠 ≥2 个查询词,或包含度 ≥ 此值,二者其一才返回。
# 冒烟发现无关查询靠单个高频词("查询")与描述重叠混入,此线挡住"滥"方向。
FALLBACK_MIN_SCORE: float = 0.25

MAX_QUERY_LENGTH: int = 500

# server_path 是注册目录的路由键:单段路径,不含斜杠/冒号/空白/.. 等 URL 语法。
# \Z(非 $)锚定字符串真实结尾,避免尾随换行绕过。
_SERVER_PATH_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]*\Z")

# 错误类别(V7 §5 第 7 条的划分);经异常上抛,MCP 层保留 isError。
C_IDENTITY = "identity"                    # 登录/身份不可用
C_PERMISSION = "permission"                # 员工无权访问目标服务/工具
C_NOT_FOUND = "not_found"                  # 目标不在注册目录
C_BAD_TARGET = "bad_target"                # 范围无效:server_path 非法/递归目标
C_INVALID_ARGUMENTS = "invalid_arguments"  # 参数错
C_SCHEMA_CHANGED = "schema_changed"        # 定义变化,要求重新搜索
C_DEFINITION_MISSING = "definition_missing"  # 目录里没有可用 Schema,拒绝盲调
C_RENEWAL = "renewal_required"             # 业务授权缺失/过期(带 /renew 入口)
C_UPSTREAM = "upstream"                    # 注册目录/业务后端故障
C_TIMEOUT = "timeout"                      # 业务调用超时

_RENEW_HINT = "/renew"


class ToolAccessError(Exception):
    """新工具的归一化错误:category 供 MCP isError 文本与调用方区分。"""

    def __init__(self, category: str, message: str) -> None:
        self.category = category
        self.message = message
        super().__init__(f"[{category}] {message}")


# ── 身份提取(只认数据面转发的头,不碰服务凭据) ─────────────────────


def _header_value(ctx: Any, name: str) -> str | None:
    """从 FastMCP 请求上下文读一个头;无上下文或无该头返回 None。

    Starlette Headers 本身大小写不敏感;这里再兜底扫一遍,兼容测试用的普通 dict。
    """
    try:
        headers = ctx.request_context.request.headers
    except AttributeError:
        return None
    value = headers.get(name)
    if value is not None:
        return value
    try:
        for key, val in headers.items():
            if key.lower() == name.lower():
                return val
    except AttributeError:
        return None
    return None


def get_caller_mcp_token(ctx: Any) -> str:
    """取调用者原始 MCP 令牌(invoke_tool 经数据面重过授权要用它)。"""
    if ctx is None:
        raise ToolAccessError(C_IDENTITY, "登录状态不可用: 未收到员工身份")
    raw = _header_value(ctx, "x-authorization") or _header_value(ctx, "authorization") or ""
    scheme, _, token = raw.strip().partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        return token.strip()
    raise ToolAccessError(
        C_IDENTITY, "登录状态不可用: 请求未携带员工 MCP 令牌")


# ── search_registry_tools ────────────────────────────────────────────


def _schema_version(schema: dict[str, Any] | None) -> str | None:
    """Schema 的稳定哈希作为版本号;registry 无原生 schema_version 字段。"""
    if not isinstance(schema, dict):
        return None
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _entry_schema(tool: dict[str, Any]) -> dict[str, Any] | None:
    """Read the canonical MCP schema, including a valid empty schema."""
    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        schema = tool.get("schema")
    return schema if isinstance(schema, dict) else None


def _collect_tool_candidates(data: dict[str, Any]) -> list[dict[str, Any]]:
    """把 /api/search/semantic 各结果分支整理成工具候选(只留工具,不动其他实体)。"""
    candidates: list[dict[str, Any]] = []
    for tool in data.get("tools") or []:
        if not isinstance(tool, dict):
            continue
        candidates.append({
            # 注册路径带前导斜杠存储;invoke 的定位键约定为去斜杠形态,
            # 这里归一化,search→invoke 直接交接。
            "server_path": (tool.get("server_path") or "").strip("/"),
            "tool_name": tool.get("tool_name") or "",
            "description": tool.get("description"),
            "inputSchema": tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else None,
            "relevance_score": float(tool.get("relevance_score") or 0.0),
        })
    for section in ("servers", "virtual_servers"):
        for server in data.get(section) or []:
            if not isinstance(server, dict):
                continue
            for tool in server.get("matching_tools") or []:
                if not isinstance(tool, dict):
                    continue
                candidates.append({
                    "server_path": (server.get("path") or "").strip("/"),
                    "tool_name": tool.get("tool_name") or "",
                    "description": tool.get("description"),
                    "inputSchema": tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else None,
                    "relevance_score": float(tool.get("relevance_score") or 0.0),
                })
    return candidates


def _dedupe_by_location(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """按 (server_path, tool_name) 去重,同键保留分数高者。"""
    best: dict[tuple[str, str], dict[str, Any]] = {}
    order: list[tuple[str, str]] = []
    for candidate in candidates:
        key = (candidate["server_path"], candidate["tool_name"])
        existing = best.get(key)
        if existing is None:
            best[key] = candidate
            order.append(key)
        elif candidate["relevance_score"] > existing["relevance_score"]:
            if candidate["inputSchema"] is None:
                candidate["inputSchema"] = existing["inputSchema"]
            best[key] = candidate
        elif existing["inputSchema"] is None:
            existing["inputSchema"] = candidate["inputSchema"]
    return [best[key] for key in order]


# ── P3-A 兜底:服务级全量工具扫描 ────────────────────────────────────
# 中文查询在关键词层塌 token("\W+" 分词 + len>2 过滤丢两字词),常态是
# "服务命中但 matching_tools 为空"。兜底对语义命中的服务读授权目录全量
# 工具,按查询词重叠本地重匹配;漏的方向(选不出工具)可接受,滥的方向
# (无词重叠也返回)用 score>0 挡住。

_ASCII_WORD = re.compile(r"[a-z0-9]+")
_CJK_RUN = re.compile(r"[\u4e00-\u9fff]+")


def _text_tokens(text: str) -> set[str]:
    """ASCII 词 + 中文字符二元组(单字 CJK 串取单字),供重叠度计算。"""
    tokens: set[str] = set()
    text = text or ""
    for word in _ASCII_WORD.findall(text.lower()):
        tokens.add(word)
    for run in _CJK_RUN.findall(text):
        if len(run) == 1:
            tokens.add(run)
            continue
        tokens.update(run[i:i + 2] for i in range(len(run) - 1))
    return tokens


def _query_overlap(query_tokens: set[str], text: str) -> tuple[float, int]:
    """查询词在工具文本中的 (包含度, 命中词数);0 = 无重叠(兜底不返回)。"""
    if not query_tokens:
        return 0.0, 0
    overlap = query_tokens & _text_tokens(text)
    return len(overlap) / len(query_tokens), len(overlap)


async def _fallback_scan_matched_servers(
    query_tokens: set[str],
    matched_servers: list[tuple[str, float]],
    headers: dict[str, str],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, bool]:
    """对语义命中的服务(预算内)读授权目录并本地重匹配。

    返回 (候选, fallback 信息, truncated);候选为空时 fallback 信息为 None。
    目录读失败(403=员工无权读该目录等)跳过该服务,不伪装成结果。
    """
    ordered = sorted(matched_servers, key=lambda item: item[1], reverse=True)
    budget = ordered[:FALLBACK_SERVER_BUDGET]
    truncated = len(ordered) > len(budget)
    scanned: list[str] = []
    candidates: list[dict[str, Any]] = []
    for path, _score in budget:
        try:
            clean = _validate_server_path(path)
        except ToolAccessError:
            continue
        try:
            response = await request_with_reconnect(
                shared_async_client(), "GET", _gateway_endpoint(f"/api/servers/{clean}"),
                headers=headers, timeout=30.0, follow_redirects=False,
            )
            response.raise_for_status()
            server_info = response.json()
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code if exc.response is not None else 0
            logger.warning("search fallback: 目录读取 %s HTTP %s, 跳过", clean, status)
            continue
        except (httpx.HTTPError, ToolAccessError, ValueError) as exc:
            logger.warning("search fallback: 目录读取 %s 失败, 跳过: %s", clean, exc)
            continue
        scanned.append(clean)
        for tool in server_info.get("tool_list") or []:
            if not isinstance(tool, dict):
                continue
            name = tool.get("name") or tool.get("tool_name") or ""
            if not name:
                continue
            score, matched = _query_overlap(
                query_tokens, f"{name} {tool.get('description') or ''}")
            if matched < 2 and score < FALLBACK_MIN_SCORE:
                continue
            schema = _entry_schema(tool)
            candidates.append({
                "server_path": clean,
                "tool_name": name,
                "description": tool.get("description"),
                "inputSchema": schema if isinstance(schema, dict) else None,
                "relevance_score": float(score),
                "_match_basis": "server_scan",
            })
    # 服务命中但没选出工具(员工可见目录里无词重叠,或目录读全跳过)也要如实
    # 上报:agent 能区分"范围内没有"与"服务命中但你无可见工具"。只报服务名,
    # 不报未选出的工具,不泄漏无权工具名称(V7 §5)。
    info = {"reason": "server_matched_tool_layer_empty",
            "servers_matched": len(ordered), "servers_scanned": len(scanned),
            "scanned": scanned, "candidates": len(candidates)}
    return _dedupe_by_location(candidates), info, truncated


async def search_registry_tools(
    query: str,
    max_results: int = SEARCH_MAX_RESULTS,
    ctx: Any = None,
) -> dict[str, Any]:
    """按员工权限做工具级检索(契约见 V7 §5;server.py 里有面向模型的 docstring)。

    返回 dict 的 results 每项含 server_path / tool_name / description /
    inputSchema / schema_version / relevance_score / callable;缺 Schema 的候选
    callable=False,不作为可调用项推荐。status 区分 success / no_match /
    auth_failed / registry_error,鉴权失败绝不包装成"正常无结果"。
    """
    query = (query or "").strip()
    if not query:
        raise ValueError("Query cannot be empty")
    if len(query) > MAX_QUERY_LENGTH:
        raise ValueError(f"Query exceeds maximum length of {MAX_QUERY_LENGTH} characters")
    if max_results != SEARCH_MAX_RESULTS:
        raise ValueError(
            f"max_results 只允许 {SEARCH_MAX_RESULTS}(试点期契约);"
            "放开其他数量另行调整契约")
    try:
        mcp_token = get_caller_mcp_token(ctx)
    except ToolAccessError as exc:
        logger.warning("search_registry_tools: %s", exc)
        return {"status": "auth_failed", "query": query, "results": [],
                "total_candidates": 0, "returned": 0, "error": exc.message}

    payload = {
        "query": query,
        "max_results": CANDIDATE_POOL,
        "entity_types": ["mcp_server", "mcp_tool", "virtual_server"],
    }
    headers = {"Authorization": f"Bearer {mcp_token}"}
    try:
        response = await request_with_reconnect(
            shared_async_client(), "POST", _gateway_endpoint("/api/search/semantic"),
            headers=headers, json=payload, timeout=30.0, follow_redirects=False,
        )
        response.raise_for_status()
        data = response.json()
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        logger.warning("search_registry_tools: /api HTTP %s", status)
        # 401 是检索身份失效;403 可能是 registry-mode 过滤等非身份决策,
        # 不当登录问题报,归 registry_error(评审 Finding 4b)。
        category = "auth_failed" if status == 401 else "registry_error"
        return {"status": category, "query": query, "results": [],
                "total_candidates": 0, "returned": 0,
                "error": f"Registry API error: HTTP {status}"}
    except (httpx.HTTPError, ToolAccessError, ValueError) as exc:
        logger.warning("search_registry_tools: /api 不可达: %s", exc)
        return {"status": "registry_error", "query": query, "results": [],
                "total_candidates": 0, "returned": 0,
                "error": "Registry API unreachable"}

    candidates = _dedupe_by_location([
        candidate for candidate in _collect_tool_candidates(data)
        if _is_target_path(candidate["server_path"]) and candidate["tool_name"]
    ])
    fallback_info = None
    truncated = False
    if not candidates:
        # P3-A 兜底:语义命中服务但工具层为空(中文查询常态),对命中服务的
        # 授权目录做预算内全量扫描;服务都没命中则如实 no_match,不扩展噪声。
        matched_servers = [
            (server.get("path") or "", float(server.get("relevance_score") or 0.0))
            for section in ("servers", "virtual_servers")
            for server in (data.get(section) or [])
            if isinstance(server, dict) and server.get("path")
        ]
        if matched_servers:
            candidates, fallback_info, truncated = await _fallback_scan_matched_servers(
                _text_tokens(query), matched_servers, headers)
    candidates.sort(key=lambda item: item["relevance_score"], reverse=True)
    total = len(candidates)
    results = []
    for candidate in candidates[:max_results]:
        version = _schema_version(candidate["inputSchema"])
        results.append({
            "server_path": candidate["server_path"],
            "tool_name": candidate["tool_name"],
            "description": candidate["description"],
            "inputSchema": candidate["inputSchema"],
            "schema_version": version,
            "relevance_score": candidate["relevance_score"],
            "callable": (
                candidate["inputSchema"] is not None
                and candidate["server_path"] != MCPGW_REGISTERED_PATH
            ),
            "match_basis": candidate.get("_match_basis", "semantic"),
        })
    status = "success" if results else "no_match"
    result = {"status": status, "query": query, "results": results,
              "total_candidates": total, "returned": len(results)}
    if fallback_info is not None:
        result["fallback"] = fallback_info
    if truncated:
        result["truncated"] = True
    return result


# ── invoke_tool ──────────────────────────────────────────────────────


def _validate_server_path(server_path: str, *, allow_self: bool = False) -> str:
    """校验并归一化 server_path 为无斜杠的单段注册路径;拒绝逃逸与递归目标。

    注册目录以 "/hr-mcp" 这类带前导斜杠的形态存路径(搜索结果原样透传),
    这里先归一化(去首尾斜杠)再校验,search→invoke 的交接不需要调用方手工
    处理斜杠;除首尾斜杠外的任何 URL 语法(斜杠、冒号、空白、..)一律拒绝。
    """
    path = (server_path or "").removeprefix("/").removesuffix("/")
    if not path or not _SERVER_PATH_PATTERN.match(path) or path in (".", ".."):
        raise ToolAccessError(
            C_BAD_TARGET,
            f"server_path 非法: 只接受注册目录的单段路径(如 hr-mcp), 收到 {server_path!r}")
    if path == MCPGW_REGISTERED_PATH and not allow_self:
        raise ToolAccessError(
            C_BAD_TARGET,
            "入口自身不能作为 invoke 目标(不允许递归调用检索/代调用工具)")
    return path


def _is_target_path(server_path: str) -> bool:
    """Check that a result can point to a business server."""
    try:
        _validate_server_path(server_path, allow_self=True)
    except ToolAccessError:
        return False
    return True


def _gateway_endpoint(path: str) -> str:
    """Build a URL on the configured gateway origin."""
    origin = httpx.URL(REGISTRY_URL)
    if (
        origin.scheme not in {"http", "https"}
        or not origin.host
        or origin.userinfo
        or origin.path not in {"", "/"}
        or origin.query
        or origin.fragment
    ):
        raise ToolAccessError(C_UPSTREAM, "REGISTRY_BASE_URL must be the gateway origin")
    return str(origin.copy_with(path=path))


async def _call_tool_via_data_plane(
    url: str,
    headers: dict[str, str],
    tool_name: str,
    arguments: dict[str, Any] | None,
    timeout: float,
) -> CallToolResult:
    """经网关 per-server 数据面发原始 tools/call(mcp SDK 客户端,无重试)。"""
    gateway_status: int | None = None

    async def _record_denial(response: httpx2.Response) -> None:
        nonlocal gateway_status
        if response.request.method == "POST" and response.status_code in {401, 403}:
            gateway_status = response.status_code

    try:
        async with (
            asyncio.timeout(timeout),
            httpx2.AsyncClient(
                headers=headers,
                timeout=httpx2.Timeout(timeout),
                follow_redirects=False,
                trust_env=False,
                event_hooks={"response": [_record_denial]},
            ) as http_client,
        ):
            transport = streamable_http_client(url, http_client=http_client)
            async with Client(transport, mode="auto", cache=None) as client:
                return await client.call_tool(tool_name, arguments or {})
    except Exception as exc:
        # The SDK translates HTTP rejections into a generic MCP error.
        if gateway_status == 401:
            raise ToolAccessError(C_IDENTITY, "网关拒绝了员工身份，请重新登录") from exc
        if gateway_status == 403:
            raise ToolAccessError(C_PERMISSION, "当前员工无权通过网关调用该工具") from exc
        raise


def _content_texts(content: Any) -> list[str]:
    """从 MCP content 块提取文本(兼容真实 TextContent 与测试替身)。"""
    texts: list[str] = []
    for block in content or []:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            texts.append(text)
            continue
        dump = getattr(block, "model_dump", None)
        if callable(dump):
            item = dump()
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                texts.append(item["text"])
    return texts


async def invoke_tool(
    server_path: str,
    tool_name: str,
    arguments: dict[str, Any] | None = None,
    expected_schema_version: str | None = None,
    ctx: Any = None,
) -> dict[str, Any]:
    """以员工身份代调用注册目录里的业务工具(契约见 V7 §5;docstring 在 server.py)。

    失败一律抛 ToolAccessError(MCP 层转 isError),类别见 C_* 常量;
    业务后端返回 isError 时按其文本归类(/renew 提示 → renewal_required)。
    """
    path = _validate_server_path(server_path)
    tool_name = (tool_name or "").strip()
    if not tool_name:
        raise ToolAccessError(C_INVALID_ARGUMENTS, "tool_name 不能为空")
    mcp_token = get_caller_mcp_token(ctx)

    # 目标与 Schema 只来自可信注册目录;员工的目录读权限由 registry 服务端把关。
    headers = {"Authorization": f"Bearer {mcp_token}"}
    try:
        response = await request_with_reconnect(
            shared_async_client(), "GET", _gateway_endpoint(f"/api/servers/{path}"),
            headers=headers, timeout=30.0, follow_redirects=False,
        )
        response.raise_for_status()
        server_info = response.json()
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 0
        logger.warning("invoke_tool: 目录读取 %s HTTP %s", path, status)
        if status == 401:
            # 与 search 的 auth_failed 同义:检索身份失效(30s TTL 过期等),
            # 模型该走重新检索/重新认证,而不是把目录当成坏了。
            raise ToolAccessError(
                C_IDENTITY,
                "检索身份已失效, 请重新发起会话或重新检索") from exc
        if status == 403:
            raise ToolAccessError(
                C_PERMISSION, f"当前员工无权访问服务 {path}") from exc
        if status == 404:
            raise ToolAccessError(
                C_NOT_FOUND, f"注册目录中没有服务 {path}") from exc
        raise ToolAccessError(
            C_UPSTREAM, f"注册目录读取失败: HTTP {status}") from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise ToolAccessError(C_UPSTREAM, "注册目录不可达") from exc

    if server_info.get("deployment") == "local" or server_info.get("is_enabled") is False:
        raise ToolAccessError(C_BAD_TARGET, f"服务 {path} 无可用的网关路由")

    tool_list = server_info.get("tool_list") or []
    entry = None
    for item in tool_list:
        if isinstance(item, dict) and (item.get("name") or item.get("tool_name")) == tool_name:
            entry = item
            break
    if entry is None:
        raise ToolAccessError(
            C_NOT_FOUND, f"服务 {path} 上没有工具 {tool_name}(或该工具未对当前员工开放)")

    schema = _entry_schema(entry)
    if not isinstance(schema, dict):
        raise ToolAccessError(
            C_DEFINITION_MISSING,
            f"工具 {path}/{tool_name} 缺少可用定义(Schema), 拒绝盲调; 请联系管理员")
    # 目录不 check_schema(注册时不校验),坏 Schema(未知 type、解析不了的外链
    # $ref)在这里拦下,归 definition_missing,不让原始异常逃出错误契约。
    try:
        validator_for(schema).check_schema(schema)
    except SchemaError as exc:
        raise ToolAccessError(
            C_DEFINITION_MISSING,
            f"工具 {path}/{tool_name} 的定义不是合法 Schema, 拒绝盲调") from exc
    except Exception as exc:  # referencing 未装/外链 $ref 解析失败等
        raise ToolAccessError(
            C_DEFINITION_MISSING,
            f"工具 {path}/{tool_name} 的定义无法解析(如外链 $ref), 拒绝盲调") from exc
    version = _schema_version(schema)
    if expected_schema_version is not None and expected_schema_version != version:
        raise ToolAccessError(
            C_SCHEMA_CHANGED,
            f"工具 {path}/{tool_name} 的定义已变化"
            f"(期望 {expected_schema_version}, 当前 {version}); "
            "请重新 search_registry_tools 后再调用")

    try:
        validator_for(schema)(schema, registry=Registry()).validate(arguments or {})
    except ValidationError as exc:
        raise ToolAccessError(
            C_INVALID_ARGUMENTS,
            f"参数不符合 {path}/{tool_name} 的定义: {exc.message}") from exc
    except Exception as exc:  # check_schema 过但 validate 阶段仍可能引用失败
        raise ToolAccessError(
            C_DEFINITION_MISSING,
            f"工具 {path}/{tool_name} 的定义无法用于参数校验, 拒绝盲调") from exc

    call_headers = {"X-Authorization": f"Bearer {mcp_token}"}
    mcp_path = f"/{path}" if server_info.get("append_mcp_path") is False else f"/{path}/mcp"
    url = _gateway_endpoint(mcp_path)
    logger.info("invoke_tool: 经数据面调用 %s/%s (员工身份)", path, tool_name)
    try:
        result = await _call_tool_via_data_plane(
            url, call_headers, tool_name, arguments, INVOKE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError as exc:
        raise ToolAccessError(
            C_TIMEOUT,
            f"调用 {path}/{tool_name} 超时({INVOKE_TIMEOUT_SECONDS:g}s), 未自动重试") from exc
    except ToolAccessError:
        raise
    except Exception as exc:  # mcp SDK 的协议/连接错误统一按上游故障归一
        raise ToolAccessError(
            C_UPSTREAM, f"调用 {path}/{tool_name} 失败") from exc

    if result.is_error:
        text = " ".join(_content_texts(getattr(result, "content", None))).strip()
        if _RENEW_HINT in text:
            raise ToolAccessError(C_RENEWAL, text or "业务授权缺失/过期, 请续期后重试")
        if "无权调用工具" in text or "permission denied" in text.lower():
            # 数据面按 params.name 的工具级拒绝文案(gateway 自造,确定性)。
            # 归 permission,不伪装成 upstream 让模型把拒绝当瞬时故障重试。
            raise ToolAccessError(C_PERMISSION, text or "当前员工无权调用该工具")
        raise ToolAccessError(C_UPSTREAM, text or "业务工具返回错误")

    content_blocks = []
    for block in getattr(result, "content", None) or []:
        dump = getattr(block, "model_dump", None)
        content_blocks.append(dump() if callable(dump) else str(block))
    return {
        "status": "success",
        "server_path": path,
        "tool_name": tool_name,
        "content": content_blocks,
        "structured": result.structured_content,
        "schema_version": version,
    }
