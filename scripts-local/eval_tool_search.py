#!/usr/bin/env python3
"""AI Registry Tools 检索评估 runner(V7 §10 骨架)。

对冻结查询集逐条调用网关 mcpgw 的 search_registry_tools,按预期工具判定命中,
输出命中率(带 Wilson 95% 区间)、首命中排名(MRR)与越权断言(结果里出现
persona 无权服务即违规,必须为 0)。dev 冒烟与 P4 正式评估共用本 runner:
正式评估只换更大的冻结查询文件,不改代码。

冻结查询文件格式(JSON):
{
  "personas": {
    "test-hr":   {"token_file": "test-hr.jwt", "deny_servers": ["data-mcp"]},
    "test-other":{"token_file": "test-other.jwt", "deny_servers": ["hr-mcp"]}
  },
  "cases": [
    {"query": "查员工", "expect_any": ["search_employees"]},
    {"query": "绩效考核详情", "expect_any": ["get_performance_detail"]},
    {"query": "完全无关的查询词组xyzzy", "expect_any": []}
  ]
}

expect_any 为空表示预期 no_match(结果里不得出现任何 hr/data 工具)。
WORKBUDDY_TOKEN_DIR 指向本地 JWT 文件目录，默认 ~/.workbuddy-tokens。
WORKBUDDY_GATEWAY_MCP_URL 指向要评估的网关 MCP 地址。
Usage:
  .venv/Scripts/python.exe scripts-local/eval_tool_search.py \
      --queries tests/fixtures/workbuddy/eval-queries-v2.json --out <报告目录>
"""

import argparse
import asyncio
import json
import logging
import math
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s,p%(process)s,{%(filename)s:%(lineno)d},%(levelname)s,%(message)s",
)
logger = logging.getLogger("eval_tool_search")

GATEWAY_MCP_URL = os.getenv(
    "WORKBUDDY_GATEWAY_MCP_URL", "http://127.0.0.1:7860/airegistry-tools/mcp"
)
SEARCH_TOOL = "search_registry_tools"
WILSON_Z = 1.96

def _wilson_interval(
    successes: int,
    total: int,
    z: float = WILSON_Z,
) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion, clamped to [0, 1]."""
    if total <= 0:
        return (0.0, 0.0)
    p = successes / total
    denom = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return (max(0.0, center - margin), min(1.0, center + margin))


def _evaluate_case(
    case: dict[str, Any],
    results: list[dict[str, Any]],
    deny_servers: list[str],
) -> dict[str, Any]:
    """单条用例判定:命中、首命中排名、泄漏(无权服务工具出现即违规)。"""
    got_names = [r.get("tool_name", "") for r in results]
    got_servers = [r.get("server_path", "") for r in results]
    expect_any = case.get("expect_any") or []
    rank = next((i + 1 for i, name in enumerate(got_names) if name in expect_any), None)
    hit = rank is not None
    leaks = sorted({s.strip("/") for s, n in zip(got_servers, got_names)
                    if s in deny_servers or s.strip("/") in deny_servers})
    no_match_expected = not expect_any
    honest_empty = no_match_expected and not results
    return {
        "query": case["query"],
        "hit": hit or honest_empty,
        "rank": rank,
        "leak": leaks,
        "got": got_names[:5],
        "status": "leak" if leaks else ("hit" if hit else
                                        ("no_match_ok" if honest_empty else "miss")),
    }


def _load_queries(path: Path) -> dict[str, Any]:
    spec = json.loads(path.read_text(encoding="utf-8"))
    # cases 可以为空: persona 各自带 cases(v2 格式), 此时全局 cases 缺省。
    if not spec.get("personas"):
        raise SystemExit(f"冻结查询文件缺少 personas: {path}")
    return spec


def _cases_for(persona: dict[str, Any], spec: dict[str, Any]) -> list[dict[str, Any]]:
    """该 persona 的用例: 优先 persona 自己的 cases(不同权限角色的用例集不同),
    缺省回退全局 cases(两角色共用一套)。"""
    return persona.get("cases") or spec.get("cases") or []


async def _run_persona(
    label: str,
    persona: dict[str, Any],
    cases: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    import httpx2
    from mcp import Client
    from mcp.client.streamable_http import streamable_http_client

    token_dir = Path(os.getenv("WORKBUDDY_TOKEN_DIR", Path.home() / ".workbuddy-tokens"))
    token_file = token_dir / persona["token_file"]
    token = token_file.read_text(encoding="utf-8").strip()
    rows: list[dict[str, Any]] = []
    async with httpx2.AsyncClient(
        headers={"X-Authorization": f"Bearer {token}"},
        follow_redirects=False,
        trust_env=False,
    ) as http_client:
        transport = streamable_http_client(GATEWAY_MCP_URL, http_client=http_client)
        async with Client(transport, mode="auto", cache=None) as session:
            for case in cases:
                result = await session.call_tool(
                    SEARCH_TOOL, {"query": case["query"]})
                if result.is_error:
                    rows.append({"query": case["query"], "status": "tool_error",
                                 "hit": False, "rank": None, "leak": [],
                                 "got": [result.content[0].text[:120]]})
                    continue
                data = result.structured_content or json.loads(result.content[0].text)
                if data.get("status") not in {"success", "no_match"}:
                    rows.append({"query": case["query"], "status": data.get("status", "tool_error"),
                                 "hit": False, "rank": None, "leak": [], "got": []})
                    continue
                rows.append(_evaluate_case(
                    case, data.get("results", []),
                    persona.get("deny_servers") or []))
    logger.info("persona %s: %d cases done", label, len(rows))
    return rows


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    hits = sum(1 for r in rows if r["hit"])
    lo, hi = _wilson_interval(hits, len(rows))
    ranks = [r["rank"] for r in rows if r["rank"]]
    mrr = sum(1.0 / rk for rk in ranks) / len(rows) if rows else 0.0
    return {"hits": hits, "total": len(rows), "wilson95": [round(lo, 4), round(hi, 4)],
            "mrr": round(mrr, 4), "leaks": sum(len(r["leak"]) for r in rows)}


def _write_report(
    out_dir: Path,
    per_persona: dict[str, list[dict[str, Any]]],
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# 工具检索评估报告({date.today().isoformat()})",
        "",
        "| persona | 命中/总数 | Wilson 95% | MRR | 越权 |",
        "|---|---|---|---|---|",
    ]
    for label, rows in per_persona.items():
        s = _summarize(rows)
        lines.append(f"| {label} | {s['hits']}/{s['total']} | "
                     f"[{s['wilson95'][0]}, {s['wilson95'][1]}] | {s['mrr']} | "
                     f"{s['leaks']} |")
    violations = sum(_summarize(rows)["leaks"] for rows in per_persona.values())
    lines += ["", f"**越权断言: {'PASS (0 泄漏)' if violations == 0 else f'FAIL ({violations} 泄漏)'}**",
              "", "## 明细", ""]
    for label, rows in per_persona.items():
        lines.append(f"### {label}")
        for r in rows:
            lines.append(f"- {r['status']:>12} | {r['query']} | {','.join(r['got']) or '(空)'}")
    report = out_dir / f"eval-report-{date.today().isoformat()}.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    raw = out_dir / f"eval-raw-{date.today().isoformat()}.json"
    raw.write_text(json.dumps(per_persona, ensure_ascii=False, indent=2),
                   encoding="utf-8")
    return report


async def _run(args: argparse.Namespace) -> int:
    spec = _load_queries(Path(args.queries))
    per_persona: dict[str, list[dict[str, Any]]] = {}
    for label, persona in spec["personas"].items():
        per_persona[label] = await _run_persona(label, persona, _cases_for(persona, spec))
    for label, rows in per_persona.items():
        s = _summarize(rows)
        logger.info("%s: %d/%d hits, wilson95=%s, leaks=%d",
                    label, s["hits"], s["total"], s["wilson95"], s["leaks"])
    report = _write_report(Path(args.out), per_persona)
    print(f"report: {report}")
    total_leaks = sum(_summarize(rows)["leaks"] for rows in per_persona.values())
    return 1 if total_leaks else 0


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI Registry Tools 检索评估 runner(命中率 + Wilson 区间 + 越权断言)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  .venv/Scripts/python.exe scripts-local/eval_tool_search.py"
            " --queries tests/fixtures/workbuddy/eval-queries-v2.json\n"
            "  .venv/Scripts/python.exe scripts-local/eval_tool_search.py"
            " --queries <冻结查询.json> --out .scratchpad/tool-discovery/eval\n"
        ),
    )
    parser.add_argument("--queries", required=True, help="冻结查询 JSON 文件")
    parser.add_argument("--out", default=".scratchpad/tool-discovery/eval",
                        help="报告输出目录")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    sys.exit(main())
