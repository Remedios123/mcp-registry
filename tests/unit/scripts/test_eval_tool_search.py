"""eval_tool_search 的纯逻辑单元测试(Wilson 区间、用例判定、越权检测)。"""

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts-local" / "eval_tool_search.py"
_spec = importlib.util.spec_from_file_location("eval_tool_search", _SCRIPT)
mod = importlib.util.module_from_spec(_spec)
sys.modules["eval_tool_search"] = mod
_spec.loader.exec_module(mod)


class TestWilsonInterval:
    def test_zero_total_returns_zero(self):
        assert mod._wilson_interval(0, 0) == (0.0, 0.0)

    def test_perfect_score_not_degenerate(self):
        lo, hi = mod._wilson_interval(10, 10)
        assert 0.7 < lo < 1.0 and hi == 1.0

    def test_zero_score_not_degenerate(self):
        lo, hi = mod._wilson_interval(0, 10)
        assert lo == 0.0 and 0.0 < hi < 0.35

    def test_monotonic_in_successes(self):
        lo_a, hi_a = mod._wilson_interval(5, 10)
        lo_b, hi_b = mod._wilson_interval(7, 10)
        assert lo_b > lo_a and hi_b > hi_a

    def test_interval_contains_point_estimate(self):
        lo, hi = mod._wilson_interval(6, 10)
        assert lo < 0.6 < hi


class TestEvaluateCase:
    BASE = {"query": "q", "expect_any": ["t1"]}

    def test_hit_records_rank(self):
        results = [{"tool_name": "t2", "server_path": "/s"},
                   {"tool_name": "t1", "server_path": "/s"}]
        row = mod._evaluate_case(dict(self.BASE), results, deny_servers=[])
        assert row["hit"] is True and row["rank"] == 2 and row["leak"] == []

    def test_miss_when_expected_absent(self):
        results = [{"tool_name": "t2", "server_path": "/s"}]
        row = mod._evaluate_case(dict(self.BASE), results, deny_servers=[])
        assert row["hit"] is False and row["status"] == "miss"

    def test_leak_on_denied_server(self):
        results = [{"tool_name": "t1", "server_path": "/hr-mcp"}]
        row = mod._evaluate_case(dict(self.BASE), results, deny_servers=["hr-mcp"])
        assert row["leak"] == ["hr-mcp"]
        assert row["status"] == "leak"

    def test_leak_tolerates_slash_forms(self):
        results = [{"tool_name": "t1", "server_path": "hr-mcp"}]
        row = mod._evaluate_case(dict(self.BASE), results, deny_servers=["hr-mcp"])
        assert row["leak"] == ["hr-mcp"]

    def test_empty_expect_any_with_empty_results_is_honest(self):
        case = {"query": "x", "expect_any": []}
        row = mod._evaluate_case(case, [], deny_servers=[])
        assert row["hit"] is True and row["status"] == "no_match_ok"

    def test_empty_expect_any_with_results_is_miss(self):
        case = {"query": "x", "expect_any": []}
        results = [{"tool_name": "t1", "server_path": "/s"}]
        row = mod._evaluate_case(case, results, deny_servers=[])
        assert row["hit"] is False and row["status"] == "miss"


class TestSummarize:
    def test_leak_count_aggregated(self):
        rows = [{"hit": True, "rank": 1, "leak": ["hr-mcp"], "status": "leak"},
                {"hit": True, "rank": None, "leak": [], "status": "hit"}]
        s = mod._summarize(rows)
        assert s["leaks"] == 1 and s["hits"] == 2 and s["total"] == 2

    def test_mrr_uses_first_hit_rank(self):
        rows = [{"hit": True, "rank": 2, "leak": [], "status": "hit"},
                {"hit": True, "rank": 1, "leak": [], "status": "hit"}]
        assert mod._summarize(rows)["mrr"] == pytest.approx(0.75)



class TestCasesFor:
    SPEC = {"personas": {}, "cases": [{"query": "global", "expect_any": []}]}

    def test_persona_own_cases_win(self):
        persona = {"token_file": ".t",
                   "cases": [{"query": "own", "expect_any": ["x"]}]}
        chosen = mod._cases_for(persona, self.SPEC)
        assert chosen == [{"query": "own", "expect_any": ["x"]}]

    def test_fallback_to_global_cases(self):
        persona = {"token_file": ".t"}
        chosen = mod._cases_for(persona, self.SPEC)
        assert chosen == [{"query": "global", "expect_any": []}]

    def test_both_missing_gives_empty(self):
        chosen = mod._cases_for({}, {})
        assert chosen == []
