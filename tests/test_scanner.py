"""Tests for the scanner dispatcher (backend/scanner.py). No network."""
import asyncio

from backend import scanner


def _run(coro):
    return asyncio.run(coro)


def test_unknown_tool_returns_error():
    res = _run(scanner.run_tool("no_such_tool", "example.com"))
    assert res["success"] is False
    assert "Unknown tool" in res["error"]


def test_ok_dispatch(monkeypatch):
    async def fake(target, **kw):
        return {"echo": target}

    monkeypatch.setitem(scanner.HANDLERS, "fake_tool", fake)
    monkeypatch.setitem(scanner.TOOLS, "fake_tool", {"timeout": 5})

    res = _run(scanner.run_tool("fake_tool", "example.com"))
    assert res["success"] is True
    assert res["tool"] == "fake_tool"
    assert res["result"]["echo"] == "example.com"
    assert "elapsed_seconds" in res


def test_exception_is_captured_without_traceback(monkeypatch):
    async def boom(target, **kw):
        raise RuntimeError("kaboom")

    monkeypatch.setitem(scanner.HANDLERS, "boom_tool", boom)
    monkeypatch.setitem(scanner.TOOLS, "boom_tool", {"timeout": 5})

    res = _run(scanner.run_tool("boom_tool", "example.com"))
    assert res["success"] is False
    assert res["error"] == "kaboom"
    # M1: never leak tracebacks to the client
    assert "Traceback" not in res["error"]


def test_timeout_is_enforced(monkeypatch):
    async def slow(target, **kw):
        await asyncio.sleep(5)
        return {}

    monkeypatch.setitem(scanner.HANDLERS, "slow_tool", slow)
    monkeypatch.setitem(scanner.TOOLS, "slow_tool", {"timeout": 0.1})

    res = _run(scanner.run_tool("slow_tool", "example.com"))
    assert res["success"] is False
    assert "Timed out" in res["error"]


def test_run_parallel_returns_one_result_per_tool(monkeypatch):
    async def fake(target, **kw):
        return {"tool_seen": target}

    monkeypatch.setitem(scanner.HANDLERS, "fake_a", fake)
    monkeypatch.setitem(scanner.HANDLERS, "fake_b", fake)
    monkeypatch.setitem(scanner.TOOLS, "fake_a", {"timeout": 5})
    monkeypatch.setitem(scanner.TOOLS, "fake_b", {"timeout": 5})

    results = _run(scanner.run_parallel(["fake_a", "fake_b"], "example.com"))
    assert len(results) == 2
    assert all(r["success"] for r in results)
    assert {r["tool"] for r in results} == {"fake_a", "fake_b"}
