"""Tests for the headless CLI (backend/cli.py). No network: PipelineRunner.run and scanner.run_tool are stubbed."""
import io
import json
import re
from contextlib import redirect_stdout

import pytest

import backend.cli as cli


FAKE_RESULT = {
    "mode": "fast",
    "target": "example.com",
    "status": "completed",
    "elapsed_seconds": 1.23,
    "phases": {
        "Recon": {"whois_lookup": {"success": True}, "dns_recon": {"success": False}},
        "Scan": {"port_scanner": {"success": True}},
    },
    "total_tools": 4,
    "findings": [{"id": 1}, {"id": 2}],
    "score": 10,
}


def _stub_run(monkeypatch, result=None):
    async def fake_run(self):
        return dict(result if result is not None else FAKE_RESULT)
    monkeypatch.setattr(cli.PipelineRunner, "run", fake_run)


def test_json_output(monkeypatch, capsys):
    _stub_run(monkeypatch)
    code = cli.main(["--target", "example.com", "--pipeline", "fast", "--json"])
    assert code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["status"] == "completed"
    assert data["score"] == 10
    assert len(data["findings"]) == 2


def test_text_summary(monkeypatch, capsys):
    _stub_run(monkeypatch)
    code = cli.main(["--target", "example.com"])
    assert code == 0
    out = capsys.readouterr().out
    assert "status: completed" in out
    assert "findings: 2" in out
    assert "score: 10" in out
    assert "Recon: 1/2 ok" in out


def test_runner_receives_mode_and_target(monkeypatch, capsys):
    seen = {}

    async def fake_run(self):
        seen["mode"] = self.mode
        seen["target"] = self.target
        return dict(FAKE_RESULT)

    monkeypatch.setattr(cli.PipelineRunner, "run", fake_run)
    code = cli.main(["--target", "example.com ", "--pipeline", "deep"])
    assert code == 0
    capsys.readouterr()
    assert seen["mode"] == "deep"
    assert seen["target"] == "example.com"


def test_invalid_pipeline_mode_rejected(monkeypatch, capsys):
    _stub_run(monkeypatch)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", "example.com", "--pipeline", "bogus"])
    assert exc.value.code == 2


def test_missing_target_rejected(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--pipeline", "fast"])
    assert exc.value.code == 2


def test_invalid_target_exits_nonzero(monkeypatch, capsys):
    _stub_run(monkeypatch)
    code = cli.main(["--target", "   "])
    assert code == 1
    assert "invalid target" in capsys.readouterr().err


def test_failed_pipeline_exits_nonzero(monkeypatch, capsys):
    _stub_run(monkeypatch, result={"error": "boom"})
    code = cli.main(["--target", "example.com"])
    assert code == 1
    err = capsys.readouterr().err
    assert "boom" in err


# ── Single tool runs (--tool) ──────────────────────────────────────

FAKE_TOOL_RESULT = {
    "tool": "dns_recon",
    "target": "example.com",
    "success": True,
    "elapsed_seconds": 0.42,
    "result": {},
    "findings": [{"id": 1}, {"id": 2}, {"id": 3}],
    "score": 7,
}


def _stub_run_tool(monkeypatch, result=None, seen=None):
    async def fake_run_tool(tool_name, target, **kwargs):
        if seen is not None:
            seen["tool"] = tool_name
            seen["target"] = target
        return dict(result if result is not None else FAKE_TOOL_RESULT)
    monkeypatch.setattr(cli.scanner, "run_tool", fake_run_tool)


def test_tool_executes_stub(monkeypatch, capsys):
    seen = {}
    _stub_run_tool(monkeypatch, seen=seen)
    code = cli.main(["--tool", "dns_recon", "--target", " example.com "])
    assert code == 0
    capsys.readouterr()
    assert seen["tool"] == "dns_recon"
    assert seen["target"] == "example.com"


def test_tool_text_summary(monkeypatch, capsys):
    _stub_run_tool(monkeypatch)
    code = cli.main(["--tool", "dns_recon", "--target", "example.com"])
    assert code == 0
    out = capsys.readouterr().out
    assert "tool: dns_recon" in out
    assert "status: ok" in out
    assert "elapsed: 0.42s" in out
    assert "findings: 3" in out
    assert "score: 7" in out


def test_tool_json_output(monkeypatch, capsys):
    _stub_run_tool(monkeypatch)
    code = cli.main(["--tool", "dns_recon", "--target", "example.com", "--json"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["tool"] == "dns_recon"
    assert data["success"] is True
    assert data["score"] == 7


def test_tool_failure_exits_nonzero(monkeypatch, capsys):
    _stub_run_tool(monkeypatch, result={"tool": "dns_recon", "target": "example.com",
                                        "success": False, "error": "boom",
                                        "elapsed_seconds": 0.1, "findings": [], "score": 0})
    code = cli.main(["--tool", "dns_recon", "--target", "example.com"])
    assert code == 1
    assert "boom" in capsys.readouterr().err


def test_tool_unknown_id_exits_2(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--tool", "bogus_tool", "--target", "example.com"])
    assert exc.value.code == 2
    assert "unknown tool" in capsys.readouterr().err


def test_tool_requires_target(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--tool", "dns_recon"])
    assert exc.value.code == 2


def test_tool_and_pipeline_conflict(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--tool", "dns_recon", "--pipeline", "fast", "--target", "example.com"])
    assert exc.value.code == 2
    assert "mutually exclusive" in capsys.readouterr().err


# ── Informational actions (--list-tools / --list-pipelines) ────────

def test_list_tools_includes_known(monkeypatch, capsys):
    def _no_call(*args, **kwargs):
        raise AssertionError("run_tool must not be called for --list-tools")
    monkeypatch.setattr(cli.scanner, "run_tool", _no_call)
    code = cli.main(["--list-tools"])
    assert code == 0
    out = capsys.readouterr().out
    assert "port_scanner" in out
    assert "Port Scanner" in out
    assert "Network Recon" in out


def test_list_tools_sorted_by_category_then_name(capsys):
    cli.main(["--list-tools"])
    out = capsys.readouterr().out
    rows = [re.split(r"  +", line) for line in out.strip().splitlines()[1:]]
    order = {c: i for i, c in enumerate(cli.CATEGORIES)}
    keys = [(order[cat], name) for _tid, name, cat, _desc in rows]
    assert keys == sorted(keys)


def test_list_pipelines_shows_modes_phases_tools(capsys):
    code = cli.main(["--list-pipelines"])
    assert code == 0
    out = capsys.readouterr().out
    assert "nuclear" in out
    assert "full_depth" in out
    assert "Recon" in out
    assert "whois_lookup" in out


def test_list_actions_take_precedence_over_tool(monkeypatch, capsys):
    def _no_call(*args, **kwargs):
        raise AssertionError("run_tool must not be called when --list-tools wins")
    monkeypatch.setattr(cli.scanner, "run_tool", _no_call)
    code = cli.main(["--list-tools", "--tool", "dns_recon"])
    assert code == 0
    assert "port_scanner" in capsys.readouterr().out
