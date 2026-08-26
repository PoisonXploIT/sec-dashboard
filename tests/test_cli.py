"""Tests for the headless CLI (backend/cli.py). No network: PipelineRunner.run is stubbed."""
import io
import json
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
