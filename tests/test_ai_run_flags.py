"""Fase J6: per-run AI options (pure decision logic).

opt=None (or True) = automatic (run if configured); opt=False = explicit
per-run opt-out; requested-but-unconfigured degrades to classic output.
"""
import pytest

import backend.jev as jev
import backend.local_llm as local_llm
import backend.main as main


@pytest.fixture(autouse=True)
def _both_configured(monkeypatch):
    monkeypatch.setattr(jev, "get_jev_config", lambda: {"enabled": True})
    monkeypatch.setattr(local_llm, "get_local_llm_config",
                        lambda: {"enabled": True})


def test_defaults_run_both_when_configured():
    assert main._ai_run_flags() == (True, True)
    assert main._ai_run_flags(True, True) == (True, True)


def test_explicit_opt_outs():
    assert main._ai_run_flags(False, False) == (False, False)
    assert main._ai_run_flags(None, False) == (True, False)
    assert main._ai_run_flags(False, None) == (False, True)


def test_unconfigured_degrades_to_classic(monkeypatch):
    monkeypatch.setattr(jev, "get_jev_config", lambda: {"enabled": False})
    monkeypatch.setattr(local_llm, "get_local_llm_config",
                        lambda: {"enabled": False})
    # User asked for both, but nothing is configured: classic output.
    assert main._ai_run_flags(True, True) == (False, False)
