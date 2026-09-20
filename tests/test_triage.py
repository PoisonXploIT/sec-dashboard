"""Fase J4a: deterministic triage buckets over stored Jev verdicts."""
from backend import triage


def test_tp_urgent_by_action_is_immediate():
    assert triage.triage_bucket("true_positive", 0.9, 1.0, 0.8) == triage.IMMEDIATE


def test_tp_urgent_by_severity_is_immediate():
    assert triage.triage_bucket("true_positive", 0.6, 2.5, 0.1) == triage.IMMEDIATE


def test_tp_not_urgent_is_scheduled():
    assert triage.triage_bucket("true_positive", 0.8, 1.0, 0.2) == triage.SCHEDULED


def test_fp_and_noise_trusted_are_none():
    assert triage.triage_bucket("false_positive", 0.9, 0.5, 0.1) == triage.NONE
    assert triage.triage_bucket("noise", 0.7, 0.2, 0.0) == triage.NONE


def test_mid_confidence_any_verdict_is_review():
    for v in ("true_positive", "false_positive", "noise"):
        assert triage.triage_bucket(v, 0.4, 3.0, 0.9) == triage.REVIEW


def test_low_confidence_is_hidden():
    assert triage.triage_bucket("true_positive", 0.29, 3.0, 0.9) is None
    assert triage.triage_bucket("noise", 0.0, 0.0, 0.0) is None


def test_unknown_verdict_trusted_is_review():
    assert triage.triage_bucket("weird_label", 0.9, 1.0, 0.1) == triage.REVIEW


def test_missing_fields_default_to_zero():
    # severity/action missing: a trusted tp is scheduled, not immediate.
    assert triage.triage_bucket("true_positive", 0.9, None, None) == triage.SCHEDULED


def test_boundary_values():
    # conf exactly 0.5 is trusted; exactly 0.3 is review (not hidden).
    assert triage.triage_bucket("true_positive", 0.5, 1.0, 0.0) == triage.SCHEDULED
    assert triage.triage_bucket("true_positive", 0.3, 1.0, 0.0) == triage.REVIEW
    # action exactly 0.5 / sev exactly 2.0 trigger immediate.
    assert triage.triage_bucket("true_positive", 0.9, 1.0, 0.5) == triage.IMMEDIATE
    assert triage.triage_bucket("true_positive", 0.9, 2.0, 0.0) == triage.IMMEDIATE


def test_summary_counts_only_known_buckets():
    counts = triage.triage_summary(
        [triage.IMMEDIATE, triage.IMMEDIATE, triage.REVIEW, None, "bogus"])
    assert counts == {"immediate": 2, "scheduled": 0, "review": 1, "none": 0}
