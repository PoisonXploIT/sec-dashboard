"""Deterministic triage over stored Jev verdicts (Fase J4).

Pure function module: no network, no I/O. Single source of truth for the four
action buckets rendered in the UI and every export. Thresholds are named
constants on purpose (same auditability rule as the jev.py questions): change
them here, with tests — never from a free-text interface.

Buckets (decision approved 2026-09-20, see SEGUIMIENTO.md "J4/J5"):
- immediate : true_positive with trusted confidence AND urgency
              (immediate_action >= ACTION_IMMEDIATE) or high severity
              (severity_score >= SEV_IMMEDIATE).
- scheduled : true_positive with trusted confidence, not urgent.
- review    : confidence in [CONF_REVIEW, CONF_TRUST) — any verdict; a human
              decides. Also the defensive bucket for unknown verdict labels
              that carry trusted confidence.
- none      : false_positive / noise with trusted confidence.

Verdicts with confidence < CONF_REVIEW are hidden (J0 rule): triage returns
None and the UI/exports omit them entirely.
"""
from __future__ import annotations

IMMEDIATE = "immediate"
SCHEDULED = "scheduled"
REVIEW = "review"
NONE = "none"

BUCKET_LABELS_ES = {
    IMMEDIATE: "ACCION INMEDIATA",
    SCHEDULED: "ACCION PROGRAMADA",
    REVIEW: "REVISION MANUAL",
    NONE: "SIN ACCION",
}

# Confidence bands (validated in Fase J0: >=0.5 trust, 0.3-0.5 review, <0.3 hide).
CONF_TRUST = 0.5
CONF_REVIEW = 0.3
# Urgency triggers for the immediate bucket.
ACTION_IMMEDIATE = 0.5
SEV_IMMEDIATE = 2.0


def _num(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def triage_bucket(verdict, confidence, severity_score, immediate_action) -> str | None:
    """Classify one stored Jev verdict into an action bucket (None = hidden)."""
    conf = _num(confidence)
    if conf < CONF_REVIEW:
        return None  # J0 rule: low-confidence verdicts are not shown or acted on.
    if conf < CONF_TRUST:
        return REVIEW
    v = str(verdict or "").strip().lower()
    if v == "true_positive":
        sev = _num(severity_score)
        action = _num(immediate_action)
        if action >= ACTION_IMMEDIATE or sev >= SEV_IMMEDIATE:
            return IMMEDIATE
        return SCHEDULED
    if v in ("false_positive", "noise"):
        return NONE
    return REVIEW  # unknown label but trusted confidence: a human looks.


def triage_summary(buckets: list[str | None]) -> dict[str, int]:
    """Count buckets; None (hidden) and unknown values are not counted."""
    counts = {IMMEDIATE: 0, SCHEDULED: 0, REVIEW: 0, NONE: 0}
    for b in buckets:
        if b in counts:
            counts[b] += 1
    return counts
