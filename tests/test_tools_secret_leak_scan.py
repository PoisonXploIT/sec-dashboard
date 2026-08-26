"""F1-SECRETS: secret_leak_scan tool + findings adapter (no network)."""
import asyncio
from urllib.parse import urlparse

import backend.findings as findings
import backend.tools.web as web


def _run(coro):
    return asyncio.run(coro)


AWS_KEY = "AKIA" + "B" * 16
GITHUB_TOKEN = "ghp_" + "a" * 36
# Built from parts so no contiguous token-shaped literal exists in the file
# (GitHub push protection would block the commit).
SLACK_TOKEN = "xoxb" + "-123456789012-123456789012-" + "aBcDeFgHiJkLmNoP"
STRIPE_KEY = "sk_live_" + "C" * 24
GOOGLE_KEY = "AIza" + "D" * 35


def _pattern_ids():
    return {p[0]: (p[1], p[2]) for p in web._SECRET_PATTERNS}


# ── pattern table ──────────────────────────────────────────────
def test_patterns_platform_keys_high_tier():
    ids = _pattern_ids()
    assert ids["aws_access_key_id"][0] == "high"
    assert ids["github_token"][0] == "high"
    assert ids["slack_token"][0] == "high"
    assert ids["stripe_key"][0] == "high"
    assert ids["google_api_key"][0] == "high"
    assert ids["private_key"][0] == "high"
    for sample in (AWS_KEY, ASIA := "ASIA" + "9" * 16, GITHUB_TOKEN, "github_pat_" + "e" * 32,
                  SLACK_TOKEN, STRIPE_KEY, "whsec_" + "f" * 20, GOOGLE_KEY,
                  "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----"):
        assert any(rx.search(sample) for _t, _s, rx in web._SECRET_PATTERNS), sample


def test_patterns_generic_and_weak_tiers():
    ids = _pattern_ids()
    assert ids["generic_token"][0] == "medium"
    assert ids["weak_match"][0] == "low"
    generic, weak = ids["generic_token"][1], ids["weak_match"][1]
    assert generic.search('api_key="abcdef1234567890"')
    assert generic.search("auth_token: 'A1b2C3d4E5f6G7h8'")
    assert weak.search('password = "SuperSecret123"')
    # A bare AKIA id must NOT be classified as a generic/weak match.
    assert not generic.search(f"aws_access_key_id = '{AWS_KEY}'")
    assert not weak.search(AWS_KEY)


def test_redaction_hides_the_secret():
    assert web._redact(AWS_KEY) == "AKIA***(20)"
    assert web._redact("x") == "***"
    assert web._redact("abcdef1234567890") == "abcd***(16)"


# ── handler (stubbed HTTP) ──────────────────────────────────────
def _stub(monkeypatch, bodies):
    """bodies: {path: (status, text)}; everything else is a 404."""
    async def fake_fetch(url, session):
        path = urlparse(url).path
        if path in bodies:
            return bodies[path]
        return 404, ""

    monkeypatch.setattr(web, "_secret_fetch", fake_fetch)


def test_handler_exposed_git_is_flagged(monkeypatch):
    _stub(monkeypatch, {
        "/.git/HEAD": (200, "ref: refs/heads/main\n"),
        "/.git/config": (200, "[core]\n\trepositoryformatversion = 1\n"),
        "/robots.txt": (404, ""),
    })
    result = _run(web.secret_leak_scan("example.com"))
    assert result["git_exposed_paths"] == ["/.git/HEAD", "/.git/config"]
    assert result["findings"] == []
    assert result["count"] == 2


def test_handler_js_key_high_tier_and_redacted(monkeypatch):
    _stub(monkeypatch, {"/main.js": (200, f'const key = "{AWS_KEY}";')})
    result = _run(web.secret_leak_scan("example.com"))
    assert result["count"] == 1
    f = result["findings"][0]
    assert f["type"] == "aws_access_key_id"
    assert f["tier"] == "high"
    assert f["source"].endswith("/main.js")
    assert AWS_KEY not in str(result)  # evidence is redacted


def test_handler_robots_token_medium_tier(monkeypatch):
    _stub(monkeypatch, {"/robots.txt": (200, 'User-agent: *\n# api_key="abcdef1234567890"\n')})
    result = _run(web.secret_leak_scan("example.com"))
    assert result["count"] == 1
    f = result["findings"][0]
    assert f["type"] == "generic_token"
    assert f["tier"] == "medium"
    assert f["source"].endswith("/robots.txt")


def test_handler_clean_target_no_findings(monkeypatch):
    _stub(monkeypatch, {})
    result = _run(web.secret_leak_scan("example.com"))
    assert result["count"] == 0
    assert result["findings"] == []
    assert result["git_exposed_paths"] == []
    assert result["js_urls_checked"] == len(web._SECRET_JS_PATHS)
    assert result["robots_checked"] is False


def test_handler_rejects_ip_target():
    result = _run(web.secret_leak_scan("10.0.0.5"))
    assert "error" in result


def test_handler_normalizes_url_input(monkeypatch):
    _stub(monkeypatch, {})
    result = _run(web.secret_leak_scan("https://Example.com:8443/path?q=1"))
    assert result["target"] == "example.com"


# ── shared session (real _secret_fetch, fake aiohttp) ─────────
class _FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def text(self, errors=None):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    """Stands in for aiohttp.ClientSession; records how many are created."""
    instances = 0
    bodies: dict = {}

    def __init__(self, *args, **kwargs):
        _FakeSession.instances += 1
        self.requests: list[str] = []

    def get(self, url, **kwargs):
        self.requests.append(url)
        path = urlparse(url).path
        behavior = _FakeSession.bodies.get(path, (404, ""))
        if isinstance(behavior, Exception):
            raise behavior
        return _FakeResponse(*behavior)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def test_handler_opens_one_shared_session_for_all_urls(monkeypatch):
    _FakeSession.instances = 0
    _FakeSession.bodies = {"/main.js": (200, f'const key = "{AWS_KEY}";')}
    monkeypatch.setattr(web.aiohttp, "ClientSession", _FakeSession)
    result = _run(web.secret_leak_scan("example.com"))
    assert _FakeSession.instances == 1
    assert result["count"] == 1
    assert result["findings"][0]["type"] == "aws_access_key_id"


def test_handler_shared_session_survives_fetch_errors(monkeypatch):
    _FakeSession.instances = 0
    _FakeSession.bodies = {
        "/main.js": RuntimeError("boom"),
        "/robots.txt": (200, 'api_key="abcdef1234567890"\n'),
    }
    monkeypatch.setattr(web.aiohttp, "ClientSession", _FakeSession)
    result = _run(web.secret_leak_scan("example.com"))
    assert _FakeSession.instances == 1
    # the failing URL degrades to not-found; the rest of the scan completes
    assert result["count"] == 1
    assert result["findings"][0]["type"] == "generic_token"


# ── _scan_text: multiple matches + position dedup ────────────
def test_scan_text_reports_multiple_secrets_in_one_file():
    found: list[dict] = []
    text = f'const a = "{AWS_KEY}";\nconst b = "{GITHUB_TOKEN}";'
    web._scan_text(text, "/main.js", found)
    assert [f["type"] for f in found] == ["aws_access_key_id", "github_token"]
    assert all(f["tier"] == "high" for f in found)


def test_scan_text_dedups_overlapping_positions():
    # The AWS key inside a quoted assignment is also caught by generic_token;
    # the overlapping span must be reported once (high tier wins).
    found: list[dict] = []
    web._scan_text(f'password = "{AWS_KEY}"', "/main.js", found)
    assert len(found) == 1
    assert found[0]["type"] == "aws_access_key_id"


def test_scan_text_clean_text_no_findings():
    found: list[dict] = []
    web._scan_text("var x = 1; // nothing secret here", "/main.js", found)
    assert found == []


# ── findings adapter ───────────────────────────────────────────
def test_adapter_git_exposed_critical_and_dedup():
    result = {
        "git_exposed_paths": ["/.git/HEAD", "/.git/config", "/.git/HEAD"],
        "findings": [],
    }
    out = findings.extract_findings("secret_leak_scan", result, "example.com")
    assert len(out) == 2
    assert all(f.severity == findings.Severity.CRITICAL for f in out)


def test_adapter_tiers_and_empty():
    result = {
        "git_exposed_paths": [],
        "findings": [
            {"source": "/main.js", "type": "aws_access_key_id", "tier": "high", "evidence": "AKIA***(20)"},
            {"source": "/main.js", "type": "aws_access_key_id", "tier": "high", "evidence": "AKIA***(20)"},
            {"source": "/robots.txt", "type": "generic_token", "tier": "medium", "evidence": "abcd***(16)"},
            {"source": "/app.js", "type": "weak_match", "tier": "low", "evidence": "pass***(14)"},
        ],
    }
    out = findings.extract_findings("secret_leak_scan", result, "example.com")
    assert len(out) == 3  # duplicate dropped
    assert [f.severity for f in out] == [
        findings.Severity.HIGH, findings.Severity.MEDIUM, findings.Severity.LOW,
    ]
    assert findings.extract_findings("secret_leak_scan", {}, "x") == []
