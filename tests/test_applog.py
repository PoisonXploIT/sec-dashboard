"""Tests for backend/applog.py — structured logging (no network)."""
import logging
from pathlib import Path

from backend import applog


def _file_path(tmp_path: Path) -> Path:
    return tmp_path / applog.LOG_FILE_NAME


def test_setup_creates_file_and_stream_handlers(tmp_path):
    logger = applog.setup_logging(log_dir=tmp_path)
    assert logger.name == "sec_dashboard"
    # RotatingFileHandler is a StreamHandler subclass: check exact types.
    handlers = list(logger.handlers)
    assert len(handlers) == 2
    assert any(isinstance(h, logging.handlers.RotatingFileHandler) for h in handlers)
    plain_streams = [h for h in handlers if type(h) is logging.StreamHandler]
    assert len(plain_streams) == 1
    fh = next(h for h in handlers if isinstance(h, logging.handlers.RotatingFileHandler))
    assert Path(fh.baseFilename) == _file_path(tmp_path)
    # Rotating with the documented bounds.
    assert isinstance(fh, logging.handlers.RotatingFileHandler)
    assert fh.maxBytes == applog.MAX_BYTES == 5 * 1024 * 1024
    assert fh.backupCount == applog.BACKUP_COUNT == 3
    # The file exists from the first setup.
    assert _file_path(tmp_path).exists()


def test_setup_is_idempotent_no_duplicate_handlers(tmp_path):
    logger = applog.setup_logging(log_dir=tmp_path)
    applog.setup_logging(log_dir=tmp_path)
    handlers = list(logger.handlers)
    assert len(handlers) == 2  # still one file + one stream, no duplicates
    # Writes still land exactly once in the file.
    child = applog.get_logger("idempotency")
    child.info("single-write-marker")
    content = _file_path(tmp_path).read_text(encoding="utf-8")
    assert content.count("single-write-marker") == 1


def test_namespaced_logger_writes_to_file_with_metadata(tmp_path):
    applog.setup_logging(log_dir=tmp_path)
    child = applog.get_logger("main")
    assert child.name == "sec_dashboard.main"
    child.info("marker-line scan_id=%d", 7)
    line = next(
        l for l in _file_path(tmp_path).read_text(encoding="utf-8").splitlines()
        if "marker-line" in l
    )
    # Format: timestamp | LEVEL | logger name | message (structured, greppable).
    assert "| INFO" in line
    assert "| sec_dashboard.main | marker-line scan_id=7" in line


def test_level_from_env_debug(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    applog.setup_logging(log_dir=tmp_path)
    child = applog.get_logger("level_test")
    child.debug("debug-marker")
    content = _file_path(tmp_path).read_text(encoding="utf-8")
    assert "debug-marker" in content


def test_level_default_info_drops_debug(tmp_path, monkeypatch):
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    applog.setup_logging(log_dir=tmp_path)
    child = applog.get_logger("level_test")
    child.debug("nope-debug")
    child.info("yes-info")
    content = _file_path(tmp_path).read_text(encoding="utf-8")
    assert "nope-debug" not in content
    assert "yes-info" in content


def test_invalid_level_falls_back_to_info(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "BOGUS")
    logger = applog.setup_logging(log_dir=tmp_path)
    assert logger.level == logging.INFO
    # Direct arg form too.
    assert applog.resolve_level("BOGUS") == logging.INFO
    assert applog.resolve_level("WARNING") == logging.WARNING
    assert applog.resolve_level(logging.ERROR) == logging.ERROR


def test_resolve_log_dir_env(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    assert applog.resolve_log_dir() == tmp_path
    # Explicit arg wins over env.
    other = tmp_path / "other"
    assert applog.resolve_log_dir(other) == other


def test_reconfigure_switches_directory(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    applog.setup_logging(log_dir=a)
    child = applog.get_logger("reconf")
    child.info("in-a")
    applog.setup_logging(log_dir=b)
    child.info("in-b")
    assert "in-a" in (a / applog.LOG_FILE_NAME).read_text(encoding="utf-8")
    assert "in-b" in (b / applog.LOG_FILE_NAME).read_text(encoding="utf-8")
