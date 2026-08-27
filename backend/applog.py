"""Structured logging for sec-dashboard.

Replaces ad-hoc print() calls with leveled loggers writing to a rotating file
plus stdout, so production (Railway) has real diagnostics: timestamps, levels,
logger names and bounded on-disk history.

Configuration (env vars, all optional):
  LOG_LEVEL — DEBUG / INFO / WARNING / ERROR (default INFO; invalid -> INFO).
  LOG_DIR   — directory for the rotating log file (default <data>/logs).

Usage:
    from backend.applog import get_logger, setup_logging
    log = get_logger("main")          # logger named "sec_dashboard.main"
    setup_logging()                   # idempotent; call once at process start

All project loggers live under the "sec_dashboard" namespace so library noise
(aiohttp, uvicorn, ...) never lands in our file.
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from backend.config import DATA_DIR

_LOGGER_NAME = "sec_dashboard"
LOG_FILE_NAME = "sec-dashboard.log"
MAX_BYTES = 5 * 1024 * 1024   # rotate at 5 MB
BACKUP_COUNT = 3             # keep sec-dashboard.log.{1..3}
_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

_LEVELS = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
}


def resolve_level(level: str | int | None = None) -> int:
    """Resolve a level from arg/env/default. Invalid or unknown -> INFO."""
    if level is None:
        level = os.environ.get("LOG_LEVEL", "")
    if isinstance(level, int):
        return level
    return _LEVELS.get(str(level).upper(), logging.INFO)


def resolve_log_dir(log_dir: "str | Path | None" = None) -> Path:
    """Resolve the log directory from arg/env/default."""
    if log_dir is not None:
        return Path(log_dir)
    env_dir = os.environ.get("LOG_DIR")
    if env_dir:
        return Path(env_dir)
    return DATA_DIR / "logs"


def setup_logging(log_dir: "str | Path | None" = None, level: "str | int | None" = None) -> logging.Logger:
    """Configure the 'sec_dashboard' logger.

    Idempotent in effect: reconfigures (removes then adds handlers), so any
    number of calls always leaves exactly one rotating file handler plus one
    stdout stream handler on the namespace logger.
    """
    directory = resolve_log_dir(log_dir)
    directory.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(_LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        try:
            handler.close()
        except Exception:
            pass

    file_handler = RotatingFileHandler(directory / LOG_FILE_NAME, maxBytes=MAX_BYTES,
                                       backupCount=BACKUP_COUNT, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(_FORMAT))
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter(_FORMAT))

    logger.setLevel(resolve_level(level))
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    # Children propagate to this logger; never duplicate on the root.
    logger.propagate = True
    return logger


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger, e.g. get_logger('main') -> 'sec_dashboard.main'."""
    if not name.startswith(_LOGGER_NAME):
        name = f"{_LOGGER_NAME}.{name}"
    return logging.getLogger(name)
