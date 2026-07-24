"""
logger.py — Structured application logging.

Provides a single pre-configured logger instance used throughout the app.
Log records are emitted as JSON-style key=value pairs so they can be easily
parsed by log aggregators (ELK, Datadog, CloudWatch, etc.).

Phase 7 additions:
  - audit_log()      : structured who/what/when audit trail
  - security_event() : dedicated security incident logging
  - Optional rotating file handler (LOG_FILE in .env)
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from config import LOG_LEVEL, LOG_FILE


class StructuredFormatter(logging.Formatter):
    """
    Formats each log record as a flat key=value string.
    Example:
        2026-07-23 18:30:00,123 | LEVEL=INFO | event=startup msg=Application started
    """

    def format(self, record: logging.LogRecord) -> str:
        level = record.levelname
        ts = self.formatTime(record, self.datefmt)
        msg = record.getMessage()

        # Collect any extra structured fields passed via the `extra` kwarg
        extras = {
            k: v
            for k, v in record.__dict__.items()
            if k not in logging.LogRecord.__dict__ and not k.startswith("_")
            and k not in ("args", "msg", "levelname", "levelno", "pathname",
                          "filename", "module", "exc_info", "exc_text",
                          "stack_info", "lineno", "funcName", "created",
                          "msecs", "relativeCreated", "thread", "threadName",
                          "processName", "process", "name", "asctime",
                          "taskName", "message")
        }

        extra_str = " ".join(f"{k}={v}" for k, v in extras.items())
        base = f"{ts} | LEVEL={level} | {msg}"
        return f"{base} {extra_str}".strip()


def get_logger(name: str = "sec_ai_chatbot") -> logging.Logger:
    """Return a configured logger. Call once per module."""
    logger = logging.getLogger(name)

    if logger.handlers:
        # Already configured -- return as-is (handles repeated imports)
        return logger

    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    # -- Console handler --
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(StructuredFormatter())
    logger.addHandler(console_handler)

    # -- Optional rotating file handler (keeps last 5 x 10 MB log files) --
    if LOG_FILE:
        try:
            file_handler = RotatingFileHandler(
                LOG_FILE, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
            )
            file_handler.setFormatter(StructuredFormatter())
            logger.addHandler(file_handler)
        except OSError as exc:
            # Don't crash if log file path is unwritable -- fall back to console only
            logger.warning(f"Could not open log file '{LOG_FILE}': {exc}")

    # Prevent log records from propagating to the root logger
    logger.propagate = False

    return logger


# Module-level logger for import convenience
log = get_logger()


# ---------------------------------------------------------------------------
# Phase 7: Structured audit + security event helpers
# ---------------------------------------------------------------------------

def audit_log(action: str, user: str, **kwargs) -> None:
    """
    Emit a structured AUDIT log entry.

    Every entry captures:
      - action : what happened  (e.g. 'login', 'upload', 'chat')
      - user   : authenticated identity performing the action
      - **kwargs: any additional context (endpoint, filename, ip, etc.)

    Example output:
      2026-07-24 ... | LEVEL=INFO | AUDIT action=login user=admin ip=127.0.0.1 result=success
    """
    log.info("AUDIT", extra={"action": action, "user": user, **kwargs})


def security_event(event_type: str, severity: str = "HIGH", **kwargs) -> None:
    """
    Emit a structured SECURITY_EVENT log entry for incidents that need attention.

    event_type examples:
      'injection_attempt', 'auth_failure', 'oversized_upload',
      'mime_mismatch', 'indirect_injection', 'rate_limit_exceeded',
      'system_prompt_leakage'

    Example output:
      2026-07-24 ... | LEVEL=WARNING | SECURITY_EVENT type=injection_attempt severity=HIGH user=admin
    """
    log.warning("SECURITY_EVENT", extra={"type": event_type, "severity": severity, **kwargs})
