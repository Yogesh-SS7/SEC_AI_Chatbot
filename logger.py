"""
logger.py — Structured application logging.

Provides a single pre-configured logger instance used throughout the app.
Log records are emitted as JSON-style key=value pairs so they can be easily
parsed by log aggregators (ELK, Datadog, CloudWatch, etc.).
"""

import logging
import sys
from config import LOG_LEVEL


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
        # Already configured — return as-is (handles repeated imports)
        return logger

    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(StructuredFormatter())
    logger.addHandler(handler)

    # Prevent log records from propagating to the root logger
    logger.propagate = False

    return logger


# Module-level logger for import convenience
log = get_logger()
