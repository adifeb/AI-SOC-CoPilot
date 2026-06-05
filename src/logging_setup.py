"""Structured logging setup.

Supports a human-readable text formatter and a JSON formatter (one object per
line) selected via config, so the tool's own operational logs can be shipped to
a SIEM just like the logs it analyzes.
"""

from __future__ import annotations

import json
import logging
import sys


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Include any extra structured fields attached via logger.*(..., extra=...)
        for k, v in record.__dict__.items():
            if k not in logging.LogRecord("", 0, "", 0, "", (), None).__dict__ and k != "message":
                payload[k] = v
        return json.dumps(payload, default=str)


def setup_logging(level: str = "INFO", fmt: str = "text") -> logging.Logger:
    """Configure the root 'soc' logger. Returns it for convenience."""
    logger = logging.getLogger("soc")
    logger.handlers.clear()
    logger.setLevel(getattr(logging, str(level).upper(), logging.INFO))

    handler = logging.StreamHandler(sys.stderr)
    if str(fmt).lower() == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s",
                                                datefmt="%H:%M:%S"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger(name: str = "soc") -> logging.Logger:
    return logging.getLogger(name)
