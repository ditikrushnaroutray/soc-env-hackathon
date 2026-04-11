"""
Central logging helpers for the SOC Analyst Environment.

Provides a consistent logging format across all server modules.
"""

import logging
import sys


_LOG_FORMAT = "[%(asctime)s] %(levelname)s %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
_CONFIGURED = False


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Get a configured logger with consistent formatting.

    Args:
        name: Logger name (typically __name__ of the calling module).
        level: Logging level (default INFO).

    Returns:
        Configured logging.Logger instance.
    """
    global _CONFIGURED

    logger = logging.getLogger(name)

    if not _CONFIGURED:
        # Configure root logger once
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
        root = logging.getLogger()
        root.addHandler(handler)
        root.setLevel(level)
        _CONFIGURED = True

    logger.setLevel(level)
    return logger
