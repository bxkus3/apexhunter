"""
ApexHunter Structured Logging Utility
Provides Rich-based console output for debug and operational telemetry.
"""

import logging
from rich.logging import RichHandler
from rich.console import Console

_console = Console(stderr=True)


def get_logger(name: str) -> logging.Logger:
    """
    Factory for module-level loggers with Rich formatting.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = RichHandler(
            console=_console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True
        )
        formatter = logging.Formatter("%(name)s - %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
