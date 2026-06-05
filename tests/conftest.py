"""Shared pytest fixtures."""

from pathlib import Path

import pytest

from src.log_parser import LogParser

REPO_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = REPO_ROOT / "logs"


@pytest.fixture(scope="session")
def events():
    """Parse the bundled sample logs once for the whole test session."""
    return LogParser().parse_logs(str(LOGS_DIR))
