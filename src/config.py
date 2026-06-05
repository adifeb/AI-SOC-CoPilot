"""Configuration loading for the AI SOC CoPilot.

Layered precedence (lowest to highest): built-in defaults -> config.yaml ->
environment variables (SOC_*) -> CLI flags (applied by the caller). Keeping the
config typed and centralized is part of the engineering-maturity goals.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict

try:
    import yaml
except ImportError:  # pragma: no cover - pyyaml is a declared dependency
    yaml = None


@dataclass
class LLMConfig:
    provider: str = "ollama"          # local Ollama only
    model: str = "llama2"
    base_url: str = "http://localhost:11434"
    timeout: int = 120
    num_ctx: int = 4096


@dataclass
class AnalysisConfig:
    alert_time_window_minutes: int = 5
    correlation_window_minutes: int = 60


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "text"              # "text" | "json"


@dataclass
class ReportConfig:
    default_format: str = "txt"
    output_dir: str = "reports"


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    report: ReportConfig = field(default_factory=ReportConfig)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _apply_env(cfg: Config) -> None:
    """Override selected fields from SOC_* environment variables."""
    mapping = {
        "SOC_LLM_PROVIDER": ("llm", "provider", str),
        "SOC_LLM_MODEL": ("llm", "model", str),
        "SOC_LLM_BASE_URL": ("llm", "base_url", str),
        "SOC_LLM_TIMEOUT": ("llm", "timeout", int),
        "SOC_LLM_NUM_CTX": ("llm", "num_ctx", int),
        "SOC_LOG_LEVEL": ("logging", "level", str),
        "SOC_LOG_FORMAT": ("logging", "format", str),
    }
    for env_key, (section, key, cast) in mapping.items():
        val = os.environ.get(env_key)
        if val is not None:
            setattr(getattr(cfg, section), key, cast(val))


def load_config(path: str | os.PathLike | None = "config.yaml") -> Config:
    """Load configuration from YAML (if present) plus environment overrides."""
    cfg = Config()

    if path and yaml is not None and Path(path).exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        for section in ("llm", "analysis", "logging", "report"):
            section_data = data.get(section) or {}
            target = getattr(cfg, section)
            for k, v in section_data.items():
                if hasattr(target, k):
                    setattr(target, k, v)

    _apply_env(cfg)
    return cfg
