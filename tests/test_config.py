"""Tests for layered configuration loading."""

from src.config import load_config


def test_defaults_when_no_file():
    cfg = load_config(path=None)
    assert cfg.llm.provider == "ollama"
    assert cfg.llm.num_ctx == 4096


def test_loads_yaml(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("llm:\n  model: mistral\n  num_ctx: 8192\n")
    cfg = load_config(str(p))
    assert cfg.llm.model == "mistral"
    assert cfg.llm.num_ctx == 8192


def test_env_override(monkeypatch):
    monkeypatch.setenv("SOC_LLM_MODEL", "llama3.1")
    monkeypatch.setenv("SOC_LLM_NUM_CTX", "16384")
    cfg = load_config(path=None)
    assert cfg.llm.model == "llama3.1"
    assert cfg.llm.num_ctx == 16384
