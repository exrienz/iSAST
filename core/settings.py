"""Configuration loading: .env, environment variables, optional YAML config.

Blueprint section 9/39. Secrets and AI settings come from .env / environment;
never from CLI arguments (blueprint section 36).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional


def _env_bool(value: Optional[str], default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_int(value: Optional[str], default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _env_float(value: Optional[str], default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return default


def load_dotenv_file(root: Path) -> Dict[str, str]:
    """Minimal .env loader (KEY=VALUE lines, # comments), no extra deps."""
    env_file = root / ".env"
    loaded: Dict[str, str] = {}
    if not env_file.exists():
        return loaded
    try:
        for raw_line in env_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key:
                loaded[key] = value
                if key not in os.environ:
                    os.environ[key] = value
    except OSError:
        return loaded
    return loaded


@dataclass
class Settings:
    """Resolved runtime settings for one scan."""

    workdir: Path = field(default_factory=lambda: Path("/tmp/isast"))
    opengrep_version: str = ""
    codeql_version: str = ""

    ai_enabled: bool = True
    ai_base_url: str = "https://api.openai.com/v1"
    ai_api_key: str = ""
    ai_model: str = ""
    ai_timeout: int = 120
    ai_max_retries: int = 3
    ai_group_budget: int = 600  # per-candidate-group AI wall clock; 0 = unlimited
    ai_max_tokens: int = 0  # 0 = gateway default; set to defend vs truncated JSON
    ai_concurrency: int = 8
    ai_temperature: float = 0.0
    ai_batch_size: int = 20
    ai_context_lines: int = 30
    ai_validate: bool = True
    ai_dedup: bool = True
    ai_rewrite: bool = True
    ai_risk_analysis: bool = True

    build_sandbox: str = "auto"

    raw: Dict[str, str] = field(default_factory=dict)

    @property
    def ai_configured(self) -> bool:
        return bool(self.ai_base_url) and bool(self.ai_api_key) and bool(self.ai_model)


def load_settings(root: Optional[Path] = None, config_file: Optional[Path] = None) -> Settings:
    """Load settings from .env, process env and optional config yaml."""
    project_root = root or Path(__file__).resolve().parent.parent
    loaded = load_dotenv_file(project_root)

    if config_file is not None:
        _apply_yaml_config(config_file, loaded)

    def env(key: str, default: str = "") -> str:
        return os.environ.get(key, loaded.get(key, default))

    settings = Settings()
    settings.raw = dict(loaded)
    settings.workdir = Path(env("ISAST_WORKDIR", "/tmp/isast")).expanduser()
    settings.opengrep_version = env("OPENGREP_VERSION", "")
    settings.codeql_version = env("CODEQL_VERSION", "")

    settings.ai_enabled = _env_bool(env("AI_ENABLED"), True)
    settings.ai_base_url = env("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    settings.ai_api_key = env("AI_API_KEY", "")
    settings.ai_model = env("AI_MODEL", "")
    settings.ai_timeout = _env_int(env("AI_TIMEOUT"), 120)
    settings.ai_max_retries = max(0, _env_int(env("AI_MAX_RETRIES"), 3))
    settings.ai_group_budget = max(0, _env_int(env("AI_GROUP_BUDGET"), 600))
    settings.ai_max_tokens = max(0, _env_int(env("AI_MAX_TOKENS"), 0))
    settings.ai_concurrency = max(1, _env_int(env("AI_CONCURRENCY"), 8))
    settings.ai_temperature = _env_float(env("AI_TEMPERATURE"), 0.0)
    settings.ai_batch_size = max(1, _env_int(env("AI_BATCH_SIZE"), 20))
    settings.ai_context_lines = max(1, _env_int(env("AI_CONTEXT_LINES"), 30))
    settings.ai_validate = _env_bool(env("AI_VALIDATE"), True)
    settings.ai_dedup = _env_bool(env("AI_DEDUP"), True)
    settings.ai_rewrite = _env_bool(env("AI_REWRITE"), True)
    settings.ai_risk_analysis = _env_bool(env("AI_RISK_ANALYSIS"), True)

    settings.build_sandbox = env("BUILD_SANDBOX", "auto").strip().lower() or "auto"
    return settings


def _apply_yaml_config(config_file: Path, target: Dict[str, str]) -> None:
    """Overlay a YAML config onto the env-derived settings mapping.

    Supports flat keys (ai_model:) and one nested level (ai: model:).
    """
    if not config_file.exists():
        return
    try:
        import yaml
    except ImportError:  # pragma: no cover - PyYAML is a hard requirement
        return
    try:
        document = yaml.safe_load(config_file.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return
    if not isinstance(document, dict):
        return
    for key, value in document.items():
        if isinstance(value, dict):
            for inner_key, inner_value in value.items():
                _set_config_value(target, f"{key}_{inner_key}".upper(), inner_value)
        else:
            _set_config_value(target, str(key).upper(), value)


def _set_config_value(target: Dict[str, str], key: str, value: Any) -> None:
    if value is None:
        return
    if key not in os.environ:
        os.environ[key] = str(value)
    target[key] = str(value)