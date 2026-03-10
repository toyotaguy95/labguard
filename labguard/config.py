"""Load and validate LabGuard configuration.

This is the agent's "self-awareness" — it reads config.yaml to learn:
  - What logs to observe (log_dir)
  - What LLM to think with (provider, model, api_key)
  - How to act (Telegram, Discord alert settings)
  - How often to loop (interval)

Design decision: We use a simple dataclass instead of a heavy config framework.
The config is loaded once at startup and passed to every module. This is the
"dependency injection" pattern — each module receives what it needs rather than
reaching out to grab global state.
"""

from dataclasses import dataclass, field
from pathlib import Path
import os
import yaml


@dataclass
class LLMConfig:
    """How the agent thinks — which LLM to use."""
    provider: str = "ollama"
    model: str = "llama3.1:8b"
    base_url: str = "http://localhost:11434/v1"
    api_key: str = "ollama"


@dataclass
class EscalationLLMConfig:
    """Optional second LLM for high-severity re-analysis.

    Agent concept: TIERED REASONING
    ================================
    Not every task needs the same brain. Background noise? Use the free
    model. Possible real attack? Escalate to a smarter (paid) model for
    a second opinion. This saves money while maintaining accuracy.

    Same pattern as a hospital triage: nurse checks vitals (free model),
    doctor only sees you if something's wrong (paid model).
    """
    enabled: bool = False
    provider: str = "anthropic"
    model: str = "claude-haiku-4-5-20251001"
    base_url: str = "https://api.anthropic.com"
    api_key: str = ""
    escalate_on: list[str] = field(default_factory=lambda: ["medium", "high", "critical"])


@dataclass
class TelegramConfig:
    """Telegram alert settings."""
    enabled: bool = False
    bot_token: str = ""
    chat_id: str = ""


@dataclass
class DiscordConfig:
    """Discord alert settings."""
    enabled: bool = False
    webhook_url: str = ""


@dataclass
class AlertsConfig:
    """How the agent acts — where to send alerts."""
    telegram: TelegramConfig = field(default_factory=TelegramConfig)
    discord: DiscordConfig = field(default_factory=DiscordConfig)


@dataclass
class AgentConfig:
    """Top-level agent configuration."""
    interval: int = 300
    log_dir: str = "/var/log/labguard"


@dataclass
class SanitizerConfig:
    """What sensitive data to scrub before sending to the LLM."""
    hostnames: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    extra_patterns: list[str] = field(default_factory=list)


@dataclass
class TuningConfig:
    """Severity tuning — reduce false positives and alert fatigue.

    whitelist_cidrs: IP ranges that are known-good (Cloudflare, your CDN,
        your own infrastructure). Log lines from these IPs get stripped
        BEFORE the LLM sees them, so it can't over-classify them.

    noise_patterns: Substrings in log lines that are known non-threats
        (e.g., Suricata internal messages). Lines matching these get
        filtered out before the LLM analyzes them.
    """
    whitelist_cidrs: list[str] = field(default_factory=list)
    noise_patterns: list[str] = field(default_factory=list)


@dataclass
class Config:
    """Complete LabGuard configuration.

    This is the single object that gets passed to observer, thinker, and actor.
    Each module only reads the fields it needs:
      - Observer reads agent.log_dir
      - Thinker reads llm.*
      - Actor reads alerts.*
      - Sanitizer reads sanitizer.*
    """
    agent: AgentConfig = field(default_factory=AgentConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    escalation_llm: EscalationLLMConfig = field(default_factory=EscalationLLMConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    sanitizer: SanitizerConfig = field(default_factory=SanitizerConfig)
    tuning: TuningConfig = field(default_factory=TuningConfig)


def load_config(path: str = "config.yaml") -> Config:
    """Load config from YAML file. Falls back to defaults if file is missing.

    Why YAML? It's human-readable and the standard for config files in
    DevOps/security tooling (Ansible, Suricata, docker-compose all use it).
    Non-technical users can edit it without knowing Python.
    """
    config_path = Path(path)

    if config_path.exists():
        with open(config_path) as f:
            raw = yaml.safe_load(f) or {}
    else:
        print(f"[*] No {path} found — using env vars and defaults")
        raw = {}

    # Build config from YAML, falling back to defaults for missing fields
    agent_raw = raw.get("agent", {})
    llm_raw = raw.get("llm", {})
    alerts_raw = raw.get("alerts", {})
    telegram_raw = alerts_raw.get("telegram", {})
    discord_raw = alerts_raw.get("discord", {})

    # Environment variables override config file values.
    # This is the standard "12-factor app" pattern — config comes from the
    # environment in production, from a file in development. It means you
    # can set LABGUARD_API_KEY in your shell profile and never put it in a file.
    sanitizer_raw = raw.get("sanitizer", {})

    escalation_raw = raw.get("escalation_llm", {})
    tuning_raw = raw.get("tuning", {})

    config = Config(
        agent=AgentConfig(
            interval=agent_raw.get("interval", 300),
            log_dir=agent_raw.get("log_dir", "/var/log/labguard"),
        ),
        llm=LLMConfig(
            provider=os.environ.get("LABGUARD_LLM_PROVIDER", llm_raw.get("provider", "ollama")),
            model=os.environ.get("LABGUARD_LLM_MODEL", llm_raw.get("model", "llama3.1:8b")),
            base_url=os.environ.get("LABGUARD_LLM_BASE_URL", llm_raw.get("base_url", "http://localhost:11434/v1")),
            api_key=os.environ.get("LABGUARD_API_KEY", llm_raw.get("api_key", "ollama")),
        ),
        alerts=AlertsConfig(
            telegram=TelegramConfig(
                enabled=telegram_raw.get("enabled", False),
                bot_token=os.environ.get("LABGUARD_TELEGRAM_TOKEN", telegram_raw.get("bot_token", "")),
                chat_id=telegram_raw.get("chat_id", ""),
            ),
            discord=DiscordConfig(
                enabled=discord_raw.get("enabled", False),
                webhook_url=os.environ.get("LABGUARD_DISCORD_WEBHOOK", discord_raw.get("webhook_url", "")),
            ),
        ),
        escalation_llm=EscalationLLMConfig(
            enabled=escalation_raw.get("enabled", False),
            provider=escalation_raw.get("provider", "anthropic"),
            model=escalation_raw.get("model", "claude-haiku-4-5-20251001"),
            base_url=escalation_raw.get("base_url", "https://api.anthropic.com"),
            api_key=os.environ.get("LABGUARD_ESCALATION_KEY", escalation_raw.get("api_key", "")),
            escalate_on=escalation_raw.get("escalate_on", ["medium", "high", "critical"]),
        ),
        sanitizer=SanitizerConfig(
            hostnames=sanitizer_raw.get("hostnames", []),
            domains=sanitizer_raw.get("domains", []),
            usernames=sanitizer_raw.get("usernames", []),
            extra_patterns=sanitizer_raw.get("extra_patterns", []),
        ),
        tuning=TuningConfig(
            whitelist_cidrs=tuning_raw.get("whitelist_cidrs", []),
            noise_patterns=tuning_raw.get("noise_patterns", []),
        ),
    )

    return config
