<img width="1027" height="1014" alt="Screenshot 2026-03-05 010621" src="https://github.com/user-attachments/assets/ad74137f-9ff9-4877-b60e-935419b6b1af" />

# LabGuard

AI-powered security monitoring agent for homelabs.

LabGuard watches your network security logs (Suricata IDS, nginx, fail2ban, SSH) and uses an LLM to provide plain-English threat assessments with actionable recommendations.

## How It Works

LabGuard follows the **Observe - Think - Act** agent pattern:

1. **Observe** - Reads security logs forwarded to it via syslog
2. **Think** - Sends observations to an LLM for analysis
3. **Act** - Sends alerts (Telegram, Discord) with plain-English explanations

## Features

- Plain-English security alerts ("Someone from Russia tried SSH 47 times")
- Works with any OpenAI-compatible LLM (Claude, GPT-4, Ollama, OpenRouter)
- Free local model support via Ollama (no API key needed)
- Telegram and Discord alerts
- Config-driven - customize without touching code
- Works alongside existing tools (Suricata, fail2ban, etc.)

## Quick Start

```bash
git clone https://github.com/toyotaguy95/labguard.git
cd labguard
cp config.example.yaml config.yaml
# Edit config.yaml with your LLM provider and alert settings
python3 -m labguard
```

## Requirements

- Python 3.10+
- A system forwarding security logs via syslog (see docs/setup.md)
- An LLM provider (Ollama for free local, or any OpenAI-compatible API)

## Project Status

Phase 1: Basic agent loop with log reading and alerts (in progress)

## License

MIT
