# LabGuard

AI-powered security monitoring agent for homelabs.

LabGuard watches your network security logs (Suricata IDS, nginx, fail2ban, SSH) and uses an LLM to provide plain-English threat assessments with actionable recommendations.

<img width="1027" alt="LabGuard Terminal Output" src="https://github.com/user-attachments/assets/ad74137f-9ff9-4877-b60e-935419b6b1af" />

## How It Works

LabGuard follows the **Observe - Sanitize - Think - Act** agent pattern:

1. **Observe** - Reads security logs forwarded via syslog (Suricata, nginx, SSH, fail2ban)
2. **Sanitize** - Scrubs private IPs, hostnames, domains, and other sensitive data before it leaves your network
3. **Think** - Sends sanitized logs to an LLM for analysis, gets structured JSON threat assessments
4. **Act** - Sends Discord/Telegram alerts for real threats, logs everything locally

```
┌──────────────┐   syslog    ┌─────────────────────────────────────┐
│ Your Router  │────TCP 514──│            LabGuard Pi              │
│              │             │                                     │
│ Suricata IDS │             │  Observe → Sanitize → Think → Act  │
│ nginx        │             │                          │          │
│ fail2ban     │             │               ┌──────────┤          │
│ sshd         │             │               ▼          ▼          │
└──────────────┘             │           Discord    Local Log      │
                             └─────────────────────────────────────┘
```

## Features

- **Plain-English alerts** - "Someone tried to access .env files 47 times" not raw Suricata signatures
- **Full network visibility** - Monitors all VLANs and external traffic via Suricata IDS
- **Privacy-first** - Three-pass data sanitizer scrubs internal IPs, hostnames, MACs, emails, and domains before anything reaches the LLM
- **LLM-agnostic** - Works with any OpenAI-compatible API (Claude, GPT-4, OpenRouter, Ollama)
- **Free local model support** - Run with Ollama for zero cost, no API key, fully private
- **Discord and Telegram alerts** - Rich embeds with severity-colored cards
- **One-command install** - `./install.sh` handles everything
- **Runs as a service** - systemd unit with security hardening, starts on boot
- **Config-driven** - YAML config, no code changes needed
- **Works alongside existing tools** - Complements Suricata, fail2ban, etc.

## Quick Start

```bash
git clone https://github.com/toyotaguy95/labguard.git
cd labguard
./install.sh
nano config.yaml            # Add your LLM provider and alert settings
python3 -m labguard --once  # Test one cycle
```

## Requirements

- Python 3.10+
- A system forwarding security logs via syslog (see docs/setup.md)
- An LLM provider:
  - **Free**: Ollama (local, private) or OpenRouter free tier
  - **Paid**: Anthropic, OpenAI, OpenRouter, or any OpenAI-compatible API

## Usage

```bash
python3 -m labguard              # Run the agent loop (default: 5 min interval)
python3 -m labguard --once       # Run one observe/think/act cycle and exit
python3 -m labguard --test-alerts # Send a test alert to verify Discord/Telegram
sudo systemctl start labguard    # Run as a background service
sudo journalctl -u labguard -f   # Follow live agent output
```

## Architecture

```
labguard/
├── config.py       # Loads YAML config + env var overrides
├── observer.py     # Reads log files, tracks position between cycles
├── sanitizer.py    # Three-pass scrub: known patterns → user config → verify
├── thinker.py      # LLM abstraction layer, structured JSON output
├── actor.py        # Discord/Telegram alerts, local logging
└── agent.py        # Main loop: observe → sanitize → think → act
```

## Roadmap

- [x] Phase 1 - Agent loop, log observation, LLM analysis, alerts, data sanitizer
- [ ] Phase 2 - Memory (remember past threats), Prometheus metrics integration, pattern detection
- [ ] Phase 3 - Tool use (let LLM query external services), human-in-the-loop defensive actions, web dashboard

## License

MIT
