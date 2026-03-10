# LabGuard

AI-powered security monitoring agent for homelabs.

LabGuard watches your network security logs (Suricata IDS, nginx, fail2ban, SSH) and uses an LLM to provide plain-English threat assessments with actionable recommendations. It proposes defensive actions like blocking IPs — but only with your approval.

<img width="1027" alt="LabGuard Terminal Output" src="https://github.com/user-attachments/assets/ad74137f-9ff9-4877-b60e-935419b6b1af" />

## How It Works

LabGuard follows the **Observe - Sanitize - Think - Act** agent pattern:

1. **Observe** - Reads security logs forwarded via syslog (Suricata, nginx, SSH, fail2ban) + infrastructure metrics from Prometheus
2. **Sanitize** - Scrubs private IPs, hostnames, domains, and other sensitive data before it leaves your network
3. **Filter** - Strips known-good traffic (Cloudflare, Google) and Suricata noise before the LLM sees it
4. **Think** - Sends sanitized logs to an LLM for analysis. If threats are found, escalates to a smarter model for a second opinion
5. **Act** - Sends Discord/Telegram alerts for real threats, proposes defensive actions, logs everything locally

```
┌──────────────┐   syslog    ┌──────────────────────────────────────────┐
│ Your Router  │────TCP 514──│              LabGuard Pi                 │
│              │             │                                          │
│ Suricata IDS │             │  Observe → Sanitize → Filter → Think    │
│ nginx        │             │                                  │       │
│ fail2ban     │             │        ┌──────────┬──────────────┤       │
│ sshd         │             │        ▼          ▼              ▼       │
│ Prometheus   │             │    Discord    Local Log     Propose      │
└──────────────┘             │   (alerts)   (all data)    (actions)     │
                             └──────────────────────────────────────────┘
```

## Features

### Core Agent
- **Plain-English alerts** - "Someone tried to access .env files 47 times" not raw Suricata signatures
- **Full network visibility** - Monitors all VLANs and external traffic via Suricata IDS
- **Privacy-first** - Three-pass data sanitizer scrubs internal IPs, hostnames, MACs, emails, and domains before anything reaches the LLM
- **LLM-agnostic** - Works with any OpenAI-compatible API (Claude, GPT-4, OpenRouter, Ollama) + native Anthropic API support
- **Free local model support** - Run with Ollama for zero cost, no API key, fully private

### Intelligence
- **Threat memory** - SQLite-backed persistent memory tracks every threat, builds IP reputation over time
- **Pattern detection** - Spots escalating attack frequency, new attacker clusters, persistent scanners, severity trends
- **Alert deduplication** - Won't spam you about the same scanner every 5 minutes (1-hour cooldown)
- **Noise filter** - Auto-strips Cloudflare/Google CDN traffic and Suricata performance messages to prevent false positives
- **Severity calibration** - Strict rules: only confirmed breaches are "critical," internet background noise is "low"

### Actions
- **Tool use** - Proposes defensive actions (block IP, rate limit, watchlist) with exact commands
- **Human-in-the-loop** - Agent proposes, you approve. No auto-execution. Copy-paste the command when ready
- **Tiered reasoning** - Free model handles routine cycles ($0), escalates to Claude Haiku only when real threats are found (~90% cost savings)
- **Infrastructure monitoring** - Ingests Prometheus metrics (CPU, memory, disk, network) via syslog

### Operations
- **Discord and Telegram alerts** - Rich embeds with severity-colored cards and proposed actions
- **Self-health monitoring** - Tracks its own cycle times, LLM failure rates, disk space, log freshness
- **Heartbeat** - Periodic status summary in journalctl so you know the agent is alive
- **One-command install** - `./install.sh` handles everything
- **Runs as a service** - systemd unit with security hardening, starts on boot

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
- A system forwarding security logs via syslog
- An LLM provider:
  - **Free**: Ollama (local, private) or OpenRouter free tier
  - **Paid**: Anthropic (Claude Haiku recommended), OpenAI, OpenRouter, or any OpenAI-compatible API

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
├── config.py         # Loads YAML config + env var overrides
├── observer.py       # Reads log files, tracks byte position between cycles
├── sanitizer.py      # Three-pass scrub: known patterns → user config → verify
├── noise_filter.py   # Strips whitelisted IPs (CDNs) and Suricata noise
├── thinker.py        # LLM abstraction (OpenAI + Anthropic APIs), structured JSON
├── actor.py          # Discord/Telegram alerts with proposed actions
├── tools.py          # Tool definitions: block_ip, rate_limit_ip, watch_ip
├── memory.py         # SQLite: threat history, IP reputation, alert dedup, proposals
├── health.py         # Self-monitoring: cycle stats, disk, log freshness, heartbeat
└── agent.py          # Main loop: observe → sanitize → filter → think → act
```

## Cost Optimization

LabGuard uses **tiered reasoning** to minimize API costs:

| Cycle type | Model used | Cost |
|---|---|---|
| No threats found | Free model (OpenRouter) | $0 |
| Low/info only | Free model | $0 |
| Medium+ threats | Free model + Haiku escalation | ~$0.01 |

Most cycles are background noise and cost nothing. Haiku only runs when the free model finds something worth a second opinion, and receives a compact summary instead of raw logs (~90% token reduction).

## Roadmap

- [x] Phase 1 - Agent loop, log observation, LLM analysis, alerts, data sanitizer
- [x] Phase 2 - Memory, pattern detection, noise filter, severity tuning, health monitoring, Prometheus metrics
- [x] Phase 3 - Tool use (propose-only), human-in-the-loop, tiered reasoning, Anthropic API
- [ ] Phase 4 - Auto-execution for low-risk actions, web dashboard, multi-agent coordination

## License

MIT
