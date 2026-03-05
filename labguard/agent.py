"""Main agent loop - observe, think, act.

Agent concept: THE AGENT LOOP / CONTROL LOOP
==============================================
This is what makes an agent an agent. Not a single LLM call — a LOOP
that continuously perceives, reasons, and acts. The loop is the agent's
lifecycle.

Every agent framework has this at its core:
  - LangChain: AgentExecutor.invoke() runs the loop
  - CrewAI: Crew.kickoff() runs agents in a loop
  - AutoGen: The conversation loop between agents

Our loop is simple and explicit:
  1. Observe  →  read new log lines
  2. Think    →  send to LLM, get analysis
  3. Act      →  alert if needed, always log
  4. Sleep    →  wait for the next cycle
  5. Repeat

The sleep between cycles is what makes this a "polling" architecture
(check periodically) vs "event-driven" (react immediately). Polling is
simpler and good enough for security monitoring — a 5-minute delay
before you learn about a threat is fine. Real-time event-driven
architectures (like Suricata itself) are more complex and unnecessary
for our use case.

State management: The Observer keeps track of file positions between
cycles (short-term memory). In Phase 2, we'll add long-term memory
so the agent remembers past threats across restarts.
"""

import time
import signal
import sys

from labguard.config import Config, load_config
from labguard.observer import Observer
from labguard.sanitizer import Sanitizer, SanitizerConfig
from labguard.thinker import Thinker
from labguard.actor import Actor




# ANSI color codes for terminal output
class _C:
    """Terminal colors. Degrades gracefully if terminal doesn't support them."""
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    RESET   = "\033[0m"


BANNER = rf"""
{_C.CYAN}{_C.BOLD}    ██╗      █████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
    ██║     ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██║     ███████║██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██║     ██╔══██║██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ███████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝{_C.RESET}
{_C.DIM}                    AI Security Agent for Homelabs{_C.RESET}
"""


class LabGuardAgent:
    """The main agent. Wires together observer, thinker, and actor.

    This is the "orchestrator" — it doesn't do any real work itself.
    It just calls observe(), think(), act() in order and manages the
    timing. This separation means you can test each module independently.
    """

    def __init__(self, config: Config):
        self.config = config
        self.observer = Observer(config.agent.log_dir)
        self.sanitizer = Sanitizer(config.sanitizer)
        self.thinker = Thinker(config.llm)
        self.actor = Actor(config.alerts)
        self.running = False
        self._cycle_count = 0

    def run_once(self) -> dict:
        """Run a single observe → think → act cycle.

        Useful for testing and for the --once CLI flag.
        Returns a summary dict of what happened.
        """
        self._cycle_count += 1
        cycle_start = time.time()

        # ── OBSERVE ──
        print(f"\n[cycle {self._cycle_count}] Observing...")
        observation = self.observer.observe()
        print(f"  {observation.summary()}")

        if observation.errors:
            for err in observation.errors:
                print(f"  [!] {err}")

        if not observation.has_data:
            print("  Nothing new — skipping think/act")
            return {"cycle": self._cycle_count, "skipped": True}

        # ── SANITIZE ──
        print(f"[cycle {self._cycle_count}] Sanitizing...")
        self.sanitizer.reset()
        sanitized = self.sanitizer.sanitize(observation)
        print(f"  Scrubbed {sanitized.total_lines} lines for LLM")
        if self.sanitizer.warnings:
            for warn in self.sanitizer.warnings:
                print(f"  [!] {warn}")

        # ── THINK ──
        print(f"[cycle {self._cycle_count}] Thinking...")
        analysis = self.thinker.think(sanitized)

        if analysis.error:
            print(f"  [!] Thinker error: {analysis.error}")
            return {"cycle": self._cycle_count, "error": analysis.error}

        print(f"  Summary: {analysis.summary}")
        print(f"  Threats: {len(analysis.threats)} found, max severity: {analysis.max_severity}")

        # ── ACT ──
        print(f"[cycle {self._cycle_count}] Acting...")
        actions = self.actor.act(analysis)

        action_summary = []
        if actions["logged"]:
            action_summary.append("logged")
        if actions["telegram"]:
            action_summary.append("telegram sent")
        if actions["discord"]:
            action_summary.append("discord sent")
        if actions["errors"]:
            for err in actions["errors"]:
                action_summary.append(f"error: {err}")

        elapsed = time.time() - cycle_start
        print(f"  Actions: {', '.join(action_summary)}")
        print(f"  Cycle completed in {elapsed:.1f}s")

        return {
            "cycle": self._cycle_count,
            "observation": observation.summary(),
            "analysis_summary": analysis.summary,
            "max_severity": analysis.max_severity,
            "threats": len(analysis.threats),
            "actions": actions,
            "elapsed": elapsed,
        }

    def run(self):
        """Run the agent loop forever (until interrupted).

        This is the main entry point for daemon mode. It runs observe →
        think → act on an interval, handling interrupts gracefully.

        Signal handling: We catch SIGINT (Ctrl+C) and SIGTERM (systemd stop)
        to shut down cleanly. Without this, killing the process could leave
        file positions in a bad state (Phase 2 concern when we persist them).
        """
        self.running = True

        # Graceful shutdown on Ctrl+C or systemd stop
        def handle_signal(signum, frame):
            print(f"\n[*] Received signal {signum}, shutting down...")
            self.running = False

        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)

        self._print_startup()

        print(f"\n[*] Starting agent loop (interval: {self.config.agent.interval}s)")
        print("[*] Press Ctrl+C to stop\n")

        while self.running:
            try:
                self.run_once()
            except Exception as e:
                print(f"[!] Cycle error: {e}")

            # Sleep in small increments so we respond to signals quickly
            # instead of being stuck in a 300-second sleep
            for _ in range(self.config.agent.interval):
                if not self.running:
                    break
                time.sleep(1)

        print("[*] LabGuard stopped.")

    def _print_startup(self):
        """Print the startup banner with status info."""
        from labguard import __version__
        from pathlib import Path

        print(BANNER)
        print(f"                          v{__version__}")
        print()

        G = _C.GREEN    # active/good
        Y = _C.YELLOW   # warning
        R = _C.RESET
        B = _C.BOLD
        D = _C.DIM

        # Observer status
        log_dir = Path(self.config.agent.log_dir)
        log_count = len(list(log_dir.glob("*.log"))) if log_dir.exists() else 0
        if log_count > 0:
            print(f"    {G}●{R} {B}Observer{R}    {log_count} log sources in {self.config.agent.log_dir}")
        else:
            print(f"    {Y}○{R} {B}Observer{R}    no log files found in {self.config.agent.log_dir}")

        # Thinker status
        print(f"    {G}●{R} {B}Thinker{R}     {self.config.llm.model} {D}via {self.config.llm.provider}{R}")

        # Sanitizer status
        san = self.config.sanitizer
        san_items = len(san.hostnames) + len(san.domains) + len(san.usernames)
        if san_items > 0:
            print(f"    {G}●{R} {B}Sanitizer{R}   {san_items} custom rules + auto-scrub")
        else:
            print(f"    {Y}○{R} {B}Sanitizer{R}   auto-scrub only {D}(add hostnames/domains to config){R}")

        # Actor status
        alert_channels = []
        if self.config.alerts.telegram.enabled:
            alert_channels.append("telegram")
        if self.config.alerts.discord.enabled:
            alert_channels.append("discord")
        if alert_channels:
            print(f"    {G}●{R} {B}Actor{R}       {', '.join(alert_channels)} alerts enabled")
        else:
            print(f"    {Y}○{R} {B}Actor{R}       local logging only {D}(no alerts configured){R}")

        # Memory status (Phase 2 placeholder)
        print(f"    {D}○ Memory      not yet configured (Phase 2){R}")
        print()


def _test_alerts(config: Config):
    """Send a test alert to all configured channels."""
    from labguard.thinker import Analysis, Threat

    print("[*] Sending test alert...")

    test_analysis = Analysis(
        summary="This is a test alert from LabGuard",
        threats=[Threat(
            severity="medium",
            source_ip="203.0.113.1",
            description="Test threat — if you see this, alerts are working!",
            evidence="N/A — test alert",
            recommendation="No action needed, this is a test",
        )],
    )

    actor = Actor(config.alerts)
    message = actor._format_alert(test_analysis)

    sent = False
    if config.alerts.telegram.enabled:
        ok = actor._send_telegram(message)
        print(f"  Telegram: {'sent' if ok else 'FAILED'}")
        sent = True
    if config.alerts.discord.enabled:
        ok = actor._send_discord(message, test_analysis)
        print(f"  Discord:  {'sent' if ok else 'FAILED'}")
        sent = True

    if not sent:
        print("  No alert channels configured. Enable telegram or discord in config.yaml")


def main():
    """CLI entry point."""
    config = load_config()

    agent = LabGuardAgent(config)

    if "--test-alerts" in sys.argv:
        _test_alerts(config)
    elif "--once" in sys.argv:
        agent._print_startup()
        agent.run_once()
    else:
        agent.run()
