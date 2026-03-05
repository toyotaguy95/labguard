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


BANNER = r"""
    ██╗      █████╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
    ██║     ██╔══██╗██╔══██╗██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
    ██║     ███████║██████╔╝██║  ███╗██║   ██║███████║██████╔╝██║  ██║
    ██║     ██╔══██║██╔══██╗██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
    ███████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
                    AI Security Agent for Homelabs
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
        print(BANNER)
        version = "0.1.0"
        print(f"                          v{version}")
        print()
        print(f"    [*] Observer:  watching {self.config.agent.log_dir}")
        print(f"    [*] Thinker:   {self.config.llm.model} via {self.config.llm.provider}")

        san = self.config.sanitizer
        san_items = len(san.hostnames) + len(san.domains) + len(san.usernames)
        if san_items > 0:
            print(f"    [*] Sanitizer: {san_items} custom rules + auto-scrub (IPs, MACs, emails)")
        else:
            print(f"    [*] Sanitizer: auto-scrub only (add hostnames/domains to config for full protection)")

        alert_channels = []
        if self.config.alerts.telegram.enabled:
            alert_channels.append("telegram")
        if self.config.alerts.discord.enabled:
            alert_channels.append("discord")
        if alert_channels:
            print(f"    [*] Actor:     {', '.join(alert_channels)} alerts enabled")
        else:
            print(f"    [*] Actor:     local logging only (no alerts configured)")


def main():
    """CLI entry point."""
    config = load_config()

    agent = LabGuardAgent(config)

    # Check for --once flag
    if "--once" in sys.argv:
        agent.run_once()
    else:
        agent.run()
