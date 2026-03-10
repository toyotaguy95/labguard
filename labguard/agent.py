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
from labguard.memory import Memory
from labguard.health import HealthMonitor, CycleStats
from labguard.noise_filter import NoiseFilter
from labguard.tools import parse_action, generate_command




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
        self.noise_filter = NoiseFilter(config.tuning)
        self.memory = Memory()

        # Escalation thinker — optional second LLM for serious threats
        if config.escalation_llm.enabled and config.escalation_llm.api_key:
            from labguard.config import LLMConfig
            esc = config.escalation_llm
            esc_llm_config = LLMConfig(
                provider=esc.provider, model=esc.model,
                base_url=esc.base_url, api_key=esc.api_key,
            )
            self.escalation_thinker = Thinker(esc_llm_config)
        else:
            self.escalation_thinker = None
        self.health = HealthMonitor(log_dir=config.agent.log_dir)
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
            self.health.record_cycle(CycleStats(
                cycle_number=self._cycle_count,
                duration=time.time() - cycle_start,
                lines_observed=0, threats_found=0, llm_success=True,
            ))
            if self.health.should_heartbeat(self._cycle_count):
                print(self.health.format_heartbeat())
            return {"cycle": self._cycle_count, "skipped": True}

        # ── SANITIZE ──
        print(f"[cycle {self._cycle_count}] Sanitizing...")
        self.sanitizer.reset()
        sanitized = self.sanitizer.sanitize(observation)
        print(f"  Scrubbed {sanitized.total_lines} lines for LLM")
        if self.sanitizer.warnings:
            for warn in self.sanitizer.warnings:
                print(f"  [!] {warn}")

        # ── FILTER NOISE ──
        # Strip known-good IPs and non-threat log lines BEFORE the LLM
        # sees them. This prevents false positives like "Cloudflare IP is
        # a critical attacker!" and saves tokens/time.
        sanitized = self.noise_filter.filter(sanitized)
        stats = self.noise_filter.stats
        if stats["filtered_lines"] > 0:
            print(f"[cycle {self._cycle_count}] Noise filter: removed {stats['filtered_lines']}/{stats['total_lines']} lines "
                  f"(whitelist: {stats['whitelist_hits']}, noise: {stats['noise_hits']})")

        # Check if there's anything left after filtering
        if not sanitized.has_data:
            print("  All lines were noise — skipping think/act")
            self.health.record_cycle(CycleStats(
                cycle_number=self._cycle_count,
                duration=time.time() - cycle_start,
                lines_observed=observation.total_lines, threats_found=0, llm_success=True,
            ))
            if self.health.should_heartbeat(self._cycle_count):
                print(self.health.format_heartbeat())
            return {"cycle": self._cycle_count, "skipped": True, "reason": "all_noise"}

        # ── REMEMBER (before thinking) ──
        # Pull historical context from memory to give the LLM awareness
        # of past events. This is "working memory" — relevant history
        # loaded into the current cycle's prompt.
        history_context = self.memory.get_context_for_llm(
            self._extract_ips(sanitized)
        )

        # Pattern detection — meta-reasoning about trends
        patterns = self.memory.detect_patterns(hours=24)
        if patterns:
            pattern_block = "\n=== Detected Patterns ===\n" + "\n".join(f"  {p}" for p in patterns) + "\n"
            history_context = (history_context or "") + pattern_block
            print(f"[cycle {self._cycle_count}] Patterns detected: {len(patterns)}")
            for p in patterns:
                print(f"  {_C.YELLOW}~{_C.RESET} {p}")

        if history_context:
            print(f"[cycle {self._cycle_count}] Memory context loaded for LLM")

        # ── THINK ──
        print(f"[cycle {self._cycle_count}] Thinking...")
        analysis = self.thinker.think(sanitized, memory_context=history_context)

        if analysis.error:
            print(f"  [!] Thinker error: {analysis.error}")
            return {"cycle": self._cycle_count, "error": analysis.error}

        print(f"  Summary: {analysis.summary}")
        print(f"  Threats: {len(analysis.threats)} found, max severity: {analysis.max_severity}")

        # ── ESCALATE (tiered reasoning) ──
        # If the primary (free) model found something serious AND we have
        # an escalation model configured, send a COMPACT summary to the
        # smarter model for a second opinion. We do NOT resend all the raw
        # logs — that's expensive. Instead we send the free model's analysis
        # plus the evidence it cited. This cuts token cost by ~90%.
        esc = self.config.escalation_llm
        if (esc.enabled and self.escalation_thinker
                and analysis.max_severity in esc.escalate_on):
            print(f"[cycle {self._cycle_count}] {_C.YELLOW}Escalating{_C.RESET} to {esc.model} for second opinion...")
            compact = self._build_escalation_context(analysis, history_context)
            escalated = self.escalation_thinker.think(compact, memory_context="")
            if not escalated.error:
                analysis = escalated
                print(f"  Escalated: {analysis.summary}")
                print(f"  Threats: {len(analysis.threats)} found, max severity: {analysis.max_severity}")
            else:
                print(f"  [!] Escalation failed: {escalated.error} — using primary analysis")

        # ── REMEMBER (after thinking) ──
        # Store this cycle's findings in long-term memory
        self.memory.record_analysis(analysis)
        threat_24h = self.memory.get_threat_count(hours=24)
        print(f"  Memory: {threat_24h} threats recorded in last 24h")

        # ── PROPOSE ACTIONS ──
        # If the LLM suggested any actions, record them as proposals.
        # These are NOT executed — they're stored for human review.
        proposals = 0
        for threat in analysis.threats:
            parsed = parse_action(threat.action)
            if parsed:
                tool, target = parsed
                cmd = generate_command(tool, target)
                pid = self.memory.record_proposal(
                    tool=tool, target=target, command=cmd,
                    reason=threat.description, severity=threat.severity,
                )
                proposals += 1
                print(f"  {_C.YELLOW}>{_C.RESET} Proposed: {tool} {target} (#{pid})")
        if proposals:
            print(f"  {proposals} action(s) proposed — awaiting human approval")

        # ── ACT ──
        print(f"[cycle {self._cycle_count}] Acting...")
        actions = self.actor.act(analysis, memory=self.memory)

        action_summary = []
        if actions["logged"]:
            action_summary.append("logged")
        if actions["telegram"]:
            action_summary.append("telegram sent")
        if actions["discord"]:
            action_summary.append("discord sent")
        if actions.get("suppressed", 0) > 0:
            action_summary.append(f"{actions['suppressed']} alerts suppressed (dedup)")
        if actions["errors"]:
            for err in actions["errors"]:
                action_summary.append(f"error: {err}")

        elapsed = time.time() - cycle_start
        print(f"  Actions: {', '.join(action_summary)}")
        print(f"  Cycle completed in {elapsed:.1f}s")

        # ── RECORD HEALTH ──
        self.health.record_cycle(CycleStats(
            cycle_number=self._cycle_count,
            duration=elapsed,
            lines_observed=observation.total_lines,
            threats_found=len(analysis.threats),
            llm_success=analysis.error is None,
            alerts_sent=int(actions.get("telegram", False)) + int(actions.get("discord", False)),
            alerts_suppressed=actions.get("suppressed", 0),
        ))

        # Heartbeat — periodic self-check printed to console/journalctl
        if self.health.should_heartbeat(self._cycle_count):
            print(self.health.format_heartbeat())

        return {
            "cycle": self._cycle_count,
            "observation": observation.summary(),
            "analysis_summary": analysis.summary,
            "max_severity": analysis.max_severity,
            "threats": len(analysis.threats),
            "actions": actions,
            "elapsed": elapsed,
        }

    def _build_escalation_context(self, analysis, history_context: str):
        """Build a compact observation for the escalation model.

        Instead of sending 1000+ raw log lines (expensive), we send:
          - The primary model's analysis summary
          - Evidence cited for each threat
          - Historical context from memory

        This cuts input tokens by ~90% while giving the escalation model
        enough context to validate or override the primary analysis.
        """
        from labguard.observer import Observation
        import time

        parts = ["=== ESCALATION REVIEW ==="]
        parts.append("A primary model analyzed the logs and found the following.")
        parts.append("Review its findings and provide your own assessment.")
        parts.append("You may adjust severity, add threats it missed, or remove false positives.")
        parts.append("")
        parts.append(f"Primary summary: {analysis.summary}")
        parts.append(f"Threats found: {len(analysis.threats)}")
        parts.append("")

        for i, t in enumerate(analysis.threats, 1):
            parts.append(f"--- Threat {i} ---")
            parts.append(f"Severity: {t.severity}")
            parts.append(f"Source IP: {t.source_ip}")
            parts.append(f"Description: {t.description}")
            parts.append(f"Evidence: {t.evidence}")
            parts.append(f"Recommendation: {t.recommendation}")
            if t.action:
                parts.append(f"Proposed action: {t.action}")
            parts.append("")

        if history_context:
            parts.append(history_context)

        compact = Observation(timestamp=time.time())
        compact.sources = {"escalation_review": "\n".join(parts)}
        compact.line_counts = {"escalation_review": len(parts)}
        return compact

    def _extract_ips(self, observation) -> list[str]:
        """Extract public IPs from observation data for memory lookup.

        We only extract public IPs — internal ones are already sanitized
        to [INTERNAL_N] placeholders and won't match anything in memory.
        """
        import re
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        ips = set()
        for data in observation.sources.values():
            for match in ip_pattern.findall(data):
                # Skip private/loopback ranges and our placeholders
                if not (match.startswith("10.") or match.startswith("192.168.")
                        or match.startswith("172.") or match.startswith("127.")):
                    ips.add(match)
        return list(ips)

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
        if self.escalation_thinker:
            esc = self.config.escalation_llm
            print(f"    {G}●{R} {B}Escalation{R}  {esc.model} {D}(on {', '.join(esc.escalate_on)}){R}")
        else:
            print(f"    {D}    Escalation  disabled {D}(add escalation_llm to config){R}")

        # Sanitizer status
        san = self.config.sanitizer
        san_items = len(san.hostnames) + len(san.domains) + len(san.usernames)
        if san_items > 0:
            print(f"    {G}●{R} {B}Sanitizer{R}   {san_items} custom rules + auto-scrub")
        else:
            print(f"    {Y}○{R} {B}Sanitizer{R}   auto-scrub only {D}(add hostnames/domains to config){R}")

        # Noise filter status
        n_cidrs = len(self.noise_filter._networks)
        n_noise = len(self.noise_filter._noise_patterns)
        print(f"    {G}●{R} {B}Filter{R}      {n_cidrs} whitelisted CIDRs, {n_noise} noise patterns")

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

        # Memory status
        threat_count = self.memory.get_threat_count(hours=24)
        top_offenders = self.memory.get_top_offenders(3)
        if threat_count > 0:
            patterns = self.memory.detect_patterns(hours=24)
            pattern_info = f", {len(patterns)} patterns" if patterns else ""
            print(f"    {G}●{R} {B}Memory{R}      {threat_count} threats in last 24h, {len(top_offenders)} tracked IPs{pattern_info}")
        else:
            print(f"    {G}●{R} {B}Memory{R}      database ready (no history yet)")

        # Health status
        report = self.health.check_health()
        if report.status == "healthy":
            print(f"    {G}●{R} {B}Health{R}      self-monitoring active (heartbeat every {self.health.heartbeat_interval} cycles)")
        else:
            print(f"    {Y}○{R} {B}Health{R}      {report.status}: {'; '.join(report.issues[:2])}")
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
