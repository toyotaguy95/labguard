"""Actor module - sends alerts and takes defensive actions.

Agent concept: ACTION / EXECUTION
==================================
The actor is the agent's interface to the outside world. It takes the
thinker's analysis and DOES something with it — sends alerts, logs
findings, and in later phases, takes defensive actions.

Key design decisions:
  1. PHASE 1 IS READ-ONLY (mostly). The actor can send notifications and
     write logs. It CANNOT modify firewall rules, block IPs, or run
     commands. This is deliberate. An agent that can take destructive
     actions based on LLM output is dangerous — the LLM can hallucinate,
     be prompt-injected, or just be wrong. We add destructive actions
     in Phase 3 with human-in-the-loop approval.

  2. SEVERITY THRESHOLD. Not every finding deserves a Telegram buzz at
     3am. The actor filters by severity — only "medium" and above trigger
     alerts by default. Info and low findings get logged silently.

  3. MULTIPLE OUTPUT CHANNELS. Telegram, Discord, and local log file.
     Each is independent — if Telegram is down, Discord still works.
     This is the "fan-out" pattern. In agent frameworks, these would
     be separate "tools" the agent can invoke.

In framework terms:
  - LangChain: these are "Tools" with side effects (send_message, etc.)
  - CrewAI: this is the agent's "task output" being routed to destinations
  - AutoGen: this is the "UserProxy" relaying results to the human

Action space (Phase 1):
  [x] Send Telegram message
  [x] Send Discord webhook
  [x] Write to local log file
  [ ] Block IP (Phase 3)
  [ ] Update firewall rule (Phase 3)
  [ ] Run arbitrary command (Phase 3, with human approval)
"""

import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

from labguard.config import AlertsConfig
from labguard.thinker import Analysis


# Minimum severity to trigger a push notification.
# Anything below this gets logged locally but won't buzz your phone.
ALERT_THRESHOLD = {"medium", "high", "critical"}

# Severity → emoji for readable alerts
SEVERITY_ICON = {
    "critical": "[CRITICAL]",
    "high":     "[HIGH]",
    "medium":   "[MEDIUM]",
    "low":      "[low]",
    "info":     "[info]",
}


class Actor:
    """Executes actions based on the thinker's analysis.

    The actor's job is simple: take an Analysis, format it for humans,
    and deliver it through the configured channels. It makes ONE decision:
    is this severe enough to send a push alert, or just log it?
    """

    def __init__(self, config: AlertsConfig, log_file: str = "labguard_findings.log"):
        self.config = config
        self.log_path = Path(log_file)

    def act(self, analysis: Analysis, memory=None) -> dict:
        """Process an analysis and take appropriate actions.

        memory: If provided, used for alert DEDUPLICATION. The agent checks
        "did I already alert about this IP at this severity recently?" before
        sending. Without memory, every cycle that finds the same scanner would
        spam your phone. With memory, you get ONE alert and then silence until
        the cooldown expires (default: 1 hour).

        This is ACTION GATING — the agent doesn't just decide what to do,
        it decides whether to do it at all based on past actions. Same concept
        as LangChain's "should I use this tool?" but simpler.

        Returns a summary of what actions were taken, useful for the
        agent loop's own logging.
        """
        result = {
            "logged": False, "telegram": False, "discord": False,
            "errors": [], "suppressed": 0,
        }

        # Always log findings locally, regardless of severity
        self._log_locally(analysis)
        result["logged"] = True

        # If there's nothing interesting, we're done
        if not analysis.has_threats:
            return result

        # Only push-notify for medium severity and above
        if analysis.max_severity not in ALERT_THRESHOLD:
            return result

        # ── DEDUPLICATION CHECK ──
        # Filter threats to only those we haven't recently alerted about.
        # This prevents the "buzzing phone at 3am" problem where the same
        # port scanner triggers an alert every 5 minutes for hours.
        alertable_threats = []
        for threat in analysis.threats:
            if threat.severity not in ALERT_THRESHOLD:
                continue
            if memory and not memory.should_alert(threat.source_ip, threat.severity):
                result["suppressed"] += 1
                # Record the suppression so we can track it
                if self.config.telegram.enabled:
                    memory.record_alert(threat.source_ip, threat.severity,
                                        "telegram", suppressed=True)
                if self.config.discord.enabled:
                    memory.record_alert(threat.source_ip, threat.severity,
                                        "discord", suppressed=True)
                continue
            alertable_threats.append(threat)

        if not alertable_threats:
            return result

        # Build a filtered analysis with only the alertable threats
        from labguard.thinker import Analysis as AnalysisClass
        filtered = AnalysisClass(
            summary=analysis.summary,
            threats=alertable_threats,
            total_events=analysis.total_events,
            threats_found=len(alertable_threats),
            top_talkers=analysis.top_talkers,
        )

        message = self._format_alert(filtered)

        # Fan-out: send to all enabled channels independently
        if self.config.telegram.enabled:
            ok = self._send_telegram(message)
            result["telegram"] = ok
            if ok and memory:
                for t in alertable_threats:
                    memory.record_alert(t.source_ip, t.severity, "telegram")
            elif not ok:
                result["errors"].append("Telegram send failed")

        if self.config.discord.enabled:
            ok = self._send_discord(message, filtered)
            result["discord"] = ok
            if ok and memory:
                for t in alertable_threats:
                    memory.record_alert(t.source_ip, t.severity, "discord")
            elif not ok:
                result["errors"].append("Discord send failed")

        return result

    def _format_alert(self, analysis: Analysis) -> str:
        """Format an analysis into a human-readable alert message.

        This is where "plain English alerts" happen. The LLM already
        wrote descriptions in plain English — we just structure them
        into a readable notification with severity icons and formatting.
        """
        lines = [f"LabGuard Alert — {analysis.summary}", ""]

        for threat in analysis.threats:
            if threat.severity not in ALERT_THRESHOLD:
                continue
            icon = SEVERITY_ICON.get(threat.severity, "[?]")
            lines.append(f"{icon} {threat.description}")
            if threat.source_ip and threat.source_ip != "unknown":
                lines.append(f"  Source: {threat.source_ip}")
            if threat.recommendation:
                lines.append(f"  Action: {threat.recommendation}")
            lines.append("")

        if analysis.top_talkers:
            lines.append(f"Top talkers: {', '.join(analysis.top_talkers)}")

        return "\n".join(lines)

    def _log_locally(self, analysis: Analysis):
        """Append findings to a local log file.

        Every analysis gets logged, not just alerts. This gives you a
        complete history for pattern detection in Phase 2.
        """
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = {
            "timestamp": timestamp,
            "summary": analysis.summary,
            "max_severity": analysis.max_severity,
            "threats_found": len(analysis.threats),
            "threats": [
                {
                    "severity": t.severity,
                    "source_ip": t.source_ip,
                    "description": t.description,
                }
                for t in analysis.threats
            ],
        }

        try:
            with open(self.log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            print(f"[!] Failed to write local log: {e}")

    def _send_telegram(self, message: str) -> bool:
        """Send alert via Telegram Bot API.

        Telegram is ideal for security alerts because:
        - Push notifications to your phone
        - Works from anywhere (not tied to being at your desk)
        - Free, no infrastructure needed
        - Supports formatting (we keep it simple for now)
        """
        cfg = self.config.telegram
        url = f"https://api.telegram.org/bot{cfg.bot_token}/sendMessage"

        payload = json.dumps({
            "chat_id": cfg.chat_id,
            "text": message,
            "parse_mode": "HTML",
        }).encode("utf-8")

        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as e:
            print(f"[!] Telegram error: {e}")
            return False

    def _send_discord(self, message: str, analysis: Analysis | None = None) -> bool:
        """Send alert via Discord webhook with rich embeds.

        Uses Discord's embed format for a clean, colored alert card.
        The sidebar color matches the severity level.
        """
        url = self.config.discord.webhook_url

        # Severity → Discord embed color (decimal RGB)
        severity_colors = {
            "critical": 15158332,   # red
            "high":     15105570,   # orange
            "medium":   16776960,   # yellow
            "low":      3447003,    # blue
            "info":     9807270,    # grey
        }

        if analysis and analysis.threats:
            color = severity_colors.get(analysis.max_severity, 9807270)
            fields = []
            for t in analysis.threats:
                if t.severity not in ALERT_THRESHOLD:
                    continue
                icon = SEVERITY_ICON.get(t.severity, "[?]")
                value = t.description
                if t.source_ip and t.source_ip != "unknown":
                    value += f"\nSource: `{t.source_ip}`"
                if t.recommendation:
                    value += f"\nAction: {t.recommendation}"
                fields.append({"name": icon, "value": value, "inline": False})

            payload = json.dumps({
                "embeds": [{
                    "title": "LabGuard Alert",
                    "description": analysis.summary,
                    "color": color,
                    "fields": fields[:10],  # Discord limit: 25, but keep it clean
                    "footer": {"text": f"LabGuard v0.1.0 | {analysis.max_severity.upper()} severity"},
                }],
            }).encode("utf-8")
        else:
            payload = json.dumps({"content": message}).encode("utf-8")

        req = urllib.request.Request(
            url, data=payload,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "LabGuard/0.1.0",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 204)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            print(f"[!] Discord error {e.code}: {body[:200]}")
            return False
        except Exception as e:
            print(f"[!] Discord error: {e}")
            return False
