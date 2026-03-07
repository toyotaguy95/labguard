"""Health monitor - the agent watches itself.

Agent concept: INTROSPECTION / SELF-AWARENESS
==============================================
A good agent doesn't just monitor external systems — it monitors ITSELF.
If your security agent is silently failing (LLM timing out, disk full,
logs stopped flowing), you have a blind spot protecting your blind spot.

This is a pattern you'll see in production agent systems:
  - LangChain's callbacks track token usage, latency, errors per chain
  - AutoGen agents can detect when they're stuck in a loop
  - CrewAI tracks task completion rates and agent performance

Our health monitor tracks:
  1. CYCLE PERFORMANCE — are cycles getting slower? Is the LLM failing?
  2. SYSTEM RESOURCES — disk space, database size, memory usage
  3. LOG SOURCE FRESHNESS — are logs still flowing, or did rsyslog break?
  4. HEARTBEAT — periodic "I'm alive and healthy" summary

The health data feeds back into the agent loop. If the agent detects
its own degradation, it can alert you — "hey, I'm struggling" — which
is way better than silently dying at 3am.
"""

import os
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CycleStats:
    """Stats from a single agent cycle."""
    cycle_number: int
    duration: float
    lines_observed: int
    threats_found: int
    llm_success: bool
    alerts_sent: int = 0
    alerts_suppressed: int = 0
    timestamp: float = field(default_factory=time.time)


@dataclass
class HealthReport:
    """Snapshot of the agent's health."""
    status: str  # "healthy", "degraded", "unhealthy"
    uptime_seconds: float
    total_cycles: int
    issues: list[str]
    metrics: dict

    @property
    def status_icon(self) -> str:
        return {"healthy": "[OK]", "degraded": "[WARN]", "unhealthy": "[CRIT]"}.get(
            self.status, "[?]"
        )


class HealthMonitor:
    """Tracks the agent's own vital signs.

    Call record_cycle() after each cycle. Call check_health() to get
    a full diagnostic. The agent loop calls heartbeat() every N cycles
    to print a status summary.
    """

    def __init__(self, log_dir: str = "/var/log/labguard", db_path: str = "labguard.db",
                 heartbeat_interval: int = 10):
        self.log_dir = Path(log_dir)
        self.db_path = Path(db_path)
        self.heartbeat_interval = heartbeat_interval
        self.start_time = time.time()
        self._history: list[CycleStats] = []
        self._max_history = 100  # rolling window

    def record_cycle(self, stats: CycleStats):
        """Record stats from a completed cycle."""
        self._history.append(stats)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

    def check_health(self) -> HealthReport:
        """Run all health checks and return a report.

        This is the agent's self-diagnosis. Each check looks at a
        different aspect of the agent's performance and flags issues.
        """
        issues = []
        metrics = {}

        # ── UPTIME ──
        uptime = time.time() - self.start_time
        metrics["uptime_seconds"] = round(uptime)
        metrics["total_cycles"] = len(self._history)

        # ── CYCLE PERFORMANCE ──
        if self._history:
            recent = self._history[-5:]  # last 5 cycles
            avg_duration = sum(c.duration for c in recent) / len(recent)
            metrics["avg_cycle_duration"] = round(avg_duration, 1)

            # Cycles getting slow?
            if avg_duration > 120:
                issues.append(f"Slow cycles: avg {avg_duration:.0f}s (target <120s)")
            elif avg_duration > 60:
                issues.append(f"Cycles moderately slow: avg {avg_duration:.0f}s")

            # LLM failures
            recent_10 = self._history[-10:]
            failures = sum(1 for c in recent_10 if not c.llm_success)
            metrics["llm_failure_rate"] = f"{failures}/{len(recent_10)}"
            if failures > len(recent_10) * 0.5:
                issues.append(f"LLM failing frequently: {failures}/{len(recent_10)} recent cycles")
            elif failures > 0:
                issues.append(f"LLM had {failures} failure(s) in last {len(recent_10)} cycles")

            # No data cycles (observer finding nothing)
            empty = sum(1 for c in recent_10 if c.lines_observed == 0)
            metrics["empty_cycles"] = empty
            if empty == len(recent_10) and len(recent_10) >= 3:
                issues.append("No new log data in recent cycles — check rsyslog")

        # ── SYSTEM RESOURCES ──
        # Disk space on working directory
        try:
            stat = os.statvfs(".")
            free_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
            total_gb = (stat.f_blocks * stat.f_frsize) / (1024 ** 3)
            used_pct = ((total_gb - free_gb) / total_gb) * 100 if total_gb > 0 else 0
            metrics["disk_free_gb"] = round(free_gb, 1)
            metrics["disk_used_pct"] = round(used_pct, 1)
            if free_gb < 0.5:
                issues.append(f"Disk critically low: {free_gb:.1f}GB free")
            elif free_gb < 2:
                issues.append(f"Disk space low: {free_gb:.1f}GB free")
        except OSError:
            pass

        # Database size
        if self.db_path.exists():
            db_mb = self.db_path.stat().st_size / (1024 * 1024)
            metrics["db_size_mb"] = round(db_mb, 1)
            if db_mb > 100:
                issues.append(f"Database large: {db_mb:.0f}MB — consider pruning old records")

        # ── LOG SOURCE FRESHNESS ──
        # Check when each log file was last modified.
        # If a log hasn't been updated in a long time, rsyslog may be broken.
        if self.log_dir.exists():
            stale_sources = []
            for log_file in sorted(self.log_dir.glob("*.log")):
                try:
                    age_minutes = (time.time() - log_file.stat().st_mtime) / 60
                    if age_minutes > 30:
                        stale_sources.append(f"{log_file.name} ({age_minutes:.0f}m)")
                except OSError:
                    pass
            metrics["stale_log_sources"] = len(stale_sources)
            if stale_sources:
                issues.append(f"Stale log sources: {', '.join(stale_sources)}")

        # ── DETERMINE STATUS ──
        critical_issues = [i for i in issues if any(
            w in i.lower() for w in ["critically", "failing frequently", "no new log"]
        )]
        if critical_issues:
            status = "unhealthy"
        elif issues:
            status = "degraded"
        else:
            status = "healthy"

        return HealthReport(
            status=status,
            uptime_seconds=uptime,
            total_cycles=len(self._history),
            issues=issues,
            metrics=metrics,
        )

    def should_heartbeat(self, cycle_number: int) -> bool:
        """Should we print a heartbeat this cycle?"""
        return cycle_number > 0 and cycle_number % self.heartbeat_interval == 0

    def format_heartbeat(self) -> str:
        """Format a heartbeat summary for the console.

        This prints every N cycles so you (or journalctl) can see
        the agent is alive and how it's doing at a glance.
        """
        report = self.check_health()

        hours = report.uptime_seconds / 3600
        lines = [
            f"\n[heartbeat] {report.status_icon} Status: {report.status} | "
            f"Uptime: {hours:.1f}h | Cycles: {report.total_cycles}"
        ]

        m = report.metrics
        if "avg_cycle_duration" in m:
            lines.append(
                f"  Performance: {m['avg_cycle_duration']}s avg cycle, "
                f"LLM failures: {m.get('llm_failure_rate', 'N/A')}"
            )
        if "disk_free_gb" in m:
            lines.append(
                f"  Resources: {m['disk_free_gb']}GB disk free ({m['disk_used_pct']}% used), "
                f"DB: {m.get('db_size_mb', 0)}MB"
            )
        if report.issues:
            for issue in report.issues:
                lines.append(f"  [!] {issue}")

        return "\n".join(lines)
