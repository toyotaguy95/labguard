"""Memory module - persistent storage for threat history and patterns.

Agent concept: LONG-TERM MEMORY
=================================
Without memory, an agent is stateless — every cycle it starts from zero.
With memory, it builds understanding over time:
  - "I've seen this attacker IP 47 times in the last week"
  - "SSH brute force attempts doubled compared to last week"
  - "I already alerted about this threat 10 minutes ago, no need to spam"

Memory types in agent design:
  1. EPISODIC MEMORY — what happened? (our threat_history table)
     Records every threat the agent has ever seen. Like a security
     analyst's notebook.

  2. SEMANTIC MEMORY — what do I know? (our ip_reputation table)
     Accumulated knowledge about entities. "This IP is a known scanner."
     Builds up over time from episodic memory.

  3. WORKING MEMORY — what am I thinking about right now?
     The current cycle's observations + relevant history from the database.
     This is what gets sent to the LLM as context.

Why SQLite?
  - Zero setup — it's a single file, included with Python
  - Fast enough for our scale (thousands of records, not millions)
  - Survives restarts (unlike in-memory dicts)
  - Easy to inspect: sqlite3 labguard.db "SELECT * FROM threat_history"
  - No server process to manage (unlike PostgreSQL, Redis)

In framework terms:
  - LangChain uses VectorStores (FAISS, Chroma) for semantic search
  - CrewAI has a built-in long_term_memory backed by SQLite
  - We're doing something similar but simpler and purpose-built
"""

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from labguard.thinker import Analysis, Threat


@dataclass
class IPStats:
    """Accumulated knowledge about an IP address."""
    ip: str
    total_sightings: int
    first_seen: float
    last_seen: float
    max_severity: str
    last_description: str


class Memory:
    """Persistent memory backed by SQLite.

    Stores threat history, IP reputation, and alert records.
    Used by the agent to:
      - Deduplicate alerts (don't spam the same threat)
      - Provide historical context to the LLM
      - Track trends over time
    """

    def __init__(self, db_path: str = "labguard.db"):
        self.db_path = Path(db_path)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_tables()

    def _init_tables(self):
        """Create tables if they don't exist.

        Using IF NOT EXISTS so this is safe to call every startup.
        The schema can evolve — we add columns with ALTER TABLE in
        future versions rather than breaking existing databases.
        """
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                source_ip TEXT,
                severity TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                recommendation TEXT,
                cycle_summary TEXT
            );

            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                total_sightings INTEGER DEFAULT 1,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                max_severity TEXT NOT NULL,
                last_description TEXT
            );

            CREATE TABLE IF NOT EXISTS alert_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                channel TEXT NOT NULL,
                source_ip TEXT,
                severity TEXT,
                suppressed INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_threat_ts ON threat_history(timestamp);
            CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_history(source_ip);
            CREATE INDEX IF NOT EXISTS idx_alert_ts ON alert_log(timestamp);
        """)
        self._conn.commit()

    def record_analysis(self, analysis: Analysis):
        """Store all threats from an analysis cycle.

        This is called after every think step. It records each threat
        and updates the IP reputation table.
        """
        now = time.time()

        for threat in analysis.threats:
            # Record the threat
            self._conn.execute(
                """INSERT INTO threat_history
                   (timestamp, source_ip, severity, description, evidence,
                    recommendation, cycle_summary)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (now, threat.source_ip, threat.severity, threat.description,
                 threat.evidence, threat.recommendation, analysis.summary),
            )

            # Update IP reputation
            if threat.source_ip and threat.source_ip != "unknown":
                self._upsert_ip(threat.source_ip, threat.severity,
                                threat.description, now)

        self._conn.commit()

    def _upsert_ip(self, ip: str, severity: str, description: str, now: float):
        """Insert or update an IP's reputation record.

        Tracks how many times we've seen this IP and its worst behavior.
        """
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        existing = self._conn.execute(
            "SELECT * FROM ip_reputation WHERE ip = ?", (ip,)
        ).fetchone()

        if existing:
            # Update: increment sightings, update last_seen, maybe upgrade severity
            old_sev = severity_order.get(existing["max_severity"], 0)
            new_sev = severity_order.get(severity, 0)
            max_sev = severity if new_sev > old_sev else existing["max_severity"]

            self._conn.execute(
                """UPDATE ip_reputation
                   SET total_sightings = total_sightings + 1,
                       last_seen = ?,
                       max_severity = ?,
                       last_description = ?
                   WHERE ip = ?""",
                (now, max_sev, description, ip),
            )
        else:
            self._conn.execute(
                """INSERT INTO ip_reputation
                   (ip, total_sightings, first_seen, last_seen,
                    max_severity, last_description)
                   VALUES (?, 1, ?, ?, ?, ?)""",
                (ip, now, now, severity, description),
            )

    def should_alert(self, source_ip: str, severity: str,
                     cooldown_seconds: int = 3600) -> bool:
        """Should we send an alert for this threat, or suppress it?

        Deduplication logic: if we already alerted about the same IP
        at the same severity within the cooldown period, suppress it.
        Default cooldown is 1 hour.

        This prevents the "buzzing phone at 3am" problem where the
        same scanner triggers an alert every 5 minutes.
        """
        cutoff = time.time() - cooldown_seconds

        recent = self._conn.execute(
            """SELECT COUNT(*) as cnt FROM alert_log
               WHERE source_ip = ? AND severity = ?
               AND timestamp > ? AND suppressed = 0""",
            (source_ip, severity, cutoff),
        ).fetchone()

        return recent["cnt"] == 0

    def record_alert(self, source_ip: str, severity: str,
                     channel: str, suppressed: bool = False):
        """Record that we sent (or suppressed) an alert."""
        self._conn.execute(
            """INSERT INTO alert_log
               (timestamp, channel, source_ip, severity, suppressed)
               VALUES (?, ?, ?, ?, ?)""",
            (time.time(), channel, source_ip, severity, int(suppressed)),
        )
        self._conn.commit()

    def get_ip_stats(self, ip: str) -> IPStats | None:
        """Get accumulated knowledge about an IP."""
        row = self._conn.execute(
            "SELECT * FROM ip_reputation WHERE ip = ?", (ip,)
        ).fetchone()

        if not row:
            return None

        return IPStats(
            ip=row["ip"],
            total_sightings=row["total_sightings"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            max_severity=row["max_severity"],
            last_description=row["last_description"],
        )

    def get_top_offenders(self, limit: int = 10) -> list[IPStats]:
        """Get the most frequently seen threat IPs."""
        rows = self._conn.execute(
            """SELECT * FROM ip_reputation
               ORDER BY total_sightings DESC LIMIT ?""",
            (limit,),
        ).fetchall()

        return [
            IPStats(
                ip=r["ip"], total_sightings=r["total_sightings"],
                first_seen=r["first_seen"], last_seen=r["last_seen"],
                max_severity=r["max_severity"],
                last_description=r["last_description"],
            )
            for r in rows
        ]

    def get_context_for_llm(self, current_ips: list[str]) -> str:
        """Build historical context to inject into the LLM prompt.

        This is WORKING MEMORY — relevant history pulled from long-term
        storage for the current cycle. The LLM gets told "you've seen
        this IP before" so it can factor that into its analysis.
        """
        if not current_ips:
            return ""

        parts = ["=== Historical Context (from memory) ==="]
        has_context = False

        for ip in current_ips[:20]:  # Limit to avoid flooding the prompt
            stats = self.get_ip_stats(ip)
            if stats and stats.total_sightings > 1:
                days_active = (stats.last_seen - stats.first_seen) / 86400
                parts.append(
                    f"  {ip}: seen {stats.total_sightings} times "
                    f"over {days_active:.1f} days, "
                    f"max severity: {stats.max_severity}"
                )
                has_context = True

        if not has_context:
            return ""

        # Also add top offenders for general awareness
        top = self.get_top_offenders(5)
        if top:
            parts.append("\n  Top repeat offenders:")
            for t in top:
                parts.append(f"    {t.ip}: {t.total_sightings} sightings")

        return "\n".join(parts) + "\n"

    def detect_patterns(self, hours: int = 24) -> list[str]:
        """Detect trends and patterns from historical data.

        Agent concept: META-REASONING
        ==============================
        This is the agent reasoning about its OWN history, not raw logs.
        A single cycle sees "5 SSH failures." Pattern detection sees
        "SSH failures tripled compared to yesterday." The LLM gets both
        perspectives, making its analysis much richer.

        Each pattern is a plain-English string that gets injected into
        the LLM prompt alongside working memory. The LLM can then say
        things like "this is part of an escalating campaign" instead of
        treating every cycle as isolated.

        Returns a list of human-readable pattern descriptions.
        """
        patterns = []
        now = time.time()

        # ── 1. FREQUENCY ESCALATION ──
        # Compare threat count in recent period vs previous period.
        # If threats doubled, that's a pattern worth noting.
        recent_cutoff = now - (hours * 3600)
        previous_cutoff = now - (hours * 3600 * 2)

        recent_count = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM threat_history WHERE timestamp > ?",
            (recent_cutoff,),
        ).fetchone()["cnt"]

        previous_count = self._conn.execute(
            """SELECT COUNT(*) as cnt FROM threat_history
               WHERE timestamp > ? AND timestamp <= ?""",
            (previous_cutoff, recent_cutoff),
        ).fetchone()["cnt"]

        if previous_count > 0 and recent_count > previous_count * 1.5:
            ratio = recent_count / previous_count
            patterns.append(
                f"ESCALATION: Threat frequency increased {ratio:.1f}x "
                f"({previous_count} -> {recent_count} in last {hours}h vs prior {hours}h)"
            )
        elif previous_count > 5 and recent_count < previous_count * 0.3:
            patterns.append(
                f"QUIET: Threat frequency dropped significantly "
                f"({previous_count} -> {recent_count}). Could indicate attacker "
                f"changed tactics or moved on."
            )

        # ── 2. NEW ATTACKERS ──
        # IPs seen for the first time in the recent period.
        new_ips = self._conn.execute(
            """SELECT ip, max_severity, last_description
               FROM ip_reputation
               WHERE first_seen > ? AND total_sightings = 1
               ORDER BY CASE max_severity
                   WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                   WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC
               LIMIT 5""",
            (recent_cutoff,),
        ).fetchall()

        if len(new_ips) >= 3:
            ips_str = ", ".join(r["ip"] for r in new_ips[:5])
            patterns.append(
                f"NEW ACTORS: {len(new_ips)} new attacker IPs appeared "
                f"in last {hours}h: {ips_str}"
            )

        # ── 3. SEVERITY ESCALATION ──
        # IPs whose max severity increased (started low, now high).
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        escalators = self._conn.execute(
            """SELECT ip, total_sightings, max_severity, last_description
               FROM ip_reputation
               WHERE total_sightings > 2 AND last_seen > ?
               ORDER BY total_sightings DESC LIMIT 20""",
            (recent_cutoff,),
        ).fetchall()

        for row in escalators:
            # Check if earliest threats from this IP were lower severity
            first_threat = self._conn.execute(
                """SELECT severity FROM threat_history
                   WHERE source_ip = ? ORDER BY timestamp ASC LIMIT 1""",
                (row["ip"],),
            ).fetchone()
            if first_threat:
                first_sev = severity_order.get(first_threat["severity"], 0)
                current_sev = severity_order.get(row["max_severity"], 0)
                if current_sev > first_sev and current_sev >= 2:  # medium+
                    patterns.append(
                        f"ESCALATION: {row['ip']} started at {first_threat['severity']} "
                        f"and escalated to {row['max_severity']} "
                        f"over {row['total_sightings']} sightings"
                    )

        # ── 4. PERSISTENT SCANNERS ──
        # IPs that keep coming back cycle after cycle.
        persistent = self._conn.execute(
            """SELECT ip, total_sightings, max_severity,
                      (last_seen - first_seen) / 86400.0 as days_active
               FROM ip_reputation
               WHERE total_sightings >= 5 AND last_seen > ?
               ORDER BY total_sightings DESC LIMIT 5""",
            (recent_cutoff,),
        ).fetchall()

        for row in persistent:
            patterns.append(
                f"PERSISTENT: {row['ip']} has been seen {row['total_sightings']} times "
                f"over {row['days_active']:.1f} days (max severity: {row['max_severity']})"
            )

        # ── 5. SEVERITY DISTRIBUTION SHIFT ──
        # If high/critical threats are a larger share than usual
        if recent_count >= 5:
            high_recent = self._conn.execute(
                """SELECT COUNT(*) as cnt FROM threat_history
                   WHERE timestamp > ? AND severity IN ('high', 'critical')""",
                (recent_cutoff,),
            ).fetchone()["cnt"]

            high_ratio = high_recent / recent_count
            if high_ratio > 0.5:
                patterns.append(
                    f"HIGH SEVERITY: {high_ratio:.0%} of recent threats are "
                    f"high/critical ({high_recent}/{recent_count})"
                )

        return patterns

    def get_threat_count(self, hours: int = 24) -> int:
        """How many threats in the last N hours?"""
        cutoff = time.time() - (hours * 3600)
        row = self._conn.execute(
            "SELECT COUNT(*) as cnt FROM threat_history WHERE timestamp > ?",
            (cutoff,),
        ).fetchone()
        return row["cnt"]

    def close(self):
        """Close the database connection."""
        self._conn.close()
