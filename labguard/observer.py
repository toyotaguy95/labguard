"""Observer module - reads security logs from local files.

Agent concept: PERCEPTION / SENSING
====================================
The observer is the agent's sensory system. It answers: "What is happening
in my environment right now?"

Key design decisions:
  1. The observer does NOT interpret data. It collects raw log lines and
     passes them forward. Interpretation is the Thinker's job.
  2. It tracks WHERE it left off in each file (file position tracking).
     Without this, every cycle would re-read the entire log file and the
     LLM would see the same events over and over.
  3. It reads ALL log sources and bundles them into one "observation" dict.
     The Thinker gets a complete snapshot, not fragments.

In framework terms:
  - LangChain: this is like a "Document Loader" or "Retriever"
  - CrewAI: this is the "tool" that gathers information
  - AutoGen: this is the message/context that gets passed to the agent

The push-based syslog design means this module only reads local files.
It never SSHs anywhere or makes network calls. If the observer is
compromised, the attacker only sees log data — no credentials to steal.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import time


@dataclass
class Observation:
    """A snapshot of what the agent observed in one cycle.

    This is the agent's "perception" — everything it saw, bundled together
    with metadata about when and how much.
    """
    timestamp: float
    sources: dict[str, str] = field(default_factory=dict)
    line_counts: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def has_data(self) -> bool:
        """Did we observe anything new?"""
        return any(count > 0 for count in self.line_counts.values())

    @property
    def total_lines(self) -> int:
        return sum(self.line_counts.values())

    def summary(self) -> str:
        """Human-readable summary for logging."""
        parts = [f"{src}: {count} lines"
                 for src, count in self.line_counts.items() if count > 0]
        if not parts:
            return "No new log activity"
        return f"Observed {self.total_lines} new lines — " + ", ".join(parts)


class Observer:
    """Reads security logs and tracks position between cycles.

    File position tracking: We store the byte offset where we stopped
    reading last time. Next cycle, we seek to that offset and only read
    new lines. This is the same technique that 'tail -f' uses, and it's
    how every log aggregator (Filebeat, Fluentd, Promtail) works.

    Edge case — log rotation: When rsyslog rotates a file (e.g., the file
    gets smaller than our saved position), we detect it and read from the
    beginning. This handles logrotate without missing data.
    """

    # Maximum bytes to read per source per cycle. Prevents the agent from
    # choking if a log file explodes (e.g., during a DDoS that generates
    # millions of lines). The LLM has a context window limit anyway.
    MAX_READ_BYTES = 50_000  # ~50KB, roughly 500-1000 log lines

    def __init__(self, log_dir: str):
        self.log_dir = Path(log_dir)
        # Track byte position in each file between cycles
        # Key: filename, Value: byte offset where we stopped reading
        self._positions: dict[str, int] = {}

    def observe(self) -> Observation:
        """Run one observation cycle. Read new lines from all log files.

        Returns an Observation containing new log data from each source.
        This gets passed directly to the Thinker.
        """
        observation = Observation(timestamp=time.time())

        if not self.log_dir.exists():
            observation.errors.append(f"Log directory {self.log_dir} not found")
            return observation

        # Find all .log files in the log directory
        log_files = sorted(self.log_dir.glob("*.log"))

        if not log_files:
            observation.errors.append(f"No log files in {self.log_dir}")
            return observation

        for log_file in log_files:
            source_name = log_file.stem  # "suricata.log" → "suricata"
            new_lines = self._read_new_lines(log_file)

            if new_lines is not None:
                observation.sources[source_name] = new_lines
                observation.line_counts[source_name] = new_lines.count("\n")
            else:
                observation.line_counts[source_name] = 0

        return observation

    def _read_new_lines(self, log_file: Path) -> Optional[str]:
        """Read only new lines from a log file since last cycle.

        This is the core of the observer's efficiency. Instead of reading
        the whole file every time, we remember where we stopped and pick
        up from there. For a 30MB Suricata log, this means reading maybe
        a few KB per cycle instead of the whole thing.
        """
        filename = str(log_file)

        try:
            file_size = log_file.stat().st_size
        except OSError as e:
            return None

        last_pos = self._positions.get(filename, 0)

        # Handle log rotation: if file is smaller than our saved position,
        # the file was rotated (replaced with a new, smaller file).
        # Start reading from the beginning.
        if file_size < last_pos:
            last_pos = 0

        # Nothing new since last read
        if file_size == last_pos:
            return None

        try:
            with open(log_file, "r", errors="replace") as f:
                f.seek(last_pos)
                data = f.read(self.MAX_READ_BYTES)

                # Save where we stopped for next cycle
                self._positions[filename] = f.tell()

                # If we hit the read limit, note that we truncated
                if len(data) >= self.MAX_READ_BYTES:
                    data += "\n[... truncated — too many logs this cycle ...]\n"

            return data if data.strip() else None

        except OSError:
            return None
