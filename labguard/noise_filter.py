"""Noise filter - strips known-good traffic before LLM analysis.

Agent concept: PRE-PROCESSING / SIGNAL EXTRACTION
===================================================
A security analyst doesn't read every single line of every log. They
filter out the noise first: known CDN traffic, internal health checks,
Suricata performance messages. Only INTERESTING lines go on their desk.

This filter runs AFTER the sanitizer (which protects privacy) but BEFORE
the thinker (which costs money and time per token). Every line we filter
here is:
  - One less token billed on the LLM API
  - One less chance for the LLM to misclassify normal traffic
  - Faster cycle times

Without this filter, the LLM sees Cloudflare traffic and panics:
"CRITICAL: persistent attacker 104.18.36.169!" — when it's just your
own website's CDN. That's alert fatigue, and it's the #1 reason people
disable security tools.

Two filter mechanisms:
  1. IP WHITELIST (CIDR ranges) — known-good infrastructure IPs
  2. NOISE PATTERNS (substrings) — log lines that are never threats
"""

import ipaddress
import re
from labguard.config import TuningConfig
from labguard.observer import Observation


# Well-known infrastructure CIDRs that are never attackers.
# Users can add more in config.yaml under tuning.whitelist_cidrs.
DEFAULT_WHITELIST = [
    # Cloudflare
    "104.16.0.0/12",
    "172.64.0.0/13",
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "131.0.72.0/22",
    # Google (common ranges)
    "142.250.0.0/15",
    "172.217.0.0/16",
    "216.58.192.0/19",
    "74.125.0.0/16",
    "209.85.128.0/17",
]

# Suricata messages that are internal/performance, not threats.
DEFAULT_NOISE = [
    "pkt seen on wrong thread",
    "SURICATA Applayer Mismatch",
    "SURICATA TLS invalid record",
    "SURICATA STREAM Packet with invalid timestamp",
    "SURICATA STREAM ESTABLISHED packet out of window",
    "SURICATA STREAM CLOSEWAIT FIN out of window",
    "SURICATA STREAM Last ACK with wrong seq",
    "SURICATA STREAM reassembly segment before base seq",
    "ET INFO",
    "GPL DNS",
]

# Regex to find IPs in a log line
_IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')


class NoiseFilter:
    """Filters out known-good traffic and noise before LLM analysis."""

    def __init__(self, config: TuningConfig):
        # Build IP networks from defaults + user config
        cidrs = DEFAULT_WHITELIST + config.whitelist_cidrs
        self._networks: list[ipaddress.IPv4Network] = []
        for cidr in cidrs:
            try:
                self._networks.append(ipaddress.IPv4Network(cidr, strict=False))
            except ValueError as e:
                print(f"[!] Invalid whitelist CIDR '{cidr}': {e}")

        # Build noise patterns from defaults + user config
        self._noise_patterns = DEFAULT_NOISE + config.noise_patterns
        self.stats = {"total_lines": 0, "filtered_lines": 0, "whitelist_hits": 0, "noise_hits": 0}

    def filter(self, observation: Observation) -> Observation:
        """Filter an observation, removing whitelisted IPs and noise.

        Returns a new Observation with only the interesting lines.
        """
        self.stats = {"total_lines": 0, "filtered_lines": 0, "whitelist_hits": 0, "noise_hits": 0}
        filtered_sources = {}

        for source, data in observation.sources.items():
            lines = data.split("\n")
            kept = []
            for line in lines:
                self.stats["total_lines"] += 1
                reason = self._should_filter(line)
                if reason == "whitelist":
                    self.stats["filtered_lines"] += 1
                    self.stats["whitelist_hits"] += 1
                elif reason == "noise":
                    self.stats["filtered_lines"] += 1
                    self.stats["noise_hits"] += 1
                else:
                    kept.append(line)
            filtered_sources[source] = "\n".join(kept)

        # Build a new observation with filtered data
        filtered = Observation(timestamp=observation.timestamp)
        filtered.sources = filtered_sources
        filtered.line_counts = {
            source: len([l for l in data.split("\n") if l.strip()])
            for source, data in filtered_sources.items()
        }
        filtered.errors = observation.errors
        return filtered

    def _should_filter(self, line: str) -> str | None:
        """Check if a line should be filtered out.

        Returns the reason ("whitelist" or "noise") or None to keep it.
        """
        if not line.strip():
            return None

        # Check noise patterns first (cheaper — just substring matching)
        for pattern in self._noise_patterns:
            if pattern in line:
                return "noise"

        # Check if ALL IPs in the line are whitelisted
        # Only filter if every IP in the line is known-good.
        # If a line has a mix (whitelisted + unknown), keep it.
        ips_found = _IP_RE.findall(line)
        if ips_found:
            non_whitelisted = [ip for ip in ips_found if not self._is_whitelisted(ip)]
            if not non_whitelisted and ips_found:
                return "whitelist"

        return None

    def _is_whitelisted(self, ip_str: str) -> bool:
        """Check if an IP falls within any whitelisted CIDR range."""
        try:
            addr = ipaddress.IPv4Address(ip_str)
        except ValueError:
            return False

        # Skip private/loopback — these are internal, not "whitelisted"
        if addr.is_private or addr.is_loopback:
            return False

        return any(addr in net for net in self._networks)
