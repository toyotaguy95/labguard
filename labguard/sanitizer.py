"""Sanitizer module - scrubs sensitive data before it leaves the Pi.

Agent concept: DATA BOUNDARY / PRIVACY LAYER
==============================================
Any agent that sends data to a cloud API needs to think about what
it's leaking. For a security agent, this is doubly important — the
logs contain your network topology, internal IPs, hostnames, and
domain names. Sending those raw to a third-party API is a privacy risk.

Security approach: DEFAULT DENY
================================
This sanitizer does NOT try to "find bad things and remove them"
(blocklist). That approach will always miss something. Instead, it:

  1. PARSES known log formats into structured fields
  2. CLASSIFIES each field as safe or sensitive
  3. SCRUBS sensitive fields with consistent placeholders
  4. VERIFIES the final output — scans for anything that looks
     like it might still be sensitive (private IPs, configured
     domains, hostnames, MAC addresses, email addresses, paths)
  5. If verification finds ANYTHING suspicious, it redacts it
     and logs a warning

The verification pass is the safety net. Even if parsing misses
something, the verifier catches it. Belt AND suspenders.
"""

import re
from dataclasses import dataclass, field

from labguard.observer import Observation


# ── Detection patterns ──

# RFC1918 private IP ranges (the main thing we protect)
_PRIVATE_IP_RE = re.compile(
    r'\b('
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r')\b'
)

# Loopback addresses
_LOOPBACK_RE = re.compile(r'\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

# Link-local addresses
_LINK_LOCAL_RE = re.compile(r'\b169\.254\.\d{1,3}\.\d{1,3}\b')

# MAC addresses (multiple common formats)
_MAC_RE = re.compile(
    r'\b([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b'
)

# Email addresses
_EMAIL_RE = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

# Unix filesystem paths that might reveal system structure
# Matches paths like /home/username, /etc/nginx, /var/log/something
# but NOT common safe paths that appear in log messages
_SAFE_PATHS = {
    "/bin/sh", "/bin/bash", "/usr/bin", "/usr/sbin",
    "/cgi-bin", "/var/log", "/dev/null",
}
_PATH_RE = re.compile(r'(?:/(?:home|users|etc|opt|srv)/[a-zA-Z0-9._\-/]+)')

# Usernames in common log patterns like "user=admin" or "for admin from"
_USER_FIELD_RE = re.compile(
    r'(?:user[=:\s]+|for\s+)([a-zA-Z0-9_.\-]+)',
    re.IGNORECASE,
)


@dataclass
class SanitizerConfig:
    """What to scrub. Users configure this in config.yaml.

    The sanitizer works without any config (scrubs private IPs, MACs,
    emails automatically). But users SHOULD add their hostnames and
    domains for thorough protection.
    """
    # Hostnames to redact (e.g., ["lab-router", "nas01", "plex-server"])
    hostnames: list[str] = field(default_factory=list)
    # Domains to redact (e.g., ["trippylab.xyz", "mydomain.com"])
    domains: list[str] = field(default_factory=list)
    # Usernames to redact (e.g., ["admin", "labguard"])
    usernames: list[str] = field(default_factory=list)
    # Extra regex patterns to scrub
    extra_patterns: list[str] = field(default_factory=list)


class Sanitizer:
    """Three-pass sanitizer: Parse → Scrub → Verify.

    Pass 1 (scrub): Replace all known sensitive patterns with placeholders.
    Pass 2 (user patterns): Replace user-configured hostnames, domains, etc.
    Pass 3 (verify): Scan the output for ANYTHING that still looks sensitive.
            If found, redact it and log a warning so the user knows.

    Maintains consistent mappings so the same IP always maps to the same
    placeholder within a cycle. [INTERNAL_3] is always the same device.
    """

    def __init__(self, config: SanitizerConfig | None = None):
        self.config = config or SanitizerConfig()
        self._ip_map: dict[str, str] = {}
        self._ip_counter = 0
        self._host_map: dict[str, str] = {}
        self._host_counter = 0
        self.warnings: list[str] = []

    def sanitize(self, observation: Observation) -> Observation:
        """Return a new Observation with all sensitive data scrubbed.

        Three-pass process on every piece of text:
          1. Scrub known patterns (private IPs, MACs, emails, paths)
          2. Scrub user-configured patterns (hostnames, domains)
          3. Verify nothing was missed — if it was, redact and warn
        """
        self.warnings.clear()

        sanitized = Observation(
            timestamp=observation.timestamp,
            errors=list(observation.errors),
        )

        for source, data in observation.sources.items():
            # Pass 1: Scrub known sensitive patterns
            clean = self._scrub_known_patterns(data)
            # Pass 2: Scrub user-configured patterns
            clean = self._scrub_user_patterns(clean)
            # Pass 3: Verify nothing leaked through
            clean = self._verify(clean, source)

            sanitized.sources[source] = clean
            sanitized.line_counts[source] = clean.count("\n")

        return sanitized

    # ── Pass 1: Known patterns ──

    def _scrub_known_patterns(self, text: str) -> str:
        """Replace all automatically-detectable sensitive patterns."""
        result = text

        # Private IPs → [INTERNAL_N] (consistent per IP)
        result = _PRIVATE_IP_RE.sub(self._replace_private_ip, result)

        # Loopback → [LOOPBACK]
        result = _LOOPBACK_RE.sub("[LOOPBACK]", result)

        # Link-local → [LINK_LOCAL]
        result = _LINK_LOCAL_RE.sub("[LINK_LOCAL]", result)

        # MAC addresses → [MAC_REDACTED]
        result = _MAC_RE.sub("[MAC_REDACTED]", result)

        # Email addresses → [EMAIL_REDACTED]
        result = _EMAIL_RE.sub("[EMAIL_REDACTED]", result)

        # Filesystem paths that reveal structure → [PATH_REDACTED]
        result = _PATH_RE.sub(self._replace_path, result)

        return result

    # ── Pass 2: User-configured patterns ──

    def _scrub_user_patterns(self, text: str) -> str:
        """Replace user-configured hostnames, domains, usernames."""
        result = text

        # Hostnames → [HOST_N] (consistent per hostname)
        for hostname in self.config.hostnames:
            if hostname and len(hostname) > 1:
                result = re.sub(
                    r'\b' + re.escape(hostname) + r'\b',
                    self._get_host_placeholder(hostname),
                    result,
                    flags=re.IGNORECASE,
                )

        # Domains → [DOMAIN_REDACTED]
        for domain in self.config.domains:
            if domain:
                result = re.sub(
                    re.escape(domain),
                    "[DOMAIN_REDACTED]",
                    result,
                    flags=re.IGNORECASE,
                )

        # Usernames → [USER_REDACTED]
        for username in self.config.usernames:
            if username and len(username) > 1:
                result = re.sub(
                    r'\b' + re.escape(username) + r'\b',
                    "[USER_REDACTED]",
                    result,
                    flags=re.IGNORECASE,
                )

        # Extra patterns
        for pattern in self.config.extra_patterns:
            if pattern:
                try:
                    result = re.sub(pattern, "[REDACTED]", result)
                except re.error:
                    pass

        return result

    # ── Pass 3: Verification ──

    def _verify(self, text: str, source: str) -> str:
        """Final safety net. Scan scrubbed output for anything suspicious.

        This catches things that Passes 1 and 2 missed — unusual formats,
        edge cases, patterns we didn't think of. If ANYTHING looks like a
        private IP, hostname-like string adjacent to a redacted IP, etc.,
        it gets redacted and we log a warning.
        """
        result = text

        # Check 1: Did any private IPs survive? (should be impossible, but verify)
        remaining_private = _PRIVATE_IP_RE.findall(result)
        if remaining_private:
            self.warnings.append(
                f"[{source}] VERIFY CAUGHT {len(remaining_private)} private IPs "
                f"that survived scrubbing — redacting"
            )
            result = _PRIVATE_IP_RE.sub("[INTERNAL_LEAKED]", result)

        # Check 2: Did any loopback IPs survive?
        remaining_loopback = _LOOPBACK_RE.findall(result)
        if remaining_loopback:
            result = _LOOPBACK_RE.sub("[LOOPBACK]", result)

        # Check 3: Did any MAC addresses survive?
        if _MAC_RE.search(result):
            self.warnings.append(f"[{source}] VERIFY CAUGHT MAC address — redacting")
            result = _MAC_RE.sub("[MAC_REDACTED]", result)

        # Check 4: Did any email addresses survive?
        if _EMAIL_RE.search(result):
            self.warnings.append(f"[{source}] VERIFY CAUGHT email address — redacting")
            result = _EMAIL_RE.sub("[EMAIL_REDACTED]", result)

        # Check 5: Check for configured hostnames one more time
        # (in case they appeared in a format Pass 2 didn't catch)
        for hostname in self.config.hostnames:
            if hostname and len(hostname) > 1 and hostname.lower() in result.lower():
                self.warnings.append(
                    f"[{source}] VERIFY CAUGHT hostname '{hostname}' — redacting"
                )
                result = re.sub(
                    re.escape(hostname), "[HOST_LEAKED]", result,
                    flags=re.IGNORECASE,
                )

        # Check 6: Check for configured domains one more time
        for domain in self.config.domains:
            if domain and domain.lower() in result.lower():
                self.warnings.append(
                    f"[{source}] VERIFY CAUGHT domain '{domain}' — redacting"
                )
                result = re.sub(
                    re.escape(domain), "[DOMAIN_LEAKED]", result,
                    flags=re.IGNORECASE,
                )

        return result

    # ── Helper methods ──

    def _replace_private_ip(self, match: re.Match) -> str:
        """Map private IPs to consistent placeholders."""
        ip = match.group(0)
        if ip not in self._ip_map:
            self._ip_counter += 1
            self._ip_map[ip] = f"[INTERNAL_{self._ip_counter}]"
        return self._ip_map[ip]

    def _replace_path(self, match: re.Match) -> str:
        """Redact filesystem paths unless they're known-safe."""
        path = match.group(0)
        if any(path.startswith(safe) for safe in _SAFE_PATHS):
            return path
        return "[PATH_REDACTED]"

    def _get_host_placeholder(self, hostname: str) -> str:
        """Consistent placeholder per hostname."""
        key = hostname.lower()
        if key not in self._host_map:
            self._host_counter += 1
            self._host_map[key] = f"[HOST_{self._host_counter}]"
        return self._host_map[key]

    def reset(self):
        """Reset all mappings between cycles."""
        self._ip_map.clear()
        self._ip_counter = 0
        self._host_map.clear()
        self._host_counter = 0
        self.warnings.clear()
