"""Tools module - actions the agent can propose.

Agent concept: TOOL USE
========================
This is what separates a chatbot from an agent. A chatbot generates text.
An agent generates text AND takes actions. Tools are the agent's hands.

In production agent frameworks:
  - LangChain: Tools are Python functions decorated with @tool
  - CrewAI: Tools are classes with a _run() method
  - AutoGen: Tools are registered functions the agent can call

Our approach is simpler but follows the same pattern:
  1. The LLM selects a tool by name ("block_ip 1.2.3.4")
  2. We parse the tool name and arguments
  3. We generate the EXACT command to run (human reviews this)
  4. We store the proposal in memory for tracking

CRITICAL DESIGN DECISION: Phase 3 is PROPOSE-ONLY.
The agent CANNOT execute commands. It generates the command string and
presents it to the human via Discord. The human copies and runs it.

Why? Because an LLM can hallucinate, be wrong, or be prompt-injected.
If the agent could auto-block IPs, an attacker could craft a log line
that tricks the LLM into blocking your own Cloudflare IP — taking
your website offline. Human-in-the-loop prevents this.

Future phases could add auto-execution for low-risk actions (watch_ip)
while keeping human approval for destructive ones (block_ip).
"""

import time
from dataclasses import dataclass


@dataclass
class ActionProposal:
    """A proposed action waiting for human approval."""
    id: int
    timestamp: float
    tool: str
    target: str
    command: str
    reason: str
    severity: str
    status: str = "pending"  # pending, approved, rejected, expired


# Map tool names to the actual commands.
# Each tool returns (command_string, description).
TOOL_REGISTRY = {
    "block_ip": {
        "command": "sudo nft add element inet filter blocklist {{ {target} }}",
        "description": "Block all traffic from {target}",
        "risk": "high",
    },
    "rate_limit_ip": {
        "command": "sudo nft add element inet filter ratelimit {{ {target} }}",
        "description": "Rate-limit traffic from {target}",
        "risk": "medium",
    },
    "watch_ip": {
        "command": None,  # No system command — just adds to LabGuard's watchlist
        "description": "Add {target} to LabGuard watchlist for closer monitoring",
        "risk": "low",
    },
}


def parse_action(action_str: str | None) -> tuple[str, str] | None:
    """Parse an action string like 'block_ip 1.2.3.4' into (tool, target).

    Returns None if the action is null, empty, or invalid.
    """
    if not action_str or action_str.strip().lower() in ("null", "none", ""):
        return None

    parts = action_str.strip().split(None, 1)
    if len(parts) != 2:
        return None

    tool, target = parts
    if tool not in TOOL_REGISTRY:
        return None

    # Basic IP validation
    target = target.strip()
    octets = target.split(".")
    if len(octets) != 4:
        return None
    try:
        if not all(0 <= int(o) <= 255 for o in octets):
            return None
    except ValueError:
        return None

    return (tool, target)


def generate_command(tool: str, target: str) -> str | None:
    """Generate the actual shell command for a tool invocation.

    Returns the command string or None for non-command tools (watch_ip).
    """
    if tool not in TOOL_REGISTRY:
        return None

    template = TOOL_REGISTRY[tool]["command"]
    if template is None:
        return None

    return template.format(target=target)


def format_proposal(tool: str, target: str, reason: str) -> str:
    """Format a proposal for display in Discord/console.

    Returns a human-readable string explaining what the agent wants to do
    and the exact command to run.
    """
    if tool not in TOOL_REGISTRY:
        return f"Unknown tool: {tool}"

    info = TOOL_REGISTRY[tool]
    desc = info["description"].format(target=target)
    command = generate_command(tool, target)

    lines = [
        f"Proposed Action: {desc}",
        f"Risk: {info['risk']}",
        f"Reason: {reason}",
    ]

    if command:
        lines.append(f"Command: {command}")
        lines.append("Run this on the router to execute.")
    else:
        lines.append("No system command needed — LabGuard handles this internally.")

    return "\n".join(lines)
