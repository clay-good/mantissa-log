"""
Transport-agnostic command dispatcher for the mantissa-log chat bot.

Shared by the Slack and Teams adapters (Slack ships in PR 7, Teams in
PR 8). The dispatcher takes a parsed command and a transport-neutral
context dict, runs the right command implementation, and returns a
transport-neutral ``BotResponse``. Each transport then formats the
response into its own native rich layout (Slack Block Kit, Teams
Adaptive Cards) without re-implementing any of the bot logic.

Three commands per SAAS_IDENTITY_SPEC §5:

  ask <natural language>     ->  NL -> SQL -> answer + SQL + cost
  explain rule <id>           ->  sigma -> English description
  health                      ->  log-source silence and volume report

A thread reply on a destructive-event alert is treated as an implicit
``ask`` whose query is augmented with the alert's auto-scope context
(actor, source, time window). The augmentation logic lives in
``thread_context.py``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ---- response shape ---------------------------------------------------------


@dataclass
class BotResponse:
    """Transport-neutral response for the chat surface.

    ``summary`` is plain text always safe to send (Slack fallback, Teams
    fallback). ``blocks`` is a list of structured sections each transport
    can render natively (table, code block, button, etc.). ``sql``,
    ``row_count`` and ``cost_cents`` are the "always shown" triplet from
    spec §6 of the death-to-the-dashboard essay; bots SHOULD render
    them inline when present.
    """

    summary: str
    blocks: list[dict] = field(default_factory=list)
    sql: Optional[str] = None
    row_count: Optional[int] = None
    cost_cents: Optional[float] = None
    is_error: bool = False


@dataclass
class BotContext:
    """Per-invocation context passed by the transport adapter.

    The transport fills in identity/channel/thread fields. The dispatcher
    treats them as opaque strings.
    """

    user: str               # workspace identity, e.g. "U01ABC" or "alice@acme.com"
    channel: str            # channel id or conversation reference
    thread_ts: Optional[str] = None    # parent message id when in a thread
    parent_message: Optional[dict] = None  # the alert payload when in a thread


# ---- command parsing --------------------------------------------------------


_CMD_RE = re.compile(r"^\s*([a-z_]+)(?:\s+(.+))?\s*$", re.IGNORECASE | re.DOTALL)


@dataclass(frozen=True)
class ParsedCommand:
    verb: str               # "ask", "explain", "health", or "unknown"
    subcommand: Optional[str] = None
    body: Optional[str] = None  # the natural-language question or rule id


def parse_command(text: str) -> ParsedCommand:
    """Parse a free-form command string. Examples:

      "ask show me oauth grants this week" -> ParsedCommand("ask", body="show me ...")
      "explain rule d1000001-..."           -> ParsedCommand("explain", "rule", "d1000001-...")
      "health"                              -> ParsedCommand("health")
      "show me oauth grants"                -> ParsedCommand("ask", body="show me oauth grants")
    """
    if text is None:
        return ParsedCommand("unknown")
    text = text.strip()
    if not text:
        return ParsedCommand("unknown")
    match = _CMD_RE.match(text)
    if not match:
        return ParsedCommand("ask", body=text)
    head = (match.group(1) or "").lower()
    rest = (match.group(2) or "").strip() or None

    if head == "health" and rest is None:
        return ParsedCommand("health")
    if head == "ask":
        return ParsedCommand("ask", body=rest)
    if head == "explain":
        # subcommand follows: "rule <id>"
        if rest and rest.lower().startswith("rule"):
            sub = "rule"
            after = rest[len("rule"):].strip()
            return ParsedCommand("explain", subcommand=sub, body=after or None)
        return ParsedCommand("explain", body=rest)
    # No recognized verb. Treat the entire input as an implicit `ask`.
    return ParsedCommand("ask", body=text)


# ---- dispatcher --------------------------------------------------------------


class CommandHandler:
    """Base class. Subclasses implement ``run`` to produce a BotResponse."""

    def run(self, parsed: ParsedCommand, context: BotContext) -> BotResponse:
        raise NotImplementedError


@dataclass
class Dispatcher:
    """Routes parsed commands to registered handlers.

    Handlers are injected at construction so the dispatcher itself stays
    pure. Tests inject lightweight fakes; production wires up real query
    generator, rule loader, and health monitor.
    """

    ask: CommandHandler
    explain: CommandHandler
    health: CommandHandler

    def dispatch(self, text: str, context: BotContext) -> BotResponse:
        parsed = parse_command(text)
        try:
            if parsed.verb == "ask":
                return self.ask.run(parsed, context)
            if parsed.verb == "explain":
                return self.explain.run(parsed, context)
            if parsed.verb == "health":
                return self.health.run(parsed, context)
            return BotResponse(
                summary=(
                    "I didn't recognize that command. Try `ask <question>`, "
                    "`explain rule <id>`, or `health`."
                ),
                is_error=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("bot.dispatch_failed verb=%s", parsed.verb)
            return BotResponse(
                summary=f"Sorry, something went wrong: {type(exc).__name__}: {exc}",
                is_error=True,
            )
