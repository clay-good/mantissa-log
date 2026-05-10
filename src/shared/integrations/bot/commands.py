"""
Command implementations for the chat-bot dispatcher.

Each command is a small class with a single dependency it can inject in
its constructor (the NL query engine for ``ask``, the rule store for
``explain``, the health monitor for ``health``). Production wires up
the real implementations. Tests inject lightweight fakes. The
implementations stay transport-neutral — they return ``BotResponse``
objects that Slack and Teams adapters format for their native rich UI.

The trust rule from the death-to-the-dashboard essay applies:

    The LLM never answers from memory. It only:
      (a) translates English to SQL against the published lake schema,
      (b) summarizes the rows the SQL actually returned.

So the ``ask`` command always populates ``BotResponse.sql``,
``row_count``, and ``cost_cents`` when they are available. The Slack
and Teams blocks render those three fields verbatim under every
answer. This is load-bearing and is the difference between a useful
tool and a hallucination machine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from .dispatcher import BotContext, BotResponse, CommandHandler, ParsedCommand
from .thread_context import extract_scope

logger = logging.getLogger(__name__)


# ---- AskCommand -------------------------------------------------------------


@dataclass
class AskCommand(CommandHandler):
    """``ask <NL>`` -> NL→SQL → answer.

    The engine is duck-typed. The integration expects an object with:

        engine.answer(question: str, scope_hint: str | None = None) -> AskResult

    where ``AskResult`` has fields:
        summary: str
        sql: str
        row_count: int
        cost_cents: float | None

    Production wires this to the QueryGenerator + SQL execution pipeline.
    Tests pass a fake that returns canned ``AskResult`` objects.
    """

    engine: Any  # duck-typed NL→SQL → answer engine

    def run(self, parsed: ParsedCommand, context: BotContext) -> BotResponse:
        question = (parsed.body or "").strip()
        if not question:
            return BotResponse(
                summary="What would you like to ask? Try `ask show me oauth grants this week`.",
                is_error=True,
            )

        # Thread auto-scope. If the parent message is an alert payload,
        # prepend a structured scope hint that the engine can consume.
        scope = extract_scope(context.parent_message) if context.thread_ts else None
        scoped_question = scope.augment_question(question) if scope and scope.has_context else question

        result = self.engine.answer(question=scoped_question, scope_hint=None)

        # Pull the always-shown triplet onto the response so all transports
        # render them inline.
        return BotResponse(
            summary=getattr(result, "summary", "") or "",
            sql=getattr(result, "sql", None),
            row_count=getattr(result, "row_count", None),
            cost_cents=getattr(result, "cost_cents", None),
        )


# ---- ExplainRuleCommand -----------------------------------------------------


@dataclass
class ExplainRuleCommand(CommandHandler):
    """``explain rule <id>`` -> English description.

    The rule store is duck-typed. The integration expects:

        store.get(rule_id: str) -> dict | None         # raw Sigma YAML dict
        nl.describe(rule_yaml_dict) -> str             # one-paragraph NL summary

    Splitting load from describe lets tests inject a static rule dict.
    """

    store: Any        # rule lookup
    nl: Any           # sigma-to-NL translator (sigma_to_nl module or wrapper)

    def run(self, parsed: ParsedCommand, context: BotContext) -> BotResponse:
        if parsed.subcommand != "rule" or not parsed.body:
            return BotResponse(
                summary="Usage: `explain rule <rule-id>`",
                is_error=True,
            )
        rule_id = parsed.body.strip()
        rule = self.store.get(rule_id)
        if rule is None:
            return BotResponse(
                summary=f"No rule found with id `{rule_id}`.",
                is_error=True,
            )
        description = self.nl.describe(rule)
        title = rule.get("title", rule_id)
        return BotResponse(
            summary=f"*{title}*\n{description}",
        )


# ---- HealthCommand ----------------------------------------------------------


@dataclass
class HealthCommand(CommandHandler):
    """``health`` -> log-source silence / volume report.

    The health monitor is duck-typed. The integration expects:

        monitor.snapshot() -> HealthSnapshot

    where HealthSnapshot has:
        silent_sources: list[str]
        volume_anomalies: list[VolumeAnomaly]
        last_evaluated: datetime
    """

    monitor: Any

    def run(self, parsed: ParsedCommand, context: BotContext) -> BotResponse:
        snap = self.monitor.snapshot()
        silent = list(getattr(snap, "silent_sources", []) or [])
        anomalies = list(getattr(snap, "volume_anomalies", []) or [])
        if not silent and not anomalies:
            return BotResponse(summary="All sources healthy. No silence or volume anomalies.")
        lines: list[str] = []
        if silent:
            lines.append("*Silent sources:*")
            for s in silent:
                lines.append(f" • {s}")
        if anomalies:
            lines.append("*Volume anomalies:*")
            for a in anomalies:
                src = getattr(a, "source", "?")
                z = getattr(a, "z_score", None)
                tag = f" (z={z:.2f})" if isinstance(z, (int, float)) else ""
                lines.append(f" • {src}{tag}")
        return BotResponse(summary="\n".join(lines))
