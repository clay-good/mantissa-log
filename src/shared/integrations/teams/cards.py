"""
Convert a transport-neutral :class:`BotResponse` into a Microsoft Teams
Adaptive Card.

Adaptive Cards are a JSON schema (https://adaptivecards.io) carried as
attachments on Bot Framework Activities. Teams renders them natively
without requiring the bot to know anything about the client. The same
card is also valid for Outlook actionable messages and the Teams web
client.

We keep the schema dependency-free and pin the version to 1.5, which is
the highest Teams reliably renders across desktop / web / mobile as of
2026. The renderer is unit-testable in plain Python without the
botbuilder SDK.

Layout mirrors the Slack renderer in :mod:`shared.integrations.slack.blocks`
so the two surfaces feel consistent to end users:

  1. summary  -> TextBlock (markdown=true, wrap=true)
  2. triplet  -> FactSet with rows / cost / error rows
  3. sql      -> Container with a monospace TextBlock
  4. extra    -> any passthrough blocks the command produced
"""

from __future__ import annotations

from typing import Any

from ..bot.dispatcher import BotResponse


ADAPTIVE_CARDS_SCHEMA = "http://adaptivecards.io/schemas/adaptive-card.json"
ADAPTIVE_CARDS_VERSION = "1.5"
ADAPTIVE_CARDS_TYPE = "AdaptiveCard"
_TEAMS_MAX_TEXTBLOCK = 8000  # Teams card payload limit per text block


def _truncate(text: str, limit: int = _TEAMS_MAX_TEXTBLOCK) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def response_to_card(response: BotResponse) -> dict:
    """Return an Adaptive Card payload for ``response``.

    Returned dict is the attachment ``content`` value, not the full
    ``Attachment`` envelope. The :class:`TeamsApp` wraps it in the
    Bot Framework Activity attachment shape when sending.
    """
    body: list[dict] = []

    if response.summary:
        body.append({
            "type": "TextBlock",
            "text": _truncate(response.summary),
            "wrap": True,
            "markdown": True,
        })

    triplet = _grounding_facts(response)
    if triplet:
        body.append({
            "type": "FactSet",
            "facts": triplet,
        })

    if response.sql:
        body.append({
            "type": "Container",
            "style": "emphasis",
            "items": [
                {
                    "type": "TextBlock",
                    "text": _truncate(response.sql),
                    "wrap": True,
                    "fontType": "Monospace",
                    "size": "Small",
                }
            ],
        })

    for extra in response.blocks or []:
        if isinstance(extra, dict):
            body.append(extra)

    return {
        "$schema": ADAPTIVE_CARDS_SCHEMA,
        "type": ADAPTIVE_CARDS_TYPE,
        "version": ADAPTIVE_CARDS_VERSION,
        "body": body,
    }


def _grounding_facts(response: BotResponse) -> list[dict]:
    """Build the rows / cost / error facts shown on every grounded answer.

    These mirror the Slack context-block elements in
    :mod:`shared.integrations.slack.blocks`. The user sees the SQL that
    ran, the row count, and the cost, every time, per the determinism
    contract from spec §6.
    """
    facts: list[dict] = []
    if response.row_count is not None:
        facts.append({"title": "Rows", "value": str(response.row_count)})
    if response.cost_cents is not None:
        facts.append({"title": "Cost", "value": f"${response.cost_cents/100:.4f}"})
    if response.is_error:
        facts.append({"title": "Status", "value": "error"})
    return facts


def text_fallback(response: BotResponse) -> str:
    """Plain-text fallback for notifications and accessible readers.

    Mirrors the Slack fallback so both transports emit the same text on
    devices that cannot render the rich card.
    """
    parts = [response.summary or ""]
    if response.sql:
        parts.append(f"SQL: {response.sql}")
    if response.row_count is not None:
        parts.append(f"rows: {response.row_count}")
    if response.cost_cents is not None:
        parts.append(f"cost: ${response.cost_cents/100:.4f}")
    return "\n".join(p for p in parts if p) or "(empty response)"


def to_attachment(card: dict) -> dict:
    """Wrap a card payload in the Bot Framework Activity attachment shape."""
    return {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": card,
    }
