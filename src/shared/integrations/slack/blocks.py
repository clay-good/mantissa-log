"""
Convert a transport-neutral :class:`BotResponse` into Slack Block Kit.

Slack Block Kit is a list of typed dicts. The schema is documented at
https://api.slack.com/block-kit. This module produces the same structure
without depending on the slack_sdk library so the renderer is unit-
testable in plain Python.

The always-shown triplet from the determinism boundary (SQL, row count,
cost in cents) renders as a small context block beneath the main
answer. The user can verify the answer without having to introspect a
separate console. This is the death-to-the-dashboard contract: every
answer is grounded.
"""

from __future__ import annotations

from typing import Optional

from ..bot.dispatcher import BotResponse


_MAX_SLACK_MRKDWN = 3000  # Slack limit per text block


def _truncate(text: str, limit: int = _MAX_SLACK_MRKDWN) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def response_to_blocks(response: BotResponse) -> list[dict]:
    """Return Slack Block Kit blocks for the response.

    Layout:
      1. section: the summary (markdown)
      2. context: SQL / row count / cost triplet, when present
      3. (any additional blocks from response.blocks, passed through)
    """
    blocks: list[dict] = []

    if response.summary:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": _truncate(response.summary)},
        })

    context_elements = _grounding_elements(response)
    if context_elements:
        blocks.append({"type": "context", "elements": context_elements})

    # SQL block, full-width, in a code block. Separate so it can be
    # collapsed visually and so very long SQL does not blow the summary's
    # 3 KB limit.
    if response.sql:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": _truncate(f"```{response.sql}```"),
            },
        })

    # Pass through any custom blocks the command produced.
    for extra in response.blocks or []:
        blocks.append(extra)

    return blocks


def _grounding_elements(response: BotResponse) -> list[dict]:
    """Build the SQL / row-count / cost context elements."""
    elements: list[dict] = []
    if response.row_count is not None:
        elements.append({"type": "mrkdwn", "text": f":mag: rows: *{response.row_count}*"})
    if response.cost_cents is not None:
        elements.append({"type": "mrkdwn", "text": f":dollar: cost: *${response.cost_cents/100:.4f}*"})
    if response.is_error:
        elements.append({"type": "mrkdwn", "text": ":warning: error"})
    return elements


def text_fallback(response: BotResponse) -> str:
    """Plain-text fallback for notifications, screen readers, and the
    Slack desktop client's notification body. Always non-empty."""
    parts = [response.summary or ""]
    if response.sql:
        parts.append(f"SQL: {response.sql}")
    if response.row_count is not None:
        parts.append(f"rows: {response.row_count}")
    if response.cost_cents is not None:
        parts.append(f"cost: ${response.cost_cents/100:.4f}")
    return "\n".join(p for p in parts if p) or "(empty response)"
