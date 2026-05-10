"""
Slack adapter for the mantissa-log chat bot.

Registers two Bolt handlers:

  - slash command  ``/mantissa <verb> [args]``
  - message event   for thread replies on destructive-event alerts

The handlers translate Slack payloads into a transport-neutral
``BotContext`` and call into the shared dispatcher. They translate the
returned ``BotResponse`` into Slack Block Kit and send it back through
the ``say`` / ``respond`` callback provided by Bolt.

``slack_bolt`` is imported lazily so the module can be loaded in
environments without it (CI, tests, the dispatcher unit tests).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..bot.dispatcher import BotContext, Dispatcher
from .blocks import response_to_blocks, text_fallback

logger = logging.getLogger(__name__)


@dataclass
class SlackApp:
    """Thin Bolt wrapper. ``dispatcher`` is injected so the same bot
    business logic can be reused by the Teams adapter (PR 8)."""

    dispatcher: Dispatcher

    def register(self, app: Any) -> None:
        """Register the bot's command and event handlers on a Bolt ``App``.

        ``app`` is the slack_bolt ``App`` (or AsyncApp) instance. We do not
        import slack_bolt here; the caller passes its app object in.
        """

        @app.command("/mantissa")
        def handle_command(ack, body, respond):
            ack()
            text = body.get("text") or ""
            ctx = BotContext(
                user=body.get("user_id") or body.get("user_name") or "",
                channel=body.get("channel_id") or "",
                thread_ts=None,
                parent_message=None,
            )
            response = self.dispatcher.dispatch(text, ctx)
            respond(
                response_type="in_channel",
                text=text_fallback(response),
                blocks=response_to_blocks(response),
            )

        @app.event("message")
        def handle_thread_reply(event, say, client):
            # Only react to messages that are thread replies. Bolt sends
            # the parent ts as ``thread_ts``.
            if not isinstance(event, dict):
                return
            thread_ts = event.get("thread_ts")
            if not thread_ts or event.get("subtype") == "bot_message":
                return
            text = event.get("text") or ""
            if not text.strip():
                return
            parent = _fetch_parent_message(client, event.get("channel"), thread_ts)
            ctx = BotContext(
                user=event.get("user") or "",
                channel=event.get("channel") or "",
                thread_ts=thread_ts,
                parent_message=parent,
            )
            response = self.dispatcher.dispatch(text, ctx)
            say(
                thread_ts=thread_ts,
                text=text_fallback(response),
                blocks=response_to_blocks(response),
            )

    def build_app(
        self,
        bot_token: str,
        signing_secret: str,
        app_factory: Optional[Callable[..., Any]] = None,
    ) -> Any:
        """Build a slack_bolt ``App`` and register handlers.

        Production callers use this. Tests construct their own fake
        ``App`` and call ``register`` directly.
        """
        if app_factory is None:
            from slack_bolt import App  # type: ignore[import-not-found]
            app_factory = App
        app = app_factory(token=bot_token, signing_secret=signing_secret)
        self.register(app)
        return app


def _fetch_parent_message(client: Any, channel: Optional[str], ts: str) -> Optional[dict]:
    """Look up the alert payload that opened the thread.

    Slack's ``conversations.replies`` API returns the parent first. We
    parse the bot's prior alert message and pull the alert payload from
    a hidden JSON block attached by the alert handler, or from the
    message's ``attachments[0].fallback`` if the alert was sent that way.
    """
    if client is None or channel is None:
        return None
    try:
        resp = client.conversations_replies(channel=channel, ts=ts, limit=1)
    except Exception as exc:  # noqa: BLE001
        logger.warning("slack.parent_lookup_failed channel=%s ts=%s err=%s", channel, ts, exc)
        return None
    messages = (resp or {}).get("messages") or []
    if not messages:
        return None
    parent = messages[0]
    # Mantissa alert handlers tag the alert payload onto the message via
    # ``metadata`` (Slack 2023+) or a hidden JSON block. We try both.
    md = parent.get("metadata") or {}
    payload = md.get("event_payload") if isinstance(md, dict) else None
    if isinstance(payload, dict):
        return payload
    # Fallback: a "json" block with the payload embedded.
    for block in parent.get("blocks") or []:
        if isinstance(block, dict) and block.get("block_id") == "mantissa_alert_payload":
            text = (block.get("text") or {}).get("text") or ""
            import json
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                continue
    return None
