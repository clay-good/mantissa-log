"""
Microsoft Teams adapter for the mantissa-log chat bot.

PR 8 of SAAS_IDENTITY_SPEC. Mirrors :class:`SlackApp` but for the Bot
Framework Activity model used by Teams. The transport-agnostic
``Dispatcher`` from PR 7 does all the work; this module only handles
the Activity / Adaptive Card translation.

Why a separate adapter rather than a shared abstraction. Slack and
Teams have genuinely different threading models. Slack threads have a
parent ``thread_ts``; Teams "replies" carry ``replyToId`` and live
under a channel conversation reference. The Bot Framework also expects
async ``TurnContext`` handlers, while Bolt is callback-based. Trying
to abstract those into a single base class would either smuggle async
into the Slack side or block the Teams side; sibling adapters with a
shared dispatcher is cleaner.

``botbuilder-core`` is imported lazily inside :meth:`build_app` so the
module loads in environments without it (CI, tests, the dispatcher
unit tests).

The transport-neutral entry point is :meth:`TeamsApp.handle_activity`
which takes a dict-shaped activity (mirroring the Bot Framework
``Activity`` JSON), a ``send`` callable, and an optional
``parent_lookup`` callable. Production wraps this in an async
``TurnContext`` handler. Tests call it directly with canned payloads.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..bot.dispatcher import BotContext, Dispatcher
from .cards import response_to_card, text_fallback, to_attachment

logger = logging.getLogger(__name__)


# Type aliases for clarity.
SendFn = Callable[[dict], None]
ParentLookupFn = Callable[[str], Optional[dict]]


@dataclass
class TeamsApp:
    """Bot Framework adapter wrapping the shared :class:`Dispatcher`."""

    dispatcher: Dispatcher

    # ---- transport-neutral entry point --------------------------------------

    def handle_activity(
        self,
        activity: dict,
        send: SendFn,
        parent_lookup: Optional[ParentLookupFn] = None,
    ) -> None:
        """Dispatch a Teams message activity and send back a card response.

        ``activity`` is a dict shaped like a Bot Framework ``Activity`` JSON
        body. Required keys: ``type``, ``text``. Optional: ``from.id``,
        ``conversation.id``, ``replyToId``, ``channelData``.

        ``send`` receives a fully-formed reply Activity dict to post to
        the conversation. The production adapter implements this as
        ``await turn_context.send_activity(...)``.

        ``parent_lookup`` returns the alert payload for a given parent
        ``replyToId`` so thread replies under destructive-event alerts
        can auto-scope to the alert's actor / source / feed / time. The
        production adapter implements this via Microsoft Graph or a
        local message-id-to-payload side store. Tests pass a dict-based
        fake.
        """
        if not isinstance(activity, dict):
            return
        if activity.get("type") not in ("message", "messageReaction"):
            return
        text = (activity.get("text") or "").strip()
        if not text:
            return
        # Suppress echoes of our own bot's messages. The Bot Framework
        # marks them in ``channelData.eventType == "messageEdited"`` or
        # by ``from.role == "bot"`` depending on Teams version.
        if _is_bot_self_message(activity):
            return

        thread_id = activity.get("replyToId")
        parent_message = parent_lookup(thread_id) if (thread_id and parent_lookup) else None

        ctx = BotContext(
            user=((activity.get("from") or {}).get("id")
                  or (activity.get("from") or {}).get("name") or ""),
            channel=((activity.get("conversation") or {}).get("id") or ""),
            thread_ts=thread_id,
            parent_message=parent_message,
        )

        response = self.dispatcher.dispatch(text, ctx)
        send(self._reply_activity(activity, response))

    # ---- Bot Framework registration -----------------------------------------

    def register(self, bot_app: Any) -> None:
        """Register ``handle_activity`` with a botbuilder Application.

        The ``bot_app`` is whatever the production wiring builds (e.g.
        ``ActivityHandler`` subclass, or the new ``botbuilder.core.Bot``
        Application API). We do not import botbuilder here; the caller
        passes its app object in.

        The typical wire-up: the caller's ``ActivityHandler.on_message_activity``
        constructs an activity dict from ``turn_context.activity`` and a
        ``send`` callable from ``turn_context.send_activity`` and then
        calls into :meth:`handle_activity`.
        """
        if hasattr(bot_app, "on_message"):
            bot_app.on_message(self._on_bot_app_message)

    async def _on_bot_app_message(self, turn_context: Any) -> None:
        """Bridge from a Bot Framework ``TurnContext`` into our handler."""
        activity = turn_context.activity
        # Coerce the ``Activity`` object (or already-dict payload) into a dict.
        activity_dict = _activity_to_dict(activity)

        async def _send(reply: dict) -> None:
            await turn_context.send_activity(reply)

        # We need an async wrapper since handle_activity is sync.
        def _sync_send(reply: dict) -> None:
            # Schedule the coroutine; whichever async runtime wraps this
            # adapter will handle it.
            import asyncio
            asyncio.ensure_future(_send(reply))

        self.handle_activity(activity_dict, _sync_send)

    def build_app(self, app_factory: Optional[Callable[..., Any]] = None) -> Any:
        """Build a botbuilder application and register handlers.

        Production callers use this. Tests construct their own fake app
        and call :meth:`handle_activity` or :meth:`register` directly.
        """
        if app_factory is None:
            from botbuilder.core import ActivityHandler  # type: ignore[import-not-found]
            app_factory = ActivityHandler
        app = app_factory()
        self.register(app)
        return app

    # ---- internals ----------------------------------------------------------

    def _reply_activity(self, request: dict, response: Any) -> dict:
        """Build the Activity dict for the bot's reply."""
        card = response_to_card(response)
        reply = {
            "type": "message",
            "text": text_fallback(response),
            "attachments": [to_attachment(card)],
        }
        thread_id = request.get("replyToId") or request.get("id")
        if thread_id:
            # When replying to a specific message, the Bot Framework
            # threads via the ``conversation.id`` plus the original
            # message id. Teams renders this as a reply under the parent.
            reply["replyToId"] = thread_id
        conversation = request.get("conversation")
        if conversation:
            reply["conversation"] = conversation
        return reply


def _is_bot_self_message(activity: dict) -> bool:
    from_obj = activity.get("from") or {}
    if (from_obj.get("role") or "").lower() == "bot":
        return True
    # Some Teams versions mark bot messages this way:
    channel_data = activity.get("channelData") or {}
    return bool(channel_data.get("isBot"))


def _activity_to_dict(activity: Any) -> dict:
    """Best-effort coercion of a botbuilder ``Activity`` to a plain dict.

    ``Activity`` objects have a ``.serialize()`` method we use when
    available; otherwise we treat the object as a Mapping or pass it
    through if already a dict.
    """
    if isinstance(activity, dict):
        return activity
    if hasattr(activity, "serialize"):
        try:
            return activity.serialize()
        except Exception:  # noqa: BLE001
            pass
    # Fall back to vars() for simple namespaces.
    return dict(getattr(activity, "__dict__", {}))
