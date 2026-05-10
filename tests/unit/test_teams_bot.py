"""
Unit tests for PR 8 of SAAS_IDENTITY_SPEC.

Two surfaces under test:

  1. Adaptive Card renderer (cards.response_to_card, to_attachment,
     text_fallback)
  2. TeamsApp.handle_activity wiring including thread-reply auto-scope

We never import botbuilder. The TeamsApp's ``handle_activity`` takes
dict-shaped activities so tests pass canned payloads directly.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.integrations.bot.commands import (  # noqa: E402
    AskCommand,
    ExplainRuleCommand,
    HealthCommand,
)
from shared.integrations.bot.dispatcher import (  # noqa: E402
    BotContext,
    BotResponse,
    Dispatcher,
)
from shared.integrations.teams.app import TeamsApp  # noqa: E402
from shared.integrations.teams.cards import (  # noqa: E402
    ADAPTIVE_CARDS_SCHEMA,
    ADAPTIVE_CARDS_TYPE,
    ADAPTIVE_CARDS_VERSION,
    response_to_card,
    text_fallback,
    to_attachment,
)


# =============================================== Cards renderer


class TestCardsEnvelope:
    def test_minimal_summary(self):
        card = response_to_card(BotResponse(summary="hi"))
        assert card["$schema"] == ADAPTIVE_CARDS_SCHEMA
        assert card["type"] == ADAPTIVE_CARDS_TYPE
        assert card["version"] == ADAPTIVE_CARDS_VERSION
        body = card["body"]
        assert body[0]["type"] == "TextBlock"
        assert body[0]["text"] == "hi"
        assert body[0]["wrap"] is True
        assert body[0]["markdown"] is True

    def test_attachment_wrapper(self):
        attach = to_attachment(response_to_card(BotResponse(summary="x")))
        assert attach["contentType"] == "application/vnd.microsoft.card.adaptive"
        assert attach["content"]["type"] == ADAPTIVE_CARDS_TYPE


class TestCardsTriplet:
    def test_factset_when_triplet_present(self):
        resp = BotResponse(summary="ok", sql="SELECT 1", row_count=3, cost_cents=12.0)
        card = response_to_card(resp)
        factset = next(b for b in card["body"] if b["type"] == "FactSet")
        titles = {f["title"]: f["value"] for f in factset["facts"]}
        assert titles["Rows"] == "3"
        assert titles["Cost"] == "$0.1200"

    def test_no_factset_when_triplet_absent(self):
        card = response_to_card(BotResponse(summary="hi"))
        assert all(b["type"] != "FactSet" for b in card["body"])

    def test_error_status_in_factset(self):
        card = response_to_card(BotResponse(summary="bad", is_error=True))
        facts = next(b for b in card["body"] if b["type"] == "FactSet")["facts"]
        assert any(f["title"] == "Status" and f["value"] == "error" for f in facts)


class TestCardsSql:
    def test_sql_in_monospace_container(self):
        card = response_to_card(BotResponse(summary="ok",
                                            sql="SELECT email FROM gws_login"))
        container = next(b for b in card["body"] if b["type"] == "Container")
        inner = container["items"][0]
        assert inner["type"] == "TextBlock"
        assert inner["fontType"] == "Monospace"
        assert "SELECT email" in inner["text"]
        assert inner["wrap"] is True

    def test_no_container_when_sql_absent(self):
        card = response_to_card(BotResponse(summary="ok", row_count=1))
        assert all(b["type"] != "Container" for b in card["body"])

    def test_truncate_oversize_summary(self):
        long = "x" * 9000
        card = response_to_card(BotResponse(summary=long))
        assert len(card["body"][0]["text"]) <= 8000


class TestCardsPassthrough:
    def test_extra_blocks_appended(self):
        custom = {"type": "ActionSet", "actions": []}
        card = response_to_card(BotResponse(summary="x", blocks=[custom]))
        assert custom in card["body"]

    def test_non_dict_extra_filtered(self):
        card = response_to_card(BotResponse(summary="x", blocks=["bad", 42]))  # type: ignore[list-item]
        # No crash; only valid dicts appended.
        for b in card["body"]:
            assert isinstance(b, dict)


class TestTextFallback:
    def test_carries_triplet(self):
        fb = text_fallback(BotResponse(summary="hi", sql="SELECT 1",
                                       row_count=2, cost_cents=5.0))
        assert "hi" in fb
        assert "SELECT 1" in fb
        assert "rows: 2" in fb
        assert "$0.0500" in fb

    def test_empty_falls_back_to_marker(self):
        fb = text_fallback(BotResponse(summary=""))
        assert fb == "(empty response)"


# =============================================== TeamsApp wiring


@dataclass
class _AskResult:
    summary: str = "Found 3 rows."
    sql: str = "SELECT * FROM gws_login"
    row_count: int = 3
    cost_cents: float = 0.42


class _FakeEngine:
    def __init__(self):
        self.result = _AskResult()
        self.questions: list[str] = []

    def answer(self, question, scope_hint=None):
        self.questions.append(question)
        return self.result


class _FakeStore:
    def __init__(self, rule=None):
        self.rule = rule

    def get(self, rule_id):
        return self.rule if self.rule and self.rule.get("id") == rule_id else None


class _FakeNL:
    def describe(self, rule):
        return f"This rule fires on {rule.get('title', '?')}."


@dataclass
class _Snap:
    silent_sources: list = field(default_factory=list)
    volume_anomalies: list = field(default_factory=list)


class _FakeMonitor:
    def snapshot(self):
        return _Snap()


def _build_app(ask_engine=None):
    ask = AskCommand(engine=ask_engine or _FakeEngine())
    explain = ExplainRuleCommand(
        store=_FakeStore(rule={"id": "R1", "title": "Test"}),
        nl=_FakeNL(),
    )
    health = HealthCommand(monitor=_FakeMonitor())
    return TeamsApp(dispatcher=Dispatcher(ask=ask, explain=explain, health=health))


def _activity(text, conv_id="conv-1", user_id="user-1", reply_to_id=None, role=None):
    act: dict = {
        "type": "message",
        "text": text,
        "from": {"id": user_id},
        "conversation": {"id": conv_id},
    }
    if reply_to_id:
        act["replyToId"] = reply_to_id
    if role:
        act["from"]["role"] = role
    return act


class TestTeamsHandleActivity:
    def test_dispatches_ask_and_sends_card(self):
        teams = _build_app()
        sent: list[dict] = []

        teams.handle_activity(_activity("ask show me oauth grants"), send=sent.append)

        assert len(sent) == 1
        reply = sent[0]
        assert reply["type"] == "message"
        assert reply["text"]
        assert reply["attachments"][0]["contentType"] == \
               "application/vnd.microsoft.card.adaptive"
        card = reply["attachments"][0]["content"]
        # Triplet renders in the FactSet
        factset = next(b for b in card["body"] if b["type"] == "FactSet")
        titles = {f["title"]: f["value"] for f in factset["facts"]}
        assert titles["Rows"] == "3"

    def test_ignores_non_message_activity(self):
        teams = _build_app()
        sent: list[dict] = []
        teams.handle_activity({"type": "typing"}, send=sent.append)
        teams.handle_activity({"type": "conversationUpdate"}, send=sent.append)
        assert sent == []

    def test_ignores_empty_text(self):
        teams = _build_app()
        sent: list[dict] = []
        teams.handle_activity(_activity(""), send=sent.append)
        teams.handle_activity(_activity("   "), send=sent.append)
        assert sent == []

    def test_ignores_bot_self_messages(self):
        teams = _build_app()
        sent: list[dict] = []
        teams.handle_activity(_activity("ask hi", role="bot"), send=sent.append)
        teams.handle_activity(
            {"type": "message", "text": "ask hi", "channelData": {"isBot": True}},
            send=sent.append,
        )
        assert sent == []

    def test_thread_reply_auto_scope(self):
        ask_engine = _FakeEngine()
        teams = _build_app(ask_engine=ask_engine)
        parent = {
            "actor_email": "alice@acme.com",
            "source": "gws",
            "feed": "admin",
            "timestamp": "2026-05-09T11:00:00Z",
        }

        def parent_lookup(message_id):
            return parent if message_id == "msg-parent-1" else None

        sent: list[dict] = []
        teams.handle_activity(
            _activity("anything else from this user today", reply_to_id="msg-parent-1"),
            send=sent.append,
            parent_lookup=parent_lookup,
        )

        # Engine got the augmented question
        assert "actor=alice@acme.com" in ask_engine.questions[0]
        # Reply preserves the replyToId so Teams threads correctly
        assert sent[0]["replyToId"] == "msg-parent-1"
        # And carries the conversation reference
        assert sent[0]["conversation"]["id"] == "conv-1"

    def test_thread_reply_without_parent_lookup_no_augment(self):
        ask_engine = _FakeEngine()
        teams = _build_app(ask_engine=ask_engine)
        sent: list[dict] = []
        teams.handle_activity(
            _activity("hello", reply_to_id="msg-X"),
            send=sent.append,
            # No parent_lookup
        )
        # Question went through verbatim, no scope augmentation
        assert ask_engine.questions[0] == "hello"
        # Reply still threads to the parent
        assert sent[0]["replyToId"] == "msg-X"

    def test_thread_reply_when_parent_lookup_returns_none(self):
        ask_engine = _FakeEngine()
        teams = _build_app(ask_engine=ask_engine)
        sent: list[dict] = []
        teams.handle_activity(
            _activity("hello", reply_to_id="msg-X"),
            send=sent.append,
            parent_lookup=lambda _id: None,
        )
        assert ask_engine.questions[0] == "hello"
        assert sent[0]["replyToId"] == "msg-X"

    def test_dispatches_explain_rule(self):
        teams = _build_app()
        sent: list[dict] = []
        teams.handle_activity(_activity("explain rule R1"), send=sent.append)
        card = sent[0]["attachments"][0]["content"]
        summary_block = next(b for b in card["body"] if b["type"] == "TextBlock")
        assert "Test" in summary_block["text"]  # rule title

    def test_dispatches_health(self):
        teams = _build_app()
        sent: list[dict] = []
        teams.handle_activity(_activity("health"), send=sent.append)
        card = sent[0]["attachments"][0]["content"]
        summary = next(b for b in card["body"] if b["type"] == "TextBlock")["text"]
        assert "healthy" in summary.lower()

    def test_non_dict_activity_no_op(self):
        teams = _build_app()
        sent: list[dict] = []
        teams.handle_activity(None, send=sent.append)  # type: ignore[arg-type]
        teams.handle_activity("not a dict", send=sent.append)  # type: ignore[arg-type]
        assert sent == []


class TestTeamsRegister:
    """The ``register`` integration with a Bot Framework Application is
    tested via a fake ``on_message`` decorator to avoid pulling in
    botbuilder. Verifies the wiring path without depending on the SDK."""

    def test_register_attaches_handler(self):
        teams = _build_app()

        class _FakeBotApp:
            def __init__(self):
                self.handler = None

            def on_message(self, fn):
                self.handler = fn
                return fn

        fake = _FakeBotApp()
        teams.register(fake)
        assert callable(fake.handler)

    def test_register_with_app_lacking_on_message_is_noop(self):
        teams = _build_app()

        class _Bare:
            pass

        teams.register(_Bare())  # should not raise
