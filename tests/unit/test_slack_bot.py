"""
Unit tests for PR 7 of SAAS_IDENTITY_SPEC.

Four layers under test:

  1. Dispatcher parsing       (parse_command, Dispatcher.dispatch)
  2. Thread auto-scope         (extract_scope, ThreadAutoScope.augment_question)
  3. Command implementations   (AskCommand, ExplainRuleCommand, HealthCommand)
  4. Slack Block Kit renderer  (response_to_blocks, text_fallback) and the
     SlackApp Bolt-handler wiring (via a fake App)

The tests inject fakes for the NL engine, rule store, and health monitor
so no LLM, lake, or Slack SDK is required to run them.
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
    ParsedCommand,
    parse_command,
)
from shared.integrations.bot.thread_context import (  # noqa: E402
    ThreadAutoScope,
    extract_scope,
)
from shared.integrations.slack.app import SlackApp  # noqa: E402
from shared.integrations.slack.blocks import (  # noqa: E402
    response_to_blocks,
    text_fallback,
)


# =================================================== Layer 1: parsing


class TestParseCommand:
    def test_health_bare(self):
        assert parse_command("health") == ParsedCommand("health")
        assert parse_command("  health  ") == ParsedCommand("health")

    def test_ask_explicit(self):
        p = parse_command("ask show me oauth grants")
        assert p.verb == "ask"
        assert p.body == "show me oauth grants"

    def test_ask_implicit_fallthrough(self):
        # No recognized verb → treated as ask
        p = parse_command("show me oauth grants this week")
        assert p.verb == "ask"
        assert p.body == "show me oauth grants this week"

    def test_explain_rule(self):
        p = parse_command("explain rule d1000001-0000-4000-8000-000000000001")
        assert p.verb == "explain"
        assert p.subcommand == "rule"
        assert p.body == "d1000001-0000-4000-8000-000000000001"

    def test_explain_without_subcommand(self):
        p = parse_command("explain")
        assert p.verb == "explain"
        assert p.subcommand is None

    def test_empty_and_none(self):
        assert parse_command("").verb == "unknown"
        assert parse_command("   ").verb == "unknown"
        assert parse_command(None).verb == "unknown"  # type: ignore[arg-type]

    def test_case_insensitive_verb(self):
        assert parse_command("ASK foo").verb == "ask"
        assert parse_command("Health").verb == "health"


# =================================================== Layer 1: dispatcher


class _StubHandler:
    def __init__(self, response=None):
        self.last_parsed = None
        self.last_context = None
        self.response = response or BotResponse(summary="ok")

    def run(self, parsed, context):
        self.last_parsed = parsed
        self.last_context = context
        return self.response


class _RaisingHandler:
    def run(self, parsed, context):
        raise RuntimeError("boom")


class TestDispatcher:
    def _make(self, ask=None, explain=None, health=None):
        return Dispatcher(
            ask=ask or _StubHandler(),
            explain=explain or _StubHandler(),
            health=health or _StubHandler(),
        )

    def test_routes_to_ask(self):
        ask = _StubHandler()
        d = self._make(ask=ask)
        ctx = BotContext(user="U1", channel="C1")
        d.dispatch("ask show me logins", ctx)
        assert ask.last_parsed.verb == "ask"
        assert ask.last_parsed.body == "show me logins"

    def test_routes_to_explain(self):
        explain = _StubHandler()
        d = self._make(explain=explain)
        d.dispatch("explain rule R1", BotContext(user="U1", channel="C1"))
        assert explain.last_parsed.subcommand == "rule"
        assert explain.last_parsed.body == "R1"

    def test_routes_to_health(self):
        h = _StubHandler()
        d = self._make(health=h)
        d.dispatch("health", BotContext(user="U1", channel="C1"))
        assert h.last_parsed.verb == "health"

    def test_unknown_returns_help(self):
        d = self._make()
        resp = d.dispatch("", BotContext(user="U1", channel="C1"))
        assert resp.is_error and "ask" in resp.summary

    def test_handler_exception_becomes_error_response(self):
        d = Dispatcher(
            ask=_RaisingHandler(),
            explain=_StubHandler(),
            health=_StubHandler(),
        )
        resp = d.dispatch("ask anything", BotContext(user="U1", channel="C1"))
        assert resp.is_error and "RuntimeError" in resp.summary


# =================================================== Layer 2: thread scope


class TestExtractScope:
    def test_empty_when_no_parent(self):
        assert not extract_scope(None).has_context
        assert not extract_scope({}).has_context

    def test_pulls_from_top_level(self):
        scope = extract_scope({
            "actor_email": "alice@acme.com",
            "source": "gws",
            "feed": "admin",
            "timestamp": "2026-05-09T11:00:00Z",
        })
        assert scope.actor == "alice@acme.com"
        assert scope.source == "gws"
        assert scope.feed == "admin"
        assert scope.when == datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)

    def test_pulls_from_metadata(self):
        scope = extract_scope({"metadata": {"actor_email": "bob@acme.com"}})
        assert scope.actor == "bob@acme.com"

    def test_pulls_from_first_result(self):
        scope = extract_scope({"results": [{"userPrincipalName": "carol@acme.com"}]})
        assert scope.actor == "carol@acme.com"

    def test_handles_iso_with_z(self):
        scope = extract_scope({"timestamp": "2026-05-09T11:00:00Z"})
        assert scope.when == datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)

    def test_handles_bad_time_silently(self):
        scope = extract_scope({"timestamp": "not-a-date"})
        assert scope.when is None


class TestAugmentQuestion:
    def test_appends_scope_suffix(self):
        scope = ThreadAutoScope(
            actor="alice@acme.com",
            source="gws",
            feed="admin",
            when=datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc),
        )
        q = scope.augment_question("anything else from this user today")
        assert q.startswith("anything else from this user today")
        assert "actor=alice@acme.com" in q
        assert "source=gws" in q
        assert "feed=admin" in q
        assert "2026-05-09T11:00:00Z" in q

    def test_no_context_returns_question_verbatim(self):
        scope = ThreadAutoScope()
        assert scope.augment_question("hi") == "hi"


# =================================================== Layer 3: commands


@dataclass
class _AskResult:
    summary: str = "Found 3 rows."
    sql: str = "SELECT * FROM gws_login LIMIT 3"
    row_count: int = 3
    cost_cents: float = 0.42


class _FakeEngine:
    def __init__(self, result=None):
        self.result = result or _AskResult()
        self.questions: list[str] = []

    def answer(self, question: str, scope_hint: Optional[str] = None):
        self.questions.append(question)
        return self.result


class TestAskCommand:
    def test_runs_engine_and_returns_triplet(self):
        eng = _FakeEngine()
        cmd = AskCommand(engine=eng)
        ctx = BotContext(user="U1", channel="C1")
        resp = cmd.run(ParsedCommand("ask", body="show me oauth grants"), ctx)
        assert resp.summary == "Found 3 rows."
        assert resp.sql.startswith("SELECT")
        assert resp.row_count == 3
        assert resp.cost_cents == 0.42
        assert eng.questions == ["show me oauth grants"]

    def test_empty_body_returns_help(self):
        cmd = AskCommand(engine=_FakeEngine())
        resp = cmd.run(ParsedCommand("ask", body=""), BotContext(user="U1", channel="C1"))
        assert resp.is_error and "ask" in resp.summary.lower()

    def test_thread_reply_augments_with_scope(self):
        eng = _FakeEngine()
        cmd = AskCommand(engine=eng)
        parent = {
            "actor_email": "alice@acme.com",
            "source": "gws",
            "feed": "admin",
            "timestamp": "2026-05-09T11:00:00Z",
        }
        ctx = BotContext(user="U1", channel="C1", thread_ts="1.0", parent_message=parent)
        cmd.run(ParsedCommand("ask", body="anything else from this user"), ctx)
        sent = eng.questions[0]
        assert sent.startswith("anything else from this user")
        assert "actor=alice@acme.com" in sent

    def test_thread_reply_without_parent_no_augment(self):
        eng = _FakeEngine()
        cmd = AskCommand(engine=eng)
        ctx = BotContext(user="U1", channel="C1", thread_ts="1.0", parent_message=None)
        cmd.run(ParsedCommand("ask", body="hello"), ctx)
        assert eng.questions[0] == "hello"


class _FakeStore:
    def __init__(self, rule=None):
        self.rule = rule

    def get(self, rule_id: str):
        return self.rule if self.rule and self.rule.get("id") == rule_id else None


class _FakeNL:
    def describe(self, rule: dict) -> str:
        return f"This rule fires on {rule.get('title', '?')}."


class TestExplainRuleCommand:
    def test_returns_description(self):
        rule = {"id": "R1", "title": "Super Admin Granted"}
        cmd = ExplainRuleCommand(store=_FakeStore(rule=rule), nl=_FakeNL())
        resp = cmd.run(
            ParsedCommand("explain", subcommand="rule", body="R1"),
            BotContext(user="U1", channel="C1"),
        )
        assert "Super Admin Granted" in resp.summary
        assert not resp.is_error

    def test_missing_subcommand_returns_usage(self):
        cmd = ExplainRuleCommand(store=_FakeStore(), nl=_FakeNL())
        resp = cmd.run(ParsedCommand("explain", body="something"), BotContext(user="U1", channel="C1"))
        assert resp.is_error and "Usage" in resp.summary

    def test_unknown_rule(self):
        cmd = ExplainRuleCommand(store=_FakeStore(rule={"id": "X", "title": "X"}), nl=_FakeNL())
        resp = cmd.run(
            ParsedCommand("explain", subcommand="rule", body="R1"),
            BotContext(user="U1", channel="C1"),
        )
        assert resp.is_error and "R1" in resp.summary


@dataclass
class _VolAnom:
    source: str
    z_score: float


@dataclass
class _Snap:
    silent_sources: list = field(default_factory=list)
    volume_anomalies: list = field(default_factory=list)


class _FakeMonitor:
    def __init__(self, snap=None):
        self.snap = snap or _Snap()

    def snapshot(self):
        return self.snap


class TestHealthCommand:
    def test_healthy(self):
        cmd = HealthCommand(monitor=_FakeMonitor())
        resp = cmd.run(ParsedCommand("health"), BotContext(user="U1", channel="C1"))
        assert "healthy" in resp.summary.lower()

    def test_silent_sources_listed(self):
        snap = _Snap(silent_sources=["gws/admin", "m365/aad"])
        cmd = HealthCommand(monitor=_FakeMonitor(snap=snap))
        resp = cmd.run(ParsedCommand("health"), BotContext(user="U1", channel="C1"))
        assert "Silent sources" in resp.summary
        assert "gws/admin" in resp.summary and "m365/aad" in resp.summary

    def test_volume_anomalies_listed(self):
        snap = _Snap(volume_anomalies=[_VolAnom("gws/login", 4.2)])
        cmd = HealthCommand(monitor=_FakeMonitor(snap=snap))
        resp = cmd.run(ParsedCommand("health"), BotContext(user="U1", channel="C1"))
        assert "Volume anomalies" in resp.summary
        assert "gws/login" in resp.summary and "4.20" in resp.summary


# =================================================== Layer 4: Slack rendering


class TestBlocks:
    def test_summary_only(self):
        blocks = response_to_blocks(BotResponse(summary="hi"))
        assert blocks[0]["type"] == "section"
        assert blocks[0]["text"]["text"] == "hi"

    def test_triplet_renders_in_context(self):
        resp = BotResponse(summary="ok", sql="SELECT 1", row_count=3, cost_cents=12.0)
        blocks = response_to_blocks(resp)
        types = [b["type"] for b in blocks]
        assert "context" in types
        ctx_block = next(b for b in blocks if b["type"] == "context")
        joined = "|".join(e["text"] for e in ctx_block["elements"])
        assert "rows" in joined and "3" in joined
        assert "$0.1200" in joined

    def test_sql_in_code_block(self):
        resp = BotResponse(summary="ok", sql="SELECT email FROM gws_login")
        blocks = response_to_blocks(resp)
        sql_block = next(b for b in blocks if b["type"] == "section"
                          and b["text"]["text"].startswith("```"))
        assert "SELECT email" in sql_block["text"]["text"]

    def test_error_flag(self):
        blocks = response_to_blocks(BotResponse(summary="bad", is_error=True))
        ctx = next(b for b in blocks if b["type"] == "context")
        assert any("error" in e["text"].lower() for e in ctx["elements"])

    def test_truncates_oversized_summary(self):
        long = "x" * 5000
        blocks = response_to_blocks(BotResponse(summary=long))
        assert len(blocks[0]["text"]["text"]) <= 3000

    def test_text_fallback_present(self):
        fb = text_fallback(BotResponse(summary="hi", sql="SELECT 1", row_count=2, cost_cents=5.0))
        assert "hi" in fb and "SELECT 1" in fb and "rows: 2" in fb

    def test_passthrough_blocks(self):
        custom = {"type": "actions", "elements": [{"type": "button"}]}
        out = response_to_blocks(BotResponse(summary="x", blocks=[custom]))
        assert custom in out


# =================================================== Layer 4: Slack app wiring


class _FakeBoltApp:
    """Minimal stand-in for slack_bolt.App.

    Records the handlers registered via ``@app.command`` and
    ``@app.event``. Tests can then invoke the handlers directly with
    fabricated Slack payloads.
    """

    def __init__(self):
        self.command_handlers: dict[str, Any] = {}
        self.event_handlers: dict[str, Any] = {}

    def command(self, name: str):
        def decorator(fn):
            self.command_handlers[name] = fn
            return fn
        return decorator

    def event(self, name: str):
        def decorator(fn):
            self.event_handlers[name] = fn
            return fn
        return decorator


class _FakeSlackClient:
    def __init__(self, parent_message: dict):
        self.parent_message = parent_message
        self.calls: list[dict] = []

    def conversations_replies(self, **kwargs):
        self.calls.append(kwargs)
        return {"messages": [self.parent_message]}


class TestSlackAppRegister:
    def _build(self, ask_engine=None):
        ask = AskCommand(engine=ask_engine or _FakeEngine())
        explain = ExplainRuleCommand(store=_FakeStore(rule={"id": "R1", "title": "T"}), nl=_FakeNL())
        health = HealthCommand(monitor=_FakeMonitor())
        return SlackApp(dispatcher=Dispatcher(ask=ask, explain=explain, health=health))

    def test_command_handler_dispatches(self):
        slack = self._build()
        app = _FakeBoltApp()
        slack.register(app)

        responses: list[dict] = []

        def respond(**kwargs):
            responses.append(kwargs)

        body = {
            "text": "ask show me oauth grants",
            "user_id": "U1",
            "channel_id": "C1",
        }
        slack_handler = app.command_handlers["/mantissa"]
        slack_handler(ack=lambda: None, body=body, respond=respond)

        assert len(responses) == 1
        out = responses[0]
        assert out["response_type"] == "in_channel"
        # Block Kit + plain fallback are both present
        assert isinstance(out["blocks"], list) and out["blocks"]
        assert "rows: 3" in out["text"]  # text fallback carries the triplet

    def test_thread_reply_handler_dispatches_with_parent(self):
        ask_engine = _FakeEngine()
        slack = self._build(ask_engine=ask_engine)
        app = _FakeBoltApp()
        slack.register(app)

        parent_message = {
            "metadata": {
                "event_payload": {
                    "actor_email": "alice@acme.com",
                    "source": "gws",
                    "feed": "admin",
                    "timestamp": "2026-05-09T11:00:00Z",
                }
            }
        }
        client = _FakeSlackClient(parent_message=parent_message)

        says: list[dict] = []

        def say(**kwargs):
            says.append(kwargs)

        event = {
            "user": "U2",
            "channel": "C1",
            "thread_ts": "1.0",
            "text": "anything else from this user today",
        }
        slack_handler = app.event_handlers["message"]
        slack_handler(event=event, say=say, client=client)

        assert len(says) == 1
        assert says[0]["thread_ts"] == "1.0"
        # The engine got the scope-augmented question
        assert "actor=alice@acme.com" in ask_engine.questions[0]
        # Slack replies use blocks
        assert isinstance(says[0]["blocks"], list)

    def test_thread_reply_ignored_when_no_thread_ts(self):
        slack = self._build()
        app = _FakeBoltApp()
        slack.register(app)
        says: list[dict] = []
        slack_handler = app.event_handlers["message"]
        slack_handler(event={"user": "U1", "channel": "C1", "text": "hi"},
                      say=lambda **kw: says.append(kw),
                      client=None)
        assert says == []

    def test_thread_reply_ignored_for_bot_messages(self):
        slack = self._build()
        app = _FakeBoltApp()
        slack.register(app)
        says: list[dict] = []
        slack_handler = app.event_handlers["message"]
        slack_handler(
            event={"user": "U1", "channel": "C1", "text": "hi",
                   "thread_ts": "1.0", "subtype": "bot_message"},
            say=lambda **kw: says.append(kw),
            client=None,
        )
        assert says == []

    def test_command_unknown_returns_help(self):
        slack = self._build()
        app = _FakeBoltApp()
        slack.register(app)
        responses: list[dict] = []
        app.command_handlers["/mantissa"](
            ack=lambda: None,
            body={"text": "", "user_id": "U1", "channel_id": "C1"},
            respond=lambda **kw: responses.append(kw),
        )
        assert responses[0]["text"].lower().startswith("i didn't recognize")
