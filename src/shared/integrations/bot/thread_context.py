"""
Thread auto-scope helper.

A reply in a thread under a destructive-event alert should be answered
with the alert's context pre-applied. If the alert says "actor
alice@acme.com on gws_admin at 02:14 UTC", a follow-up question
"anything else from this user today" should run scoped to that actor
and a time window around 02:14, not as a global query.

Implementation note. We extract context from the alert payload using a
small set of well-known field names. The destructive-event rule pack
(PR 6) populates these via the parsers shipped in PRs 2–5, so the
extraction is deterministic across all M365 and GWS rules. Other rule
sources (CloudTrail, Okta, GitHub) populate the same field names
via their existing parsers; sources that emit non-standard fields will
have their context auto-scope quietly skipped, which is correct
behaviour (do not invent context).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional


@dataclass(frozen=True)
class ThreadAutoScope:
    """Scope extracted from a thread's parent alert."""

    actor: Optional[str] = None             # actor.email / user.email / userPrincipalName
    source: Optional[str] = None            # source.name e.g. "gws" or "m365"
    feed: Optional[str] = None              # feed name e.g. "admin" or "aad"
    when: Optional[datetime] = None         # alert event time
    window_minutes: int = 60                # default look-back / look-forward span

    @property
    def has_context(self) -> bool:
        return any((self.actor, self.source, self.feed, self.when))

    def augment_question(self, question: str) -> str:
        """Prepend scope hints to a free-form NL question.

        The hints are appended as a structured suffix that the NL→SQL
        translator can consume (it sees them as additional context, not
        as part of the user's intent). Keeping the user's question verbatim
        is important — rephrasing risks changing the meaning.
        """
        if not self.has_context:
            return question
        parts = []
        if self.actor:
            parts.append(f"actor={self.actor}")
        if self.source:
            parts.append(f"source={self.source}")
        if self.feed:
            parts.append(f"feed={self.feed}")
        if self.when:
            iso = self.when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            parts.append(f"time_window={iso}±{self.window_minutes}m")
        return f"{question}\n\n[scope: {', '.join(parts)}]"


def extract_scope(parent_message: Optional[dict]) -> ThreadAutoScope:
    """Pull (actor, source, feed, when) from a parent alert payload.

    Looks up several common field paths because alerts arrive from
    different rule packs with slightly different schemas. Missing fields
    are returned as None so callers can decide whether to use the scope.
    """
    if not isinstance(parent_message, dict):
        return ThreadAutoScope()

    metadata = parent_message.get("metadata") or {}
    results = parent_message.get("results") or []
    first_result = results[0] if isinstance(results, list) and results else {}

    actor = (
        _first_nonempty(parent_message, "actor_email", "actor")
        or _first_nonempty(metadata, "actor_email", "actor", "user_email")
        or _first_nonempty(first_result, "actor.email", "user.email", "userPrincipalName",
                           "actor_email", "user_email")
    )

    source = (
        _first_nonempty(parent_message, "source", "source_name")
        or _first_nonempty(metadata, "source", "source_name")
        or _first_nonempty(first_result, "source.name", "source")
    )

    feed = (
        _first_nonempty(parent_message, "feed")
        or _first_nonempty(metadata, "feed")
        or _first_nonempty(first_result, "feed", "applicationName")
    )

    when = _coerce_datetime(
        _first_nonempty(parent_message, "timestamp", "event_time", "@timestamp")
        or _first_nonempty(metadata, "timestamp", "event_time")
        or _first_nonempty(first_result, "@timestamp", "event_time", "createdDateTime")
    )

    return ThreadAutoScope(actor=actor, source=source, feed=feed, when=when)


def _first_nonempty(obj: dict, *keys: str) -> Optional[str]:
    for k in keys:
        v = obj.get(k)
        if v not in (None, "", []):
            return str(v)
    return None


def _coerce_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        v = value
        if v.endswith("Z"):
            v = v[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(v).astimezone(timezone.utc)
        except ValueError:
            return None
    return None
