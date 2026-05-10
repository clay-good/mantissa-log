"""
Paging extensions for the alert router.

A small layer over the existing :class:`AlertRouter` that recognizes
destructive-event rules carrying paging metadata and fans them out to
on-call destinations (PagerDuty, Slack, Teams) in addition to any
severity-based routing already configured.

Design rationale. The destructive-event rule pack lives in
``rules/sigma/destructive/`` and uses three custom Sigma top-level
fields:

    paging: true                       # boolean flag
    evidence_query: |                  # SQL the bot auto-runs when paging
      SELECT ...
    paging_destinations:               # optional override
      - pagerduty
      - slack
      - teams

The fields are non-standard Sigma. The Sigma format ignores fields it
does not recognize, so the rules remain readable by any standard Sigma
tooling. The paging behaviour is therefore a *configuration*, not a
structural change to ``DetectionRule`` or ``AlertRouter``. This keeps the
PR 6 footprint small and avoids coupling the engine to a single
deployment's notion of "what does paging mean."

The extraction function takes the loaded YAML and returns a typed
``PagingMetadata`` object. The attach function copies that metadata onto
an ``Alert.metadata`` dict so downstream consumers (router, chat bots,
audit log) can read it without re-parsing the rule.

The router wrapper (:class:`PagingAwareRouter`) reuses the existing
:class:`AlertRouter` internals via composition. It does not subclass
because subclassing the existing router would couple us to its private
``_determine_destinations`` shape; composition lets us upgrade either
side independently.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default destinations when a paging rule does not specify its own list.
DEFAULT_PAGING_DESTINATIONS = ("pagerduty", "slack", "teams")

# Metadata keys on ``Alert.metadata`` populated by ``attach_to_alert``.
META_PAGING = "paging"
META_EVIDENCE_QUERY = "evidence_query"
META_PAGING_DESTINATIONS = "paging_destinations"


@dataclass(frozen=True)
class PagingMetadata:
    """Paging-relevant fields extracted from a destructive-event rule.

    ``evidence_query`` is the SQL the on-call investigation surface should
    auto-run when the alert fires. It typically scopes to the actor and a
    time window so the on-call sees adjacent activity inline with the page.
    """

    paging: bool
    evidence_query: Optional[str] = None
    paging_destinations: tuple[str, ...] = DEFAULT_PAGING_DESTINATIONS


def extract_paging_metadata(rule_yaml: Dict[str, Any]) -> Optional[PagingMetadata]:
    """Return :class:`PagingMetadata` if the rule opts in to paging.

    A rule opts in by setting ``paging: true`` at the top level. If the
    flag is absent or falsy, this function returns ``None`` and the alert
    flows through the standard severity-based routing.
    """
    if not isinstance(rule_yaml, dict):
        return None
    if not rule_yaml.get("paging"):
        return None
    raw_destinations = rule_yaml.get("paging_destinations") or DEFAULT_PAGING_DESTINATIONS
    if not isinstance(raw_destinations, (list, tuple)):
        raw_destinations = DEFAULT_PAGING_DESTINATIONS
    return PagingMetadata(
        paging=True,
        evidence_query=rule_yaml.get("evidence_query"),
        paging_destinations=tuple(raw_destinations),
    )


def attach_to_alert(alert: Any, paging: PagingMetadata) -> Any:
    """Copy paging metadata onto an ``Alert.metadata`` dict in place.

    Returns the alert for convenience. We require duck typing here rather
    than importing ``Alert`` so this module stays independent of the
    detection package (avoids an import cycle).
    """
    if not hasattr(alert, "metadata") or alert.metadata is None:
        setattr(alert, "metadata", {})
    alert.metadata[META_PAGING] = True
    if paging.evidence_query is not None:
        alert.metadata[META_EVIDENCE_QUERY] = paging.evidence_query
    alert.metadata[META_PAGING_DESTINATIONS] = list(paging.paging_destinations)
    return alert


@dataclass
class PagingAwareRouter:
    """Wraps an existing :class:`AlertRouter`, adding paging destinations.

    The wrapper resolves destinations in this order:
      1. Whatever the underlying router would resolve normally.
      2. If ``alert.metadata.get("paging") is True``, the destinations in
         ``alert.metadata.get("paging_destinations", DEFAULT)`` are
         added (deduplicated, preserving the union).

    The wrapper delegates ``route_alert`` to the underlying router after
    augmenting the alert's ``destinations`` list. This avoids reaching
    into private internals like ``_determine_destinations``.
    """

    inner: Any  # the underlying AlertRouter

    def route_alert(self, alert: Any):
        self._augment_destinations(alert)
        return self.inner.route_alert(alert)

    def route_alerts(self, alerts: List[Any]):
        for alert in alerts:
            self._augment_destinations(alert)
        return self.inner.route_alerts(alerts)

    # --- internals ----------------------------------------------------------

    def _augment_destinations(self, alert: Any) -> None:
        meta = getattr(alert, "metadata", None) or {}
        if not meta.get(META_PAGING):
            return
        paging_dests = meta.get(META_PAGING_DESTINATIONS) or list(DEFAULT_PAGING_DESTINATIONS)
        existing = getattr(alert, "destinations", None) or []
        # Preserve order of existing destinations, then add new ones in
        # the order they appear in the paging list.
        seen = set(existing)
        merged = list(existing)
        for dest in paging_dests:
            if dest not in seen:
                merged.append(dest)
                seen.add(dest)
        alert.destinations = merged
