"""
SaaS sign-in IP threat-intel enrichment.

PR 14 of SAAS_IDENTITY_SPEC, closing the §10 item: "Threat-intel
enrichment for SaaS sign-in IPs — uses the existing ``enrichment/``
module but needs a feed config update."

This module is the bridge between the SaaS collectors shipped in
PRs 2–13 and the existing :class:`ThreatIntelService`. It does two
things:

  1. Maps each (source, feed) tuple to the path where the actor IP
     lives in the raw collector payload. The map is small and explicit
     because every SaaS API encodes the IP differently:

         gws        ipAddress           (Reports API, top level)
         m365 aad   ClientIP            (Management Activity)
         m365 graph ipAddress           (Graph audit endpoints)
         okta       client.ipAddress    (nested)
         slack      context.ip_address  (nested)
         github     actor_ip            (top level)
         salesforce CLIENT_IP           (top level)

  2. Calls into the existing :class:`ThreatIntelService` (or any
     duck-typed substitute) to look up the IP reputation and attaches
     the result under ``threat_intel`` on the event.

Where in the pipeline. Enrichment is deliberately *not* run inside the
collector hot path. The collectors write raw events to the lake
unmodified. A separate post-ingest enrichment pass (or the existing
parser pipeline) consumes raw events, calls :meth:`enrich`, and writes
enriched Parquet to the events partition.

Two design decisions worth being explicit about:

  - Private / reserved / link-local IPs are skipped without a lookup.
    Threat intel feeds carry no useful signal for RFC 1918 addresses
    and would waste cache slots and API quota.

  - Idempotency. The enricher is safe to call twice on the same event;
    if ``threat_intel`` is already present it is left untouched. This
    makes back-fill reruns cheap and avoids API double-charging when
    the post-ingest pass restarts.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)


# Registry of where the actor IP lives in each (source, feed) raw event.
# ``None`` means the feed has no IP to enrich (e.g. directory_audits is a
# config-change feed without a network-level actor IP).
#
# Paths use dotted notation: ``a.b.c`` means ``event["a"]["b"]["c"]``.
# Add new (source, feed) pairs here when a new collector ships.
SAAS_FEED_IP_PATHS: dict[tuple[str, str], Optional[str]] = {
    # Google Workspace -- every Reports API feed surfaces ipAddress at the top.
    ("gws", "login"): "ipAddress",
    ("gws", "admin"): "ipAddress",
    ("gws", "drive"): "ipAddress",
    ("gws", "token"): "ipAddress",
    ("gws", "calendar"): "ipAddress",
    ("gws", "groups"): "ipAddress",
    ("gws", "groups_enterprise"): "ipAddress",
    ("gws", "gmail"): "ipAddress",
    ("gws", "mobile"): "ipAddress",
    ("gws", "chrome"): "ipAddress",
    ("gws", "meet"): "ipAddress",
    ("gws", "chat"): "ipAddress",
    ("gws", "user_accounts"): "ipAddress",
    ("gws", "access_transparency"): "ipAddress",
    ("gws", "saml"): "ipAddress",
    ("gws", "context_aware_access"): "ipAddress",
    ("gws", "data_studio"): "ipAddress",
    ("gws", "gcp"): "ipAddress",
    ("gws", "keep"): "ipAddress",
    ("gws", "jamboard"): "ipAddress",
    ("gws", "rules"): "ipAddress",

    # Microsoft 365 Management Activity -- ClientIP at top level.
    ("m365", "aad"): "ClientIP",
    ("m365", "exchange"): "ClientIP",
    ("m365", "sharepoint"): "ClientIP",
    ("m365", "general"): "ClientIP",
    ("m365", "dlp"): "ClientIP",

    # Microsoft Graph audit endpoints -- ipAddress at top level (signIns and
    # risk_detections). The directory audit endpoint does not carry an IP;
    # alerts_v2 is structurally different and is left None pending a
    # per-rule mapping when the rule pack stabilises.
    ("m365", "signins"): "ipAddress",
    ("m365", "directory_audits"): None,
    ("m365", "risk_detections"): "ipAddress",
    ("m365", "defender_alerts"): None,

    # Okta System Log -- nested under client.
    ("okta", "system"): "client.ipAddress",

    # Slack Audit Logs -- nested under context.
    ("slack", "audit"): "context.ip_address",

    # GitHub Audit Log -- actor_ip at top level.
    ("github", "audit"): "actor_ip",

    # Salesforce Event Monitoring -- CLIENT_IP on each CSV row.
    ("salesforce", "events"): "CLIENT_IP",
}


# Result key on the enriched event.
ENRICHMENT_KEY = "threat_intel"


def get_ip_field_path(source: str, feed: str) -> Optional[str]:
    """Return the IP field path for a (source, feed) pair, or None.

    Returns ``None`` both when the feed is not registered AND when the
    feed is registered with a deliberate ``None`` (no IP available).
    Callers should treat both cases as "skip enrichment" identically.
    """
    return SAAS_FEED_IP_PATHS.get((source, feed))


def get_path(event: dict, path: str) -> Optional[str]:
    """Read a dotted-path value from an event dict. Returns None on miss
    or on any intermediate value being non-dict."""
    cur: Any = event
    for segment in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(segment)
        if cur is None:
            return None
    return cur if isinstance(cur, str) else None


def is_routable_ip(value: str) -> bool:
    """True if ``value`` is a public IPv4 or IPv6 address worth looking up.

    Filters out private, loopback, link-local, multicast, reserved, and
    unspecified addresses. Threat intel feeds carry no useful signal for
    RFC 1918 traffic and lookups would waste cache slots and API quota.
    """
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(value.strip())
    except (ValueError, TypeError):
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return False
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False
    return True


@dataclass
class SaaSSigninEnricher:
    """Wraps a duck-typed threat-intel service and applies it to SaaS
    collector raw events.

    The service must expose ``lookup_ip_reputation(ip) -> ThreatIntelResult``
    or raise on transport failure. The bridge calls into the production
    :class:`ThreatIntelService` from ``shared.enrichment.threat_intel``
    in real deployments; tests inject a fake.
    """

    service: Any

    def enrich(self, event: dict, source: str, feed: str) -> dict:
        """Mutate ``event`` in place by attaching ``threat_intel`` data.

        No-ops (and returns the event unchanged) when:
          - the (source, feed) is not registered for IP enrichment
          - the registered path resolves to no value
          - the value is not a routable public IP
          - the event already carries a ``threat_intel`` block (idempotent)
          - the upstream service returns None or raises

        Returns the (possibly mutated) event for caller convenience.
        """
        if ENRICHMENT_KEY in event:
            return event
        path = get_ip_field_path(source, feed)
        if not path:
            return event
        ip = get_path(event, path)
        if not ip or not is_routable_ip(ip):
            return event
        try:
            result = self.service.lookup_ip_reputation(ip)
        except Exception as exc:  # noqa: BLE001
            # We swallow lookup failures. The collector run loop is
            # already noisy in error cases; an enrichment miss should
            # never fail the ingest. Log at debug so operators have a
            # trail without spamming.
            logger.debug("saas_signin.lookup_failed ip=%s source=%s feed=%s err=%s",
                         ip, source, feed, exc)
            return event
        if result is None:
            return event
        event[ENRICHMENT_KEY] = _result_to_dict(result, ip=ip)
        return event


def _result_to_dict(result: Any, ip: str) -> dict:
    """Coerce a ThreatIntelResult-shaped object into a stable dict.

    We pick exactly the fields a downstream Sigma rule or NL query is
    likely to ask for. Keeping the dict small keeps the lake row narrow
    and stops field drift from the threat intel SDK leaking into our
    schema.
    """
    return {
        "ip": ip,
        "reputation_score": getattr(result, "reputation_score", None),
        "is_malicious": bool(getattr(result, "is_malicious", False)),
        "confidence": float(getattr(result, "confidence", 0.0) or 0.0),
        "categories": list(getattr(result, "categories", []) or []),
        "abuse_score": getattr(result, "abuse_score", None),
        "total_reports": int(getattr(result, "total_reports", 0) or 0),
        "is_tor_exit": bool(getattr(result, "is_tor_exit", False)),
        "is_vpn": bool(getattr(result, "is_vpn", False)),
        "is_proxy": bool(getattr(result, "is_proxy", False)),
        "sources": list(getattr(result, "sources", []) or []),
        "cached": bool(getattr(result, "cached", False)),
    }
