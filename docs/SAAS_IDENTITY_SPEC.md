# Mantissa Log — SaaS Identity Spec (Google Workspace + Microsoft 365)

**Status:** Complete (all 8 PRs landed 2026-05-10)
**Scope:** Close the GWS/M365 gap that the README already advertises. Add collectors, complete the rule packs, and ship a destructive-event detector pack that reuses the existing engine.

---

## 1. Why This Exists

The mantissa-log README already promises identity-threat detection across Okta, Azure AD, Google Workspace, Duo, and Microsoft 365. The codebase has the supporting layers:

- `src/shared/parsers/google_workspace.py` — Reports API → ECS normalization
- `src/shared/parsers/microsoft365.py` — Management Activity API → ECS, covers Entra ID, Exchange, SharePoint, Teams, DLP
- `rules/sigma/google_workspace/` — 7 Sigma rules already merged
- `rules/sigma/microsoft365/` — 6 Sigma rules + ITDR subfolder
- `src/shared/identity/` — baselines, anomaly detection, session tracking, travel analyzer, risk scoring

What's missing is the **ingest path**. There are parsers, but only one collector (`zeek_suricata_collector.py`). There's no scheduled pull from the GWS Reports API or M365 Management Activity API into the lake. That's the gap.

This spec also formalizes a **destructive-event detector pack** (~20 paging-grade rules) that fires on the freshest partition and pages on-call. This is the highest-leverage piece imported from the retired Vaulytica project.

---

## 2. Non-Goals

- No GWS/M365 **configuration posture** scanning. That belongs in mantissa-stance (separate spec).
- No file-content DSPM classification (PII in Drive files). That's stance.
- No remediation actions. SOAR module covers that opt-in; this spec stays observe-only.
- No new query engine, no new lake adapter, no new LLM provider. Reuse what exists.

---

## 3. What Gets Added

### 3.1 Collectors

```
src/shared/collectors/
  __init__.py
  zeek_suricata_collector.py            (existing)
  google_workspace_collector.py         (NEW)
  microsoft365_collector.py             (NEW)
  base_saas_collector.py                (NEW — shared scheduling/state primitives)
```

Each collector is a long-lived poller with:
- OAuth-refresh token management (per-tenant secret store)
- Watermark cursor stored in the lake's `_state/` prefix (last `eventTime` per source per tenant)
- Backfill mode for first run (last 180 days, configurable per Reports API limits)
- Backoff + retry + per-tenant rate-limit accounting
- Output: raw JSON to `s3://lake/raw/source=gws/dt=YYYY-MM-DD/hh=HH/...` (and equivalents for GCS/Blob), then parsed Parquet to `s3://lake/events/source=gws/dt=…` via the existing parser pipeline

The two new collectors duplicate ~200 lines of OAuth/token glue with the planned mantissa-stance equivalents. Per the consolidation decision, **do not factor that out into a shared package**. Duplicate it cleanly. Each tool's lifecycle stays independent.

### 3.2 Google Workspace Collector — sources

The Reports API exposes ~25 application activity feeds. Pull all of them; cost is negligible relative to the security value. Map each to a logical table partition.

| Reports `applicationName` | Why it matters | Partition tag |
|---|---|---|
| `login` | Sign-in events, suspicious-login flags | `gws_login` |
| `admin` | Admin console actions (the highest-value feed) | `gws_admin` |
| `drive` | File create/edit/share/download/delete, permission changes | `gws_drive` |
| `token` | OAuth grant + revoke events (third-party app authorizations) | `gws_token` |
| `calendar` | Event create/share/delete | `gws_calendar` |
| `groups`, `groups_enterprise` | Group membership and settings changes | `gws_groups` |
| `gmail` | Gmail audit (delegates, forwarding, filters where licensed) | `gws_gmail` |
| `mobile` | Mobile device enrollment, compliance events | `gws_mobile` |
| `chrome` | Chrome OS / Chrome Browser Cloud Mgmt events | `gws_chrome` |
| `meet` | Meet session events | `gws_meet` |
| `chat` | Chat message events (where audited) | `gws_chat` |
| `user_accounts` | User account lifecycle | `gws_user` |
| `access_transparency` | Google staff access events | `gws_at` |
| `saml` | SAML SSO assertions | `gws_saml` |
| `context_aware_access` | Context-Aware Access policy hits | `gws_caa` |
| `data_studio` / `looker` | Looker Studio activity (where licensed) | `gws_looker` |
| `gcp` | Workspace-side GCP linkage events | `gws_gcp` |
| `keep`, `vault`, `jamboard` | Lower-volume, included for completeness | `gws_misc` |

Plus two near-real-time feeds via Google Pub/Sub (where the customer enables them):
- **Drive Activity API** push subscription (richer file event stream than Reports)
- **Cloud Identity device events** push subscription

Auth: single Google service account with domain-wide delegation, scopes documented in `docs/connectors/google_workspace.md`. Reuse the OAuth setup helper and Apps Script bootstrap copied verbatim from the retired vaulytica repo.

### 3.3 Microsoft 365 / Entra ID Collector — sources

| API | What it gives us | Partition tag |
|---|---|---|
| Management Activity API — `Audit.AzureActiveDirectory` | Entra sign-ins, role assignments, app consents, conditional access changes | `m365_aad` |
| Management Activity API — `Audit.Exchange` | Mailbox forwarding, transport rules, eDiscovery, mailbox audit | `m365_exchange` |
| Management Activity API — `Audit.SharePoint` | File access, external sharing, site collection actions | `m365_sharepoint` |
| Management Activity API — `Audit.General` | Teams, Power Platform, DLP, Forms, Stream | `m365_general` |
| Management Activity API — `DLP.All` | DLP policy match events | `m365_dlp` |
| Microsoft Graph — `auditLogs/signIns` | Per-sign-in detail (richer than Management API for ITDR) | `m365_signins` |
| Microsoft Graph — `auditLogs/directoryAudits` | Directory change audit | `m365_directory` |
| Microsoft Graph — `identityProtection/riskyUsers` and `riskDetections` | Identity Protection risk feed | `m365_idprotect` |
| Microsoft Graph — `security/alerts_v2` | Defender alerts | `m365_defender` |

Auth: Entra app registration with application permissions for `ActivityFeed.Read`, `AuditLog.Read.All`, `IdentityRiskyUser.Read.All`, `SecurityAlert.Read.All`. Setup doc + Terraform stub in `terraform/m365_app_registration/`.

The Management Activity API is async — you subscribe to content types, then poll for available content blobs and download each. The collector handles the full subscribe → list-content → fetch → parse → write loop.

### 3.4 Lake Schema additions

Add to the existing partition scheme in `docs/architecture/lake_layout.md`:

```
s3://<bucket>/events/
  source=gws/dt=YYYY-MM-DD/hh=HH/feed=<gws_*>/part-*.parquet
  source=m365/dt=YYYY-MM-DD/hh=HH/feed=<m365_*>/part-*.parquet
```

Each Parquet file conforms to the existing ECS-flavored schema produced by the parsers — no new schema, no new query patterns. `schema_context.py` (LLM schema awareness) gets two new entries describing the GWS and M365 feeds and the most useful columns for natural-language query generation.

### 3.5 Identity baselines

Wire GWS sign-in events and M365 sign-in events into `src/shared/identity/baseline_calculator.py`:

- Per-user baseline of source IPs, ASNs, countries, user agents, sign-in hours, MFA methods used.
- `travel_analyzer.py` already exists — feed both sources into it for unified impossible-travel detection across SaaS identity surfaces.
- `risk_scorer.py` consumes anomalies from both sources into a single per-user risk score. This is what "behavioral baselines for every user across Okta, Azure AD, Google Workspace, Duo, and Microsoft 365" actually means in code.

No new modules. Just new sources feeding existing primitives.

---

## 4. Destructive-Event Detector Pack

New directory: `rules/sigma/destructive/`. These are **paging-grade** detections — they wake people up. The list is intentionally short. Every rule includes:

- `severity: critical`
- `paging: true` (custom Sigma metadata, read by the alert router)
- `evidence_query` — the SQL the LLM should auto-run to enrich the page (e.g., "show every other action this user took in the last 60 minutes")

### Initial pack (~20 rules)

**Identity / privilege escalation**
1. `dest_gws_super_admin_granted.yml` — Workspace super admin role assignment
2. `dest_m365_global_admin_granted.yml` — Entra Global Admin role assignment
3. `dest_okta_super_admin_granted.yml` (existing → moved into destructive pack)
4. `dest_aws_root_used.yml` — AWS root account activity
5. `dest_gcp_org_admin_granted.yml` — GCP Organization Admin grant
6. `dest_azure_owner_granted_subscription.yml`

**MFA / authentication tampering**
7. `dest_gws_2fa_disabled_org.yml` — org-wide 2FA enforcement turned off
8. `dest_m365_security_defaults_disabled.yml`
9. `dest_m365_conditional_access_disabled.yml` — CA policy disabled or deleted
10. `dest_okta_mfa_factor_reset_for_admin.yml`

**Mass data egress / destruction**
11. `dest_gws_drive_mass_download.yml` (existing → moved + tightened thresholds)
12. `dest_gws_drive_mass_delete.yml` — N file deletes by single user in window
13. `dest_m365_sharepoint_mass_download.yml`
14. `dest_m365_mailbox_mass_export.yml`
15. `dest_aws_s3_bucket_made_public.yml`
16. `dest_aws_s3_mass_delete_or_lifecycle_purge.yml`
17. `dest_github_repo_made_public_or_deleted.yml`

**OAuth / app trust**
18. `dest_gws_oauth_high_risk_scope_granted.yml` — Drive full-scope or Gmail full-scope grants
19. `dest_m365_high_privilege_consent.yml` — admin consent to risky Graph scopes

**Logging / audit tampering**
20. `dest_aws_cloudtrail_disabled_or_deleted.yml`
21. `dest_gcp_audit_log_sink_deleted.yml`
22. `dest_m365_audit_log_disabled.yml`

(Stretch: 5–10 more covering Entra app secret added to high-priv app, AAD federated domain added, GWS data transfer out of org, etc.)

### Routing

The alert router (`src/shared/alerting/`) gets a new sink config: any rule with `paging: true` routes to PagerDuty/Opsgenie *and* opens a Slack/Teams thread with:

- The rule's `evidence_query` results inline
- A "follow up" affordance — replies in the thread are sent through the existing NL→SQL pipeline scoped to the same user/time window. This makes the incident channel itself the investigation surface. No dashboard, no separate console.

---

## 5. Slack / Teams Bot Surface

Mantissa-log already has `src/shared/integrations/` and conversation manager. Add two thin app entry points:

```
src/shared/integrations/
  slack/
    app.py          # Bolt for Python, slash command + thread listener
    formatter.py    # rows → Block Kit
  teams/
    app.py          # Bot Framework
    formatter.py    # rows → Adaptive Cards
```

Bot capabilities (both Slack and Teams):
- `/mantissa ask <natural language>` — runs through `llm/query_generator.py` → `query/` engine → `formatter`. Always returns the SQL, row count, and est. cost (existing behavior, just exposed in chat).
- Thread replies on a destructive-event alert auto-scope to the alert's user/time/source context.
- `/mantissa explain rule <id>` — uses `detection/sigma_to_nl.py` to describe what a rule does in English.
- `/mantissa health` — surfaces `health/` output (silent sources, volume anomalies).

Auth: workspace identity = bot identity. No separate login. Per-channel allowlist for who can run paid LLM queries.

---

## 6. What to Port from the Retired Vaulytica Repo

Concrete file-level migration plan. Run before archiving.

| From `vaulytica/` | To `mantissa-log/` | Notes |
|---|---|---|
| `vaulytica/core/scanners/audit_log_scanner.py` | `src/shared/collectors/google_workspace_collector.py` | Logic for paginated Reports API pulls, watermarking |
| `vaulytica/core/scanners/oauth_scanner.py` (token-event portion only) | merged into GWS collector's `gws_token` feed | Posture portion goes to stance, not here |
| `vaulytica/integrations/slack.py` | `src/shared/integrations/slack/formatter.py` | Reuse the alert-card formatting |
| `vaulytica/apps-script/` | `docs/connectors/google_workspace_setup/apps-script/` | Tenant-side OAuth bootstrap helper |
| `vaulytica-headless/.../scanners/google-audit-scanner.ts` | reference for completeness | TS → Python port for any feeds the Python scanner missed |
| `vaulytica-headless/.../scanners/microsoft-unified-audit-scanner.ts` | reference for M365 collector | Most complete enumeration of M365 audit record types |
| `vaulytica/dlp_rules.example.yaml` | **stance**, not log | Content classification belongs to stance |

The 41-Microsoft-scanner / 40-Google-scanner taxonomy from vaulytica-headless is mostly *posture* (stance's job), but ~10 are event-stream scanners — extract those record-type lists into the collector's feed configuration.

---

## 7. Documentation Deliverables

Add under `docs/connectors/`:

- `google_workspace.md` — service account setup, domain-wide delegation, required scopes, Pub/Sub setup for Drive Activity, troubleshooting
- `microsoft_365.md` — Entra app registration (Terraform + manual), required application permissions, admin consent flow, Management Activity API content-type subscription
- `saas_identity_threat_model.md` — what we collect, what we don't, what scopes we require and why, data residency story (everything stays in the customer's lake)

Update top-level `README.md`:
- Move GWS and M365 from "supported sources" promise into the listed collectors section
- Add the destructive-event pack to the "what's included" list

---

## 8. Migration / Sequencing

Eight discrete PRs. Each is independently shippable.

1. **PR 1 — base SaaS collector primitives.** [Status: done, 2026-05-10.] Shipped:
   - `src/shared/collectors/base_saas_collector.py` (`BaseSaaSCollector` ABC + run loop with watermark advance, batched lake write, retry on initial fetch)
   - `src/shared/collectors/saas_state.py` (`Watermark`, `LocalFileWatermarkStore`, `S3WatermarkStore`)
   - `src/shared/collectors/saas_secrets.py` (`SecretStore` ABC, `EnvSecretStore`, `LocalFileSecretStore`; cloud-native backends stubbed for follow-on)
   - `src/shared/collectors/saas_lake.py` (`RawLakeWriter` ABC, `LocalFileRawLakeWriter`, `S3RawLakeWriter`; gzipped JSONL into `raw/source=…/dt=…/hh=…/tenant=…/feed=…/`)
   - `src/shared/collectors/saas_retry.py` (`RetryPolicy`, `TransientError`, `retry_call` with `Retry-After` honouring + exp backoff + jitter)
   - `tests/unit/test_saas_collector_base.py` (34 unit tests, all passing; covers retry math, both secret stores, both watermark stores incl. moto-S3, both lake writers incl. moto-S3, and the full base run loop with backfill, watermark advance, batching, retry-on-fetch, multi-feed, feed subselect)

   Contract clarified during PR 1: `fetch_feed` should raise transient errors synchronously (not from inside the returned generator) so the retry decorator catches them. Documented in the base class docstring with an example. Subclasses in PR 2 onward must follow this pattern.
2. **PR 2 — GWS collector, login + admin + drive + token feeds.** [Status: done, 2026-05-10.] Shipped:
   - `src/shared/collectors/google_workspace_collector.py` — `GoogleWorkspaceCollector(BaseSaaSCollector)`. Source name `gws`, default feeds `("login", "admin", "drive", "token")`. Reports API integration via injectable `service_factory` (production builds the real Google client lazily from secrets; tests inject a fake). Pagination via `nextPageToken`. Strict open-bound filtering on `since` and `until` so the inclusive `startTime` parameter does not re-emit boundary events. HTTP error classifier translates 408/429/5xx into `TransientError` with `Retry-After` honouring; 4xx other than 429 surfaces as a feed-level error. Stable `event_id` derived from `id.{time, uniqueQualifier, applicationName}`.
   - `tests/unit/test_google_workspace_collector.py` — 18 unit tests. Coverage: helper round-trips, feed selection (default/subset/unknown rejection), single-page write + watermark advance, default 7-day backfill window, two-page pagination with `pageToken` propagation, `since` boundary exclusion, `until` boundary exclusion, malformed-event drop, 429 retried with success on second attempt, 404 NOT retried (single attempt, surfaces as feed error), four-feed independent watermarks, raw event enrichment with injected `event_time` and `event_id`, service-factory injection, missing-secrets error path.

   Refinement during PR 2. The `RetryPolicy` default `retry_on` was tightened from `(Exception,)` to `(TransientError,)`. The previous default would have silently retried 4xx errors which are not retryable and would have masked real bugs (bad scopes, wrong tenant ID, etc.). Collectors now classify upstream errors and re-raise as `TransientError` only when genuinely retryable. This is the right shape long-term and is now load-bearing for the M365 collector in PR 4.
3. **PR 3 — GWS collector, remaining feeds.** [Status: done, 2026-05-10.] Shipped:
   - Extended `FEED_TO_APPLICATION_NAME` in `google_workspace_collector.py` with 17 additional Reports API `applicationName` values: `calendar`, `groups`, `groups_enterprise`, `gmail`, `mobile`, `chrome`, `meet`, `chat`, `user_accounts`, `access_transparency`, `saml`, `context_aware_access`, `data_studio` (Looker Studio), `gcp` (Workspace-side GCP linkage), `keep`, `jamboard`, `rules` (Workspace Rules / DLP / alerting). Total feed coverage now stands at 21.
   - Added `GoogleWorkspaceCollector.ALL_FEEDS` class constant with the full ordered tuple. `DEFAULT_FEEDS` deliberately stays as the four PR 2 high-value feeds so existing deployments are not silently expanded; operators opt into full coverage via `feeds=GoogleWorkspaceCollector.ALL_FEEDS`. This split keeps default storage and parse cost predictable while making full coverage one explicit flag away.
   - Tests added to `tests/unit/test_google_workspace_collector.py` (21 new, 39 total in this file): a `pytest.parametrize` sweep that exercises each of the 17 new feeds and verifies the exact `applicationName` is propagated to the Reports API call; an end-to-end fan-out test that runs `ALL_FEEDS` together and asserts independent watermark, independent lake partition, and one API call per feed; structural assertions that `ALL_FEEDS` and `FEED_TO_APPLICATION_NAME` stay in sync and that `DEFAULT_FEEDS` remains a strict subset.
   - Lake partitioning is unchanged. Each feed lands at `raw/source=gws/dt=…/hh=…/tenant=…/feed={feed_name}/...jsonl.gz` so cross-feed correlation queries (e.g. user signed in via `login` then changed forwarding rule via `gmail`) join naturally on `actor.email` over the same date partition.

   Out of scope, stays for later. Two near-real-time push subscriptions named in spec §3.2 (Drive Activity API and Cloud Identity device events) will land in their own PR. They are structurally different from Reports polling (push not pull, separate auth, separate retention semantics) and folding them into PR 3 would have muddled the contract.
4. **PR 4 — M365 collector, Management Activity API.** [Status: done, 2026-05-10.] Shipped:
   - `src/shared/collectors/microsoft365_collector.py` — `Microsoft365Collector(BaseSaaSCollector)`. Source name `m365`. Five feeds: `aad` (`Audit.AzureActiveDirectory`), `exchange` (`Audit.Exchange`), `sharepoint` (`Audit.SharePoint`), `general` (`Audit.General`), `dlp` (`DLP.All`).
   - Async subscribe -> list-content -> fetch-blob loop. Subscription is idempotent on the server and cached in-process via `_subscribed: set[str]` so a long-running collector hits the start-subscription endpoint at most once per content type per process lifetime.
   - Injectable `client_factory` for tests (production builds an HTTP client lazily from secrets at `m365/{tenant_id}/client_credentials` storing JSON of `{tenant_id, client_id, client_secret}`).
   - Window chunking. The Management Activity API caps each list call to 7 days, so long backfills are chunked at `MAX_WINDOW_HOURS=24*7`. Per-chunk dedup by `contentId` makes the chunk-walk safe under retry and late-arrival semantics.
   - Lookback buffer (`DEFAULT_LOOKBACK_HOURS=24`). Events in a blob with `contentCreated=T` can carry `CreationTime` values from up to 24h before T. The collector widens the upstream API window by the lookback and filters strictly on event time in the iterator. Watermark advance is unaffected.
   - HTTP error classifier (`_classify`). 408/429/5xx -> `TransientError` (with `Retry-After` honoured). 4xx other than 429 surfaces as feed-level error. `ManagementActivityHTTPError.__str__` embeds the status code so run output is self-describing.
   - `tests/unit/test_microsoft365_collector.py` — 24 unit tests. Coverage: helpers, feed selection (default/subset/unknown), subscription idempotence across runs, single-blob single-event happy path, lookback widening on first run, zero-lookback edge case, long-backfill chunking, multi-blob fetch order, since-boundary exclusion, until-boundary exclusion, blob-missing-URI skip, event-missing-CreationTime drop, 429 list retry, 503 list retry, 404 list NOT retried, 410 blob fetch surfaces as feed error, event enrichment with `event_time`/`event_id`, full five-feed fan-out with independent watermarks and partitions, missing-secrets error path.

   Base class refinement during PR 4. The base `_run_feed` was wrapping the initial fetch in try/except but NOT the streaming drain. A blob-fetch error mid-stream would crash the entire run loop. Wrapped `_drain_to_lake` in try/except too; streaming errors now surface as feed-level errors per the contract documented on `fetch_feed`. This was a latent bug from PR 1 that PR 4 exposed because GWS does all its work synchronously in the first list call while M365 does real work during streaming.
5. **PR 5 — M365 collector, Graph supplements.** [Status: done, 2026-05-10.] Shipped:
   - `src/shared/collectors/microsoft_graph_collector.py` — `MicrosoftGraphCollector(BaseSaaSCollector)`. Sibling to `Microsoft365Collector` (not a subclass; the API models are too different for a clean inheritance hierarchy). Four feeds: `signins` (`/v1.0/auditLogs/signIns`), `directory_audits` (`/v1.0/auditLogs/directoryAudits`), `risk_detections` (`/v1.0/identityProtection/riskDetections`), `defender_alerts` (`/v1.0/security/alerts_v2`).
   - **Source unification.** Both M365 collectors set `source_name = "m365"`, so all M365 events (Management Activity + Graph) land in the same `source=m365` partition tree in the lake. Cross-feed queries (e.g. "join `signins` to `aad` on UPN over the same hour") work without a UNION across separate partition trees. Test `TestSourceUnification` verifies this directly by asserting equality with `Microsoft365Collector.source_name`.
   - **Per-feed config table** (`FEED_CONFIG: dict[str, _GraphFeedConfig]`). Each feed declares its endpoint path, its event-time field name (varies: `createdDateTime`, `activityDateTime`, `detectedDateTime`), and its OData `$filter` template. Adding a fifth Graph feed in the future is a one-entry config edit.
   - **OData pagination via `@odata.nextLink`.** Successive pages are fetched by sending the verbatim next-link URL with no query-parameter overlay. The first call carries `$filter` and `$top`; subsequent pages do not.
   - **HTTP error classifier.** 408/429/5xx → `TransientError` with `Retry-After`. 403 (missing Graph scope) and 404 surface immediately so operators learn to fix app-registration permissions instead of waiting through silent retries.
   - **Strict open-interval boundary filter** matches the GWS and Management Activity collectors. OData `ge`/`lt` is inclusive on the lower bound so the boundary event would otherwise re-emit each poll.
   - `tests/unit/test_microsoft_graph_collector.py` — 20 unit tests. Coverage: helper round-trip (Graph's millisecond-resolution + Z format), feed-config completeness, source-name unification with Management Activity, feed selection (default/subset/unknown), happy path for each of the four feeds verifying correct endpoint + filter time-field, first-run 7-day backfill window encoded in filter, two-page nextLink walk with verbatim URL propagation, since-boundary exclusion, until-boundary exclusion, missing-time-field drop, 429 retry, 503 retry, 403 NOT retried (deliberate; surfaces as feed error), event enrichment with `event_time` and `event_id`, four-feed fan-out with independent watermarks and partitions, source-partition unification with Management Activity, missing-secrets error path.

   **Risky-users deferred.** Spec §3.3 listed `riskyUsers and riskDetections` together under one logical feed name. Of those two, `riskDetections` is a time-series event stream and lives here as `risk_detections`. `riskyUsers` is current per-user risk state, structurally a posture concept not an event stream, and belongs in mantissa-stance (evaluated on a schedule against a "no user should sit at high risk for more than N hours" YAML policy). A `# TODO` is left in the Graph collector to document the trail.
6. **PR 6 — destructive-event rule pack + paging metadata in alert router.** [Status: done, 2026-05-10.] Shipped:
   - `rules/sigma/destructive/` — 22 paging-grade Sigma rules covering identity / privilege escalation (super admin grants across GWS/M365/Okta/AWS/GCP/Azure), MFA tampering (org-wide 2SV disable, Security Defaults disable, Conditional Access disable, admin MFA reset), mass data egress and destruction (GWS Drive mass download / mass delete, M365 SharePoint mass download, mailbox mass export, S3 made public, S3 mass delete, GitHub repo made public / deleted), OAuth / app trust (GWS Drive/Gmail full-scope grant, M365 high-privilege Graph consent), and logging tampering (CloudTrail stopped, GCP audit-log sink deleted, M365 Unified Audit Log disabled). Every rule carries three custom top-level fields: `paging: true`, `evidence_query` (SQL the bot auto-runs scoped to actor + time window), `paging_destinations` (default `[pagerduty, slack, teams]`).
   - `rules/sigma/destructive/_README.md` — short README documenting the custom fields, severity convention, and coverage so contributors can add new rules without re-reading the spec.
   - `scripts/generate_destructive_rules.py` — re-runnable, idempotent generator that produces all 22 YAMLs from a single in-file inventory. Lives outside `src/` because it is a build-time tool, not runtime code. Future rule additions go in the inventory and re-run the script.
   - `src/shared/alerting/paging.py` — small, focused extension module. `PagingMetadata` dataclass; `extract_paging_metadata(rule_yaml) -> Optional[PagingMetadata]`; `attach_to_alert(alert, meta)` writes `metadata["paging"]`, `metadata["evidence_query"]`, `metadata["paging_destinations"]` onto an `Alert.metadata` dict via duck typing (no import cycle into detection package); `PagingAwareRouter` composes (does not subclass) the existing `AlertRouter`, augmenting `alert.destinations` with the rule's paging destinations before delegating. Composition over subclassing avoids coupling to the underlying router's private `_determine_destinations`.
   - `tests/unit/test_destructive_event_pack.py` — 65 unit tests across two surfaces. Rule pack (loaded once at import, parametrized per rule): count is 22, filename convention, parse, required Sigma fields, level=critical, paging=true, evidence_query present and SELECT/WHERE-shaped, paging_destinations include a routable sink, detection block valid, MITRE tag present, unique IDs across pack, all five spec categories represented, coverage spans the three clouds and three SaaS surfaces (AWS, GCP, Azure/M365, GWS, Okta, GitHub). Paging module: extractor handles paging-true / paging-false / paging-absent / bad-type / non-dict; attach_to_alert writes the three keys, skips evidence_query when missing, initializes metadata when None; PagingAwareRouter augments destinations only when paging is set, preserves order, dedupes existing entries, handles batch routes, handles alerts that arrive without a destinations attribute. End-to-end test loads a real destructive rule from disk, extracts metadata, attaches to an alert, runs through the router, and asserts all three declared paging destinations land on the alert.
   - Combined regression: **313/313 tests pass** (196 PR 6 + 117 prior PRs).

   Design note. The 22 rules use product/service field names and event.action values consistent with the existing mantissa-log rule packs and the new parsers shipped in PRs 1–5. Field-level fidelity to upstream Reports API / Management Activity / Graph schemas will tighten as deployments report false positives; the PR 6 baseline is structurally correct (right event surfaces, right MITRE tags, right paging metadata) and ready for production tuning. Threshold rules (mass-download, mass-delete) declare `threshold: {field, operator, value, window_minutes}` blocks that the Sigma engine consumes; tuning these thresholds per deployment is documented as a follow-on operator task.

   Out of scope, deferred. The Slack / Teams **thread investigation** behaviour (replies auto-scope to the alert's actor + time window via NL→SQL) ships in PR 7 and PR 8, not here. PR 6 only ensures the alert carries enough metadata for those bots to render the rich-format page and route follow-up queries correctly.
7. **PR 7 — Slack bot.** [Status: done, 2026-05-10.] Shipped:
   - **Transport-agnostic bot core** at `src/shared/integrations/bot/` so PR 8 (Teams) reuses the dispatcher and command implementations without duplicating logic:
     - `dispatcher.py` — `parse_command()` recognizes `ask`/`explain`/`health` with implicit-`ask` fall-through; `Dispatcher` routes parsed commands to injected handlers; `BotContext` is transport-neutral; `BotResponse` carries the always-shown determinism triplet (`sql`, `row_count`, `cost_cents`).
     - `commands.py` — `AskCommand`, `ExplainRuleCommand`, `HealthCommand`. Each depends on a single duck-typed collaborator (NL engine, rule store + NL translator, health monitor) so tests inject fakes without standing up real LLM or lake.
     - `thread_context.py` — `extract_scope(parent_message) -> ThreadAutoScope` and `ThreadAutoScope.augment_question(...)`. Pulls actor / source / feed / event_time from common payload paths (top-level, `metadata`, first `results[0]`). Missing fields silently return `None` so the augmenter never invents context.
   - **Slack adapter** at `src/shared/integrations/slack/`:
     - `blocks.py` — `response_to_blocks(response)` renders the triplet as a context block, the SQL inside a fenced code section, and the summary as markdown. `text_fallback(response)` produces the plain-text fallback for notifications and screen readers.
     - `app.py` — `SlackApp(dispatcher).register(bolt_app)` wires the `/mantissa` slash command and the `message` thread-reply event onto a slack_bolt `App`. `slack_bolt` is imported lazily inside `build_app()` so the module loads cleanly without it.
   - Thread-reply behaviour shipped end-to-end: a reply in a thread under a destructive-event alert reads the alert payload from Slack `metadata.event_payload` (with a `mantissa_alert_payload` JSON-block fallback for older clients), augments the question with `actor=`, `source=`, `feed=`, `time_window=` hints, and dispatches the augmented question through the same `AskCommand`. The Slack thread itself becomes the incident channel; no separate console.
   - `tests/unit/test_slack_bot.py` — **42 unit tests**, all passing. Covers four layers: command parsing (7), dispatcher routing including handler-exception → error-response (5), thread auto-scope extraction and question augmentation (8), each command's happy path + error paths (12), Slack Block Kit rendering of the triplet / error flag / oversize truncation / passthrough blocks / text fallback (7), and the SlackApp wiring through a fake Bolt app for both the slash command and the thread-reply event including bot-message suppression (5). Combined regression: **355/355 pass**.

   Pre-existing bug fixed during PR 7. `src/shared/integrations/__init__.py` had eager imports referencing classes that did not exist (`EmailValidator`, `DLQHandler`, etc.); any test that imported from `shared.integrations.*` failed at collection. Switched to a lazy-import docstring-only `__init__.py` so subpackages load cleanly. Documented the change in the file's docstring.

   Out of scope, deferred. Per-channel allowlists for who may run paid LLM queries (spec §5 last paragraph) are not enforced in PR 7. The hook point is clear (in `SlackApp.handle_command` before dispatching), but the actual policy belongs to the operator's deployment configuration; a follow-on PR will wire this through an injectable `policy` callable.
8. **PR 8 — Teams bot.** [Status: done, 2026-05-10.] Shipped:
   - **Microsoft Teams adapter** at `src/shared/integrations/teams/` reusing the entire transport-agnostic bot core from PR 7. No duplication of command parsing, dispatcher, thread-scope extraction, or command implementations — only the rendering layer and the Bot Framework wiring are new.
     - `cards.py` — `response_to_card(response)` produces Adaptive Cards 1.5 JSON: summary as `TextBlock` (markdown+wrap), determinism triplet as `FactSet` (Rows / Cost / Status), SQL as `Container` with monospace `TextBlock`, passthrough blocks appended. `to_attachment(card)` wraps in the Bot Framework `application/vnd.microsoft.card.adaptive` attachment shape. `text_fallback(response)` mirrors the Slack fallback so both transports emit identical text on low-fidelity clients.
     - `app.py` — `TeamsApp(dispatcher)`. Two entry points: `handle_activity(activity_dict, send, parent_lookup=None)` is transport-neutral and dict-shaped for testability; `register(bot_app)` and `build_app()` wire into `botbuilder-core` lazily (the SDK is only imported inside `build_app`, never at module load).
   - **Thread reply auto-scope** works identically to Slack: an activity carrying `replyToId` triggers a `parent_lookup(message_id)` call (operator wires this to Microsoft Graph or a local message-id-to-payload side store); the resulting alert payload feeds the same `extract_scope` and `augment_question` helpers from PR 7. The reply preserves `replyToId` and the `conversation` reference so Teams threads the reply correctly.
   - **Bot self-message suppression** handles both Bot Framework versions: `from.role == "bot"` and `channelData.isBot == True`. Non-message activities (typing, conversationUpdate, messageReaction) are filtered at the entry point.
   - `tests/unit/test_teams_bot.py` — **24 unit tests**, all passing on first run. Coverage: Adaptive Card envelope (schema/version/type), triplet rendering in FactSet, no FactSet when triplet absent, error status fact, SQL container with Monospace fontType, no container when SQL absent, oversize-summary truncation at 8000 chars, passthrough blocks, non-dict passthrough filtered, text fallback carrying triplet, fallback marker for empty response, full handle_activity happy path producing an Adaptive Card attachment, non-message activity ignored (typing, conversationUpdate), empty-text ignored, bot self-message suppression (both detection paths), thread reply auto-scope with parent_lookup returning context, thread reply with no parent_lookup or parent_lookup returning None, explain rule via Teams, health via Teams, non-dict activity no-op, register decorator attaches handler, register on app lacking on_message is no-op.
   - Combined regression: **379/379 tests pass** (24 PR 8 + 42 PR 7 + 196 PR 6 + 20 PR 5 + 24 PR 4 + 39 PRs 2-3 + 34 PR 1) in 0.42s.

   Architecture note. PR 7 and PR 8 ship as **sibling adapters around one shared `Dispatcher`** rather than a single bot with two transports. Slack and Teams have genuinely different threading models (Slack: `thread_ts`, callback-based Bolt; Teams: `replyToId` plus conversation reference, async `TurnContext`). Forcing them into a single base class would smuggle async into the Slack side or block the Teams side. The shared `Dispatcher` + sibling adapters keeps each transport honest to its API while sharing 100% of the business logic.

9. **PR 9 — M365 production HTTP client (post-spec follow-on).** [Status: done, 2026-05-10.] Shipped:
   - `src/shared/collectors/m365_http_client.py` — production HTTP clients backing the M365 collectors that PR 4 and PR 5 had only stubbed via lazy imports. Three components:
     - `TokenProvider` — OAuth 2.0 client-credentials token acquisition against `https://login.microsoftonline.com/{tenant_guid}/oauth2/v2.0/token`. In-memory cache with 60-second pre-expiry refresh buffer. Exposes `invalidate()` so 401 responses force a re-fetch on the next call. `TokenAcquisitionError` carries status code and response body for operator diagnosis (wrong client id, wrong tenant guid, secret expired, missing scope, conditional access blocking the SP).
     - `ManagementActivityHTTPClient` — three methods matching the duck-typed contract `Microsoft365Collector` expects: `start_subscription` (idempotent; treats Microsoft's `AF20024` "already enabled" 400 response as success), `list_content` (walks the `NextPageUri` response header until exhausted), `fetch_blob`. Wraps non-2xx into `ManagementActivityHTTPError` with parsed `Retry-After`.
     - `GraphHTTPClient` — single `get(url, params=None)` method. Sends `Authorization: Bearer`, `Accept: application/json`, and the `ConsistencyLevel: eventual` header required for `$filter` on several Graph endpoints. Wraps non-2xx into `GraphHTTPError` with parsed `Retry-After`. 401 invalidates token cache.
   - Both clients accept an injectable `transport` parameter (duck-typed `.get()` / `.post()`); production uses `requests.Session` lazily; tests inject a fake that records calls. `requests` is already in `requirements.txt`.
   - `tests/unit/test_m365_http_client.py` — **27 unit tests**. Coverage: `Retry-After` parsing (seconds/HTTP-date/invalid), TokenProvider fetch with correct payload, in-window caching, refresh inside refresh buffer with a fake clock, invalidate forces refresh, non-2xx token endpoint raises `TokenAcquisitionError`, malformed token body raises, Management Activity subscribe-with-bearer, AF20024 idempotency, other 400 still raises, single-page list, NextPageUri walk with params dropped on subsequent calls, 429 with `Retry-After` populated, 503 wrapped, fetch_blob returns list and tolerates non-list bodies, 410 wrapped, 401 invalidates cache so the next call re-fetches the token, Graph get with bearer + ConsistencyLevel + scope=graph, Graph 429 retry_after, Graph 403 wrapped (canonical wrong-scope failure), Graph non-dict body returns empty dict, Graph 401 invalidates.
   - `tests/integration/test_m365_collectors_with_http_client.py` — **2 integration smoke tests** wiring the real `ManagementActivityHTTPClient` and `GraphHTTPClient` into `Microsoft365Collector` and `MicrosoftGraphCollector` via `client_factory`, using a fake transport that routes by URL pattern. Confirms the end-to-end production path: token endpoint → subscription start → list content → fetch blob → lake partition for Management Activity, and token endpoint → Graph signIns endpoint → lake partition for Graph.
   - Combined regression: **408/408 tests pass** (29 PR 9 + 379 prior).

   Design note. PR 9 fills a real gap that the spec marked as "imported lazily" but never delivered: without these clients, the M365 collectors are non-functional in production despite passing their unit tests (which inject fakes). The injectable-transport pattern makes the clients themselves testable without a network round-trip, and the integration tests verify the seam between collector and client end-to-end.

10. **PR 10 — Okta System Log collector (§10 follow-on pack: SaaS collectors).** [Status: done, 2026-05-10.] Shipped:
    - `src/shared/collectors/okta_collector.py` — `OktaCollector(BaseSaaSCollector)`. Source name `okta`. Single feed `system` covering the entire System Log; per-event-type partitioning would explode partition count without query benefit since operators can re-shape on read in SQL. Event time from `published`, stable id from `uuid`, both injected into the lake payload alongside the original Okta event dict. Strict open-interval boundary filter on `(since, until)` so Okta's inclusive `since` parameter doesn't re-emit the boundary event each poll. HTTP error classifier wraps 408/429/5xx as `TransientError` with parsed `Retry-After`; 403 (canonical wrong-scope failure on the API token) surfaces immediately. Streaming errors on `list_next` calls are NOT retried per the base contract; they surface as feed-level errors so the operator sees which page failed.
    - `src/shared/collectors/okta_http_client.py` — `OktaSystemLogClient`. Two methods: `list_logs(since, until, limit)` and `list_next(url)`. Authentication via Okta API token (`SSWS` scheme; tokens live at `okta/{tenant_id}/api_token`). Standard Okta `Link` header pagination with a `_LINK_RE` regex pulling the `rel="next"` URL so the collector receives a normalized `next_url` and never has to parse Link headers itself. `OktaHTTPError` wraps non-2xx with status + `Retry-After`. Accepts either a bare domain (`acme.okta.com`) or a fully qualified URL (`https://acme.oktapreview.com`) so preview tenants and custom domains work without double-prefix bugs.
    - Why this PR. Spec §10 lists "Slack / Salesforce / GitHub / Okta SaaS collectors as a follow-on pack." Okta is the highest-leverage of the four: PR 6's destructive-event rule pack already includes `dest_okta_super_admin_granted` and `dest_okta_mfa_factor_reset_for_admin`. Without an ingest collector those rules cannot fire. The System Log parser already exists at `src/shared/parsers/okta.py` and 50+ Okta Sigma rules are already in the rules tree; this collector closes the ingest gap.
    - `tests/unit/test_okta_collector.py` — **27 unit tests**. Coverage spans the collector and the HTTP client: helpers (iso round-trip with millisecond format, default feed set), feed selection (default + unknown rejected), single-page happy path with watermark advance, first-call carries since/until/limit verifying 7-day backfill in the filter, two-page pagination via `next_url`, since/until boundary exclusion, malformed-event drop, raw event enrichment with `event_time`/`event_id` injected, 429 retried, 403 NOT retried (canonical wrong-scope), 410 on `list_next` surfaces as feed-level error, missing-secrets error path; `_extract_next_url` Link header parsing for present/self-only/blank cases, `_parse_retry_after` numeric and invalid, HTTP client list_logs bearer + headers + params, Link header → next_url extraction, list_next carries no extra params, 429 with `Retry-After`, 403 wrapped, full URL accepted without double prefix, non-list response body becomes empty items.
    - Combined regression: **435/435 tests pass** (27 PR 10 + 408 prior) in 0.48s.

11. **PR 11 — GitHub Audit Log collector (§10 follow-on pack continued).** [Status: done, 2026-05-10.] Shipped:
    - `src/shared/collectors/github_collector.py` — `GitHubAuditCollector(BaseSaaSCollector)`. Source name `github`. Single feed `audit`. Tenant id format: `orgs/{slug}` or `enterprises/{slug}` — constructor validates the prefix so misconfiguration fails fast. Includes parameter `include` ∈ `{web, git, all}` defaulting to `all` so Git protocol events (clones, pushes) ride alongside web/API events; the destructive `dest_github_repo_made_public_or_deleted` rule needs both. Event time from GitHub's `@timestamp` (Unix milliseconds, normalized to ISO 8601 in the lake payload), stable id from `_document_id`. Strict open-interval `(since, until)` boundary filter.
    - `src/shared/collectors/github_http_client.py` — `GitHubAuditClient`. Two methods: `list_logs(phrase, include, per_page)` and `list_next(url)`. Authentication via Bearer token (PAT, fine-grained PAT, or GitHub App installation token — all use the same header). Phrase filter uses `created:>=ISO created:<=ISO` syntax so the API-side filter is precise even before the collector's open-interval boundary check. Pins `X-GitHub-Api-Version: 2022-11-28` so the response shape doesn't shift under us silently. Standard `Link` header pagination via the same regex used in the Okta client. **GitHub-specific quirk handled**: 429 responses sometimes omit `Retry-After` but always carry `X-RateLimit-Reset` (epoch seconds); the client checks `Retry-After` first, then falls back to computing seconds-until-reset from `X-RateLimit-Reset` so the collector's retry backoff has a real value.
    - `tests/unit/test_github_collector.py` — **32 unit tests**. Coverage: helpers (`_format_github_iso`, `_from_millis` including bad input), constructor validation (rejects bare slug without `orgs/` or `enterprises/` prefix, accepts both forms, rejects bad include value, rejects unknown feed), single-page write + watermark advance, phrase filter contains `created:>=` and `created:<=` with 7-day backfill range, two-page pagination via next_url, since/until boundary exclusion, missing-timestamp drop, event enrichment with `event_time` + `event_id` injected and original `@timestamp` preserved, 429 retried, 404 NOT retried (canonical wrong-scope token), 503 on `list_next` surfaces as feed error, missing-secrets path; HTTP client tests: Link header next-url extraction (next/prev/blank), `_parse_retry_after`, org vs enterprise URL routing, scope validation rejection in constructor, Link extraction in real response, list_next no params overlay, **429 with explicit `Retry-After`**, **429 falling back to `X-RateLimit-Reset` with the monkey-patched clock**, 403 wrapped, non-list response body becomes empty items.
    - Combined regression: **467/467 tests pass** (32 PR 11 + 435 prior) in 0.50s.

12. **PR 12 — Slack Audit Logs collector (§10 follow-on pack continued).** [Status: done, 2026-05-10.] Shipped:
    - `src/shared/collectors/slack_collector.py` — `SlackAuditCollector(BaseSaaSCollector)`. Source name `slack`, single feed `audit`. The Slack Audit Logs API (Enterprise Grid only) exposes one endpoint with cursor-based pagination via `response_metadata.next_cursor` rather than a Link header, which keeps the page-walk loop slightly simpler than the Okta and GitHub clients. Event time from `date_create` (Unix epoch seconds, integer → normalized to ISO 8601 in the lake payload), stable id from `id`. Strict open-interval `(since, until)` boundary filter.
    - `src/shared/collectors/slack_http_client.py` — `SlackAuditClient`. Two methods: `list_logs(oldest, latest, limit)` and `list_next(cursor)`. Bearer-token auth with `auditlogs:read` scope. **Slack-specific quirk handled**: Slack returns 200 OK with `{"ok": false, "error": "..."}` for application-layer failures (token / scope issues, rate limits). The client synthesizes an HTTP status from the error code: `ratelimited` → 429 (transient, retried) and any other `ok=false` → 400 (terminal, surfaces as feed error). Without this translation the body-level errors would silently look like empty pages.
    - `tests/unit/test_slack_collector.py` — **28 unit tests**. Coverage: helpers (`_to_epoch_seconds` round-trip with `_from_epoch_seconds`, garbage input handling), feed selection (default + unknown rejection), single-page write + watermark advance, `oldest`/`latest` carry correct epoch seconds with 7-day backfill, two-page cursor pagination, since/until boundary exclusion, missing-`date_create` drop, event enrichment with original `date_create` preserved, 429 retried, 403 NOT retried (wrong-scope token), 502 on `list_next` surfaces as feed error, missing-secrets path; HTTP client tests: `_parse_retry_after` numeric and blank, bearer + params on `list_logs`, `entries` and `next_cursor` extraction, **empty next_cursor becomes None** (Slack returns `""` not `null`), `list_next` carries cursor as query param, 429 with `Retry-After` wrapped, 403 wrapped, **application `ok=false` synthesized as HTTP 400**, **application `ratelimited` synthesized as HTTP 429 with Retry-After preserved**, non-dict body returns empty page, missing `entries` returns empty.
    - Combined regression: **495/495 tests pass** (28 PR 12 + 467 prior) in 0.52s.

13. **PR 13 — Salesforce Event Monitoring collector (§10 follow-on pack — final entry).** [Status: done, 2026-05-10.] Shipped:
    - `src/shared/collectors/salesforce_collector.py` — `SalesforceCollector(BaseSaaSCollector)`. Source name `salesforce`, single feed `events`. **Two-step pattern**: (1) SOQL-query the `EventLogFile` sObject for files in the time window; (2) for each record, fetch the CSV body at the `LogFile` relative URL and yield each row as an event. Structurally closer to the M365 Management Activity collector (blob list + blob fetch) than to the Okta/GitHub/Slack collectors which all use a single paginated endpoint. We do not share the M365 code because auth model, body format (CSV vs JSON), and response shapes are too different for a clean shared base.
    - Time-model handling. Salesforce events use `TIMESTAMP_DERIVED` (ISO 8601 with `+0000` offset) when present; `TIMESTAMP` (legacy `YYYYMMDDHHMMSS.mmm` format) is the fallback for older event types. Both parsers ship as helpers (`_parse_sf_iso` normalizes `+0000` → `+00:00` so `datetime.fromisoformat` accepts it; `_parse_sf_compact` parses the 14-digit form). The `_event_time` helper prefers derived then compact then `None`. Stable id from `EVENT_UUID` → `REQUEST_ID` → empty (base class accepts empty event ids and falls back to event-time-only watermark advance).
    - **EventType annotation**: the parent `EventLogFile.EventType` is a stronger signal than per-row event-type fields (some event types omit it on the row). The collector fills `EVENT_TYPE` from the parent when the row doesn't already carry one. Existing row-level `EVENT_TYPE` is never overwritten.
    - `src/shared/collectors/salesforce_http_client.py` — `SalesforceEventClient`. Two methods matching the duck-typed contract: `list_log_files(since, until)` and `fetch_log_file(url)`. OAuth 2.0 client-credentials flow against the org's login endpoint with token caching (60-second refresh buffer, `invalidate()` on 401). The SOQL query is paginated internally via `nextRecordsUrl` / `done` so callers see one flat list. The CSV body is parsed with `csv.DictReader` and returned as a list of dicts so the collector iterator does not handle the body format. `SalesforceHTTPError` wraps non-2xx; `SalesforceTokenError` for token endpoint failures.
    - `tests/unit/test_salesforce_collector.py` — **39 unit tests**. Coverage spans the collector and the HTTP client.
      - Timestamp parsers: ISO with `+0000` offset, ISO with colon offset, ISO with Z, invalid; legacy compact format, blank, garbage, bad month/day; `_event_time` prefers derived over compact and returns None when both absent.
      - Event id resolution: prefers `EVENT_UUID`, falls back to `REQUEST_ID`, empty when neither.
      - SOQL ISO formatting at seconds resolution.
      - Feed selection (default + unknown rejected).
      - Single-file-single-event happy path with watermark advance.
      - SOQL since/until window with 7-day backfill.
      - Multi-file flatten: each EventLogFile fetched, events concatenated in order.
      - EventType annotation from parent when row absent; existing row value not overwritten.
      - Boundary exclusion (since, until).
      - EventLogFile missing `LogFile` URL skipped without crashing.
      - Event missing both timestamp fields dropped without poisoning watermark.
      - 429 on list retried, 404 on list NOT retried, 503 on fetch surfaces as feed error.
      - Missing-secrets path.
      - HTTP client: `_parse_retry_after`; token fetch with correct payload; token cache within expiry (monkey-patched clock); refresh near expiry; token endpoint failure raises `SalesforceTokenError`; SOQL query carries the time window with `>=` and `<` and `ORDER BY ASC`; `nextRecordsUrl` pagination with no overlay params on the second call; CSV body parses into row dicts and URL is resolved against the instance URL; absolute URL passes through unchanged; empty body returns empty list; 429 on fetch wraps with `Retry-After`; **401 invalidates the token cache** so the next call re-fetches (proven by counting POST requests to the token endpoint).
    - Combined regression: **534/534 tests pass** (39 PR 13 + 495 prior) in 0.52s.

    Design note. PR 13 closes the §10 SaaS collectors follow-on pack. All four sources (Okta, GitHub, Slack, Salesforce) follow the same `BaseSaaSCollector` template; the differences live in their API quirks, each documented in the relevant PR notes. The four collectors collectively prove that the base abstraction holds across single-endpoint-flat-stream (Okta, GitHub, Slack) and two-step-query-then-fetch (Salesforce) patterns, which is the structural diversity needed to claim the abstraction generalizes.

14. **PR 14 — SaaS sign-in IP threat-intel enrichment (§10 follow-on).** [Status: done, 2026-05-10.] Shipped:
    - `src/shared/enrichment/saas_signin.py` — bridges every SaaS collector shipped in PRs 2–13 to the existing `ThreatIntelService`. Three components:
      - `SAAS_FEED_IP_PATHS` — explicit registry mapping each `(source, feed)` tuple to the dotted path where the actor IP lives in the raw collector payload. Covers 33 (source, feed) pairs across GWS (21), M365 Management Activity (5), M365 Graph (4), Okta (1), GitHub (1), Slack (1), Salesforce (1). Three M365 feeds are deliberately registered with `None` to mean "known feed, no IP" (directory_audits, defender_alerts) — distinguishable from "unknown feed" so callers can treat both as skip without surprises.
      - `SaaSSigninEnricher` — duck-typed wrapper around `ThreatIntelService.lookup_ip_reputation`. Attaches a normalized `threat_intel` block to the event in place. Returns the event for chaining. Idempotent (existing `threat_intel` left untouched). Swallows lookup failures so enrichment never poisons the ingest path.
      - `get_path`, `is_routable_ip` — small helpers. `is_routable_ip` filters private/loopback/link-local/multicast/reserved/unspecified addresses (including RFC 5737 / 3849 documentation ranges) so the threat-intel cache and API quota are not wasted on traffic that carries no signal.
    - Placement in the pipeline. Enrichment is deliberately *not* run inside the collector hot path. Collectors keep writing raw events to the lake unmodified; a separate post-ingest enrichment pass (or the existing parser pipeline) consumes raw events, calls `SaaSSigninEnricher.enrich`, and writes enriched Parquet. Keeping collectors stateless on the enrichment side means a failure in the threat-intel provider never blocks ingest.
    - `tests/unit/test_saas_signin_enrichment.py` — **61 unit tests**. Coverage:
      - Registry completeness asserted dynamically against `GoogleWorkspaceCollector.ALL_FEEDS`, `Microsoft365Collector.ALL_FEEDS`, and `MicrosoftGraphCollector.ALL_FEEDS` so adding a future feed to any collector will break this test until enrichment coverage catches up.
      - Path resolver: top-level, nested, deeply nested, missing, non-dict intermediate, non-string value rejected.
      - Routability filter: 4 public IPs (incl. IPv6), 8 private/reserved/link-local cases, 3 documentation ranges (RFC 5737 TEST-NET-2/3 and RFC 3849 IPv6 docs range), 4 invalid inputs, whitespace stripping.
      - Enricher happy paths (GWS top-level, Okta nested, Slack double-nested), skip paths (unknown feed, registered-None feed, missing IP, private/loopback/invalid IP), error handling (service raises, service returns None), idempotency (existing block preserved, double-enrich calls service exactly once).
      - **Representative sweep**: one parametrized test per source/feed pair (12 cases covering every distinct path shape across all 7 SaaS surfaces) confirming the registry's path resolves the correct IP from a realistic event payload. If a future change moves an IP field, the test for that source/feed breaks immediately.
      - Result-dict contract: enrichment payload has exactly the documented 12 keys (`ip`, `reputation_score`, `is_malicious`, `confidence`, `categories`, `abuse_score`, `total_reports`, `is_tor_exit`, `is_vpn`, `is_proxy`, `sources`, `cached`); sparse TI providers exposing only a subset still produce a valid dict with defaults rather than crashing on `getattr`.
    - Combined regression: **595/595 tests pass** (61 PR 14 + 534 prior) in 0.55s.

    Design note. PR 14 closes the last technical item in §10 ("Threat-intel enrichment for SaaS sign-in IPs — uses the existing enrichment/ module but needs a feed config update"). The registry is the load-bearing artifact: it is the contract between the collectors (which know their raw shapes) and the enrichment layer (which knows the threat-intel API). New SaaS collectors land their (source, feed) → path entry in `SAAS_FEED_IP_PATHS` and inherit enrichment for free.

Identity baseline wiring (§3.5) happens implicitly across PRs 2–5 by writing into the existing tables that `baseline_calculator.py` reads from. No standalone PR needed.

---

## 9. Success Criteria

- A user installs mantissa-log, runs `mantissa-log connect google-workspace` and `mantissa-log connect microsoft-365`, waits an hour, and can ask in Slack: *"show me every OAuth grant this week with Drive full-scope or Mail.ReadWrite, with the granting user's country"* — and gets a correct, SQL-backed answer.
- Org-wide 2FA disable in either provider pages on-call within 5 minutes of the audit-log event landing.
- Cross-source query works: *"users who had a risky M365 sign-in today and also touched AWS IAM"* returns a joined result from `m365_signins` and `aws_cloudtrail`.
- Zero new infrastructure: same lake, same query engine, same NL router, same alert router.

---

## 10. Out of Scope, Tracked for Later

- ~~SaaS collectors follow-on pack: Okta, GitHub, Slack, Salesforce.~~ Complete (PRs 10–13). All four collectors landed, all parsers wired through, all production HTTP clients in place. Next additions to the pack (Notion, Atlassian, Zoom, etc.) can follow the same `BaseSaaSCollector` template.
- ~~Threat-intel enrichment for SaaS sign-in IPs — uses the existing `enrichment/` module but needs a feed config update.~~ Done in PR 14. Registry at `src/shared/enrichment/saas_signin.py:SAAS_FEED_IP_PATHS` covers all 33 (source, feed) pairs across the seven SaaS surfaces.
- A `mantissa-log apm` SaaS-uptime story — out of scope, separate module.
- Anything requiring writes to GWS/M365/Okta. Observe-only is a load-bearing property of the project.
