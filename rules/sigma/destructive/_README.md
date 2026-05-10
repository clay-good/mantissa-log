# Destructive-Event Detection Pack

Paging-grade Sigma rules for irreversible or near-irreversible events that
should wake on-call engineers. Maintained per SAAS_IDENTITY_SPEC §4.

## Custom Sigma fields

Every rule in this directory carries three non-standard top-level YAML
fields read by `src/shared/alerting/paging.py`:

- `paging: true` — boolean flag enabling on-call fan-out.
- `evidence_query` — SQL the chat investigation surface auto-runs when the
  alert fires. Should scope to the actor and a tight time window so the
  on-call sees adjacent activity in the page.
- `paging_destinations` — optional override for the default list of
  `pagerduty`, `slack`, `teams`.

These fields are ignored by standard Sigma tooling, so the rules remain
portable. The paging behaviour is a configuration layered on top of the
existing detection engine.

## Severity

Every rule in this pack uses `level: critical`. By design the pack is
small (target ~20 rules) and high precision. Anything that would
generate more than one page per week across a typical deployment
should not live here.

## Coverage

- Identity / privilege escalation (GWS, M365, Okta, AWS, GCP, Azure)
- MFA / authentication tampering
- Mass data egress and destruction
- OAuth / app trust grants of high-risk scope
- Logging / audit tampering

See SAAS_IDENTITY_SPEC §4 for the rule-by-rule inventory.
