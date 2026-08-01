# Auth Validation Failure Monitoring

## Overview

Clerk JWT validation in `cybersec/apps/api/deps/__init__.py` records every
auth validation failure as a Prometheus counter, in addition to the existing
`logger.warning` lines. This lets you alert on abuse patterns (signature
forgery probing, leaked-token reuse) that are invisible in normal error
logs.

Metrics are exposed by the in-process registry backing
`GET /api/metrics` (see `cybersec/core/metrics_registry.py`). All metrics
are exported with the `cybersec_` prefix, so the metric below is scraped as
`cybersec_auth_validation_failures_total`.

## Metric: `auth_validation_failures_total`

Counter with one label, `reason`. Incremented exactly once per rejected
request at each failure point inside `get_optional_user`.

| reason            | Failure point                                            | What it usually means                                                          |
|-------------------|----------------------------------------------------------|--------------------------------------------------------------------------------|
| `missing_kid`     | JWT header has no `kid` claim                            | Malformed/forged token without a key id                                       |
| `unknown_kid`     | `kid` not found in the cached Clerk JWKS                 | Forged/random key ids (signature-forgery probing) — NOT normal user behavior  |
| `jwt_error`       | Signature/expiry/issuer/audience verification failed     | Expired or invalid tokens; the majority of normal failures                     |
| `missing_sub`     | Token validated but has no `sub` claim                   | Malformed custom token                                                         |
| `inactive_user`   | Local `users.is_active` is false                         | Revoked/banned/deleted user (webhook kill-switch worked)                       |
| `sync_error`      | Local user sync/upsert raised                            | DB or Clerk API problem                                                        |
| `unexpected_error`| Any other exception during validation                   | Bug or unexpected condition — investigate                                      |

Example scrape output:

```
# HELP cybersec_auth_validation_failures_total Auth validation failures, by reason (missing_kid, unknown_kid, jwt_error, missing_sub, inactive_user, sync_error, unexpected_error)
# TYPE cybersec_auth_validation_failures_total counter
cybersec_auth_validation_failures_total{reason="unknown_kid"} 3
cybersec_auth_validation_failures_total{reason="inactive_user"} 17
```

## Metric: `auth_validation_failures_by_ip`

Counter with an `ip` label, incremented for every auth failure with the
client IP (`get_remote_address`; note this is the socket peer, so behind a
reverse proxy you may see the proxy's IP unless `X-Forwarded-For` is
trusted).

**Cardinality is bounded on purpose:** only `MAX_AUTH_FAILURE_IP_SERIES`
(1000) distinct IPs ever get their own series. Once the cap is reached,
new IPs are no longer added to metrics and are instead logged at WARNING —
rely on log-based alerting for those (the total counter is still
incremented for every failure, so the per-reason signal is never lost).

## Suggested alert rule

A burst of `unknown_kid` errors is a signature-forgery/probing pattern —
attackers submitting random key ids. Normal user behavior produces mostly
`inactive_user` and `jwt_error` (expired tokens), which look completely
different. Alert on the rate of `unknown_kid` failures:

```yaml
groups:
  - name: auth-failures
    rules:
      - alert: ClerkJwtUnknownKidBurst
        expr: rate(cybersec_auth_validation_failures_total{reason="unknown_kid"}[5m]) > 5
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Burst of JWT requests with unknown key ids (possible signature forgery probing)"
          description: >
            {{ $value | humanize }} unknown-kid auth validation failures per second over 5m.
            This pattern indicates forged/probed tokens, not normal user behavior.
```

### Additional rules worth considering

- `rate(cybersec_auth_validation_failures_total{reason="missing_kid"}[5m]) > 5`
  — malformed-token probing.
- A sudden jump in `inactive_user` failures for a single user id (visible in
  logs) usually means the webhook revocation worked; a persistent trickle
  for one `sub` can indicate a leaked token still being replayed.
- A large distinct-IP count on `auth_validation_failures_by_ip` (or the
  WARNING log lines past the cardinality cap) indicates distributed
  credential stuffing against the API.

## Testing

`tests/apps/api/test_auth_failure_metrics.py` asserts that each failure
path increments the counters with the correct `reason` label (and that the
IP counter is cardinality-capped).
