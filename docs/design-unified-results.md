# Unified Results Model — Design Proposal

Status: **proposal — no data migrated yet**
Scope: schema + ORM models only; no route/business-logic changes in this pass

## 1. Current state (verified against code + live dev DB)

### 1.1 Two unrelated run tables

| | `scans` | `tool_results` |
|---|---|---|
| Purpose | port scans (CLI `--save`, `scan_type='port'`) + web-app scans (`scan_type='web'`) | the other tools: dns, whois, ping, traceroute, ssl, http_headers, subdomain, geoip, os_fingerprint, port_scan |
| Parent | `scan_results.scan_id FK` (structured rows) | none — flat table, no FK to `scans` |
| Child | `scan_results` (port/vuln rows), `reports.scan_id` | — |
| Columns | id, user_id, target, scan_type, status, port_range, options JSONB, started_at, completed_at, heartbeat_at, worker_id, progress_pct, error_message | id, user_id, tool_name, target, result_data JSONB + lifecycle (status, started_at, completed_at, error_message, heartbeat_at, worker_id, progress_pct) |
| Status vocabulary | `scan_status_enum` | `scan_status_enum` (shared type, added `2026_8_3_0200`) |

Note: the lifecycle columns on `tool_results` already exist (migration `add_tool_results_lifecycle`); both tables already share the exact same enum type. **The gap is lineage, not vocabulary.**

### 1.2 Writers (verified in `tools.py` / `webapp.py` / `cli/main.py`)

- `tool_results` — written only via `_save_tool_result()` in `cybersec/apps/api/routes/tools.py`, called by 10 tools:
  dns, whois (post/stream/get), ping, traceroute, ssl, http_headers, subdomain (post/stream), geoip (post/stream/get), os_fingerprint (post/stream), port_scan (post/stream). Rows are written **after** the run finishes; `status` defaults to `'completed'`.
- `scans` — written by `webapp.py` (`scan_type='web'`, `status` running→completed, one `ScanResult` row per vulnerability with `port=None, protocol='http', state='open', service=vuln_type, banner=evidence, cves=[]`) and by `cli/main.py` (`scan_type='port'`, structured `ScanResult` rows). Worker recovery (`core/recovery.py`) also mutates `scans.status` (`running`→`timed_out`).
- AI endpoints (`ai_analyze`/`ai_chat`) are tier-gated but do **not** persist to `tool_results`.

Dev DB today: 26 `tool_results` rows (21 geoip, 5 whois), 0 `scans`. Data migration cost is trivial right now.

### 1.3 Actual `result_data` shapes (dataclasses + live rows — not assumed)

- **dns** (`DNSResult`): `{target, record_type, records: [{type, ttl, value, priority?, mname?, rname?, serial?}], query_time_ms, error}`
- **whois** (`WHOISResult`, confirmed in dev): flat ~34-key object — `{target, domain, tld, registrar, registrar_iana_id, registrar_url, registrar_abuse_email, registrar_abuse_phone, creation_date, expiration_date, updated_date, domain_age_days, days_until_expiry, expiry_status, name_servers: [], dnssec, status: [], status_explanations: [], emails: [], registrant_org, registrant_country, admin_contact?, tech_contact?, abuse_contact?, privacy_protected, raw_text, rdap?, rdap_available, registry, iana?, available?, historical_whois, related_domains, risk_indicators: [], summary, normalized, cached, error}`
- **ssl** (`SSLResult`, reshaped by the route): `{host, port, tls_version, cipher_suite, certificate: {valid_from, valid_to, days_remaining, issuer, subject, san, is_expired}, valid, is_self_signed, supports_tls12, supports_tls13, error}`
- **geoip** (live row): ~50-key flat object with `ip_results: []`, `resolved_ips: []`, `provider`, `threat_score`, `is_cdn`, etc.

All payloads are **tool-specific and unrelated in shape** — they cannot be normalized into shared columns; they belong in a JSONB payload, exactly as today.

## 2. Options

### Option A — Full unification: new `tool_runs` parent entity

Create a single parent table `tool_runs` and re-point all three children at it.

```
tool_runs (new)                      scans / tool_results (legacy, kept this pass)
├── id  (UUID; reuses legacy scans.id / tool_results.id)
├── user_id FK users SET NULL        tool_results.result_data JSONB   (unchanged payload)
├── tool_name  VARCHAR(50)  ('port_scan', 'webapp', 'dns', ...)
├── target
├── status (scan_status_enum)
├── port_range, options JSONB
├── started_at / completed_at
├── error_message
├── heartbeat_at, worker_id, progress_pct  (worker recovery, port scans)
├── created_at / updated_at
│
├── scan_results.tool_run_id FK CASCADE  (new nullable col; backfilled = scan_id)
├── tool_results.tool_run_id FK CASCADE  (new nullable col; backfilled = id)
└── reports.tool_run_id FK CASCADE       (new nullable col; backfilled = scan_id)
```

Key trick: **`tool_runs.id` reuses the legacy `scans.id` / `tool_results.id`**, so backfill is a plain `INSERT ... SELECT` with zero mapping tables, and `scan_results.scan_id`, `tool_results.id`, `reports.scan_id` are all directly reusable as `tool_run_id`. `tool_name` is normalized to the tier vocabulary (`'port'`→`'port_scan'`, `'web'`→`'webapp'`).

Migration steps (single migration, all additive/backfill — no DROP, no RENAME):
1. `CREATE TABLE tool_runs` (superset of both legacy parents).
2. Backfill from `scans` (n=0 dev) and `tool_results` (n=26 dev).
3. Add nullable `tool_run_id` (indexed) to `scan_results`, `tool_results`, `reports`; backfill each via the id-reuse property.
4. `CREATE INDEX idx_*_tool_run_id` on the three child columns.

Tradeoffs:
- **+** Single lineage: activity feed / usage dashboard becomes one query against `tool_runs` (plus optional LEFT JOIN payloads). The exact problem this task exists to solve.
- **+** Data migration is trivial today (26 rows); id-reuse means no mapping tables and no data loss.
- **+** Route compatibility: old tables keep every column; app code keeps working untouched.
- **−** New rows are still written to the legacy tables until the follow-up pass flips writers (`tools.py _save_tool_result`, `webapp.py`, `cli/main.py`, `recovery.py`) to create `tool_runs` rows — until then, `tool_runs` is populated only by backfill, so the feed query is "current run data + backfilled history" during the transition.
- **−** Bigger ORM diff: new `ToolRun` model; `ScanResult`/`ToolResult`/`Report` grow a `tool_run_id` column. `Scan`/`ToolResult` models stay as the legacy payload carriers.
- **−** Follow-up pass (routes) must learn to create parent rows; worker recovery code currently keys on `scans.status`/`worker_id` and needs re-pointing to `tool_runs` (or a view).

### Option B — Shared vocabulary only (no parent)

`tool_results` already carries lifecycle + the shared enum. The remaining work is a read-path convenience: a `tool_runs` **SQL view** `UNION ALL`ing `scans` (with `scan_type`→`tool_name` normalization) and `tool_results`, plus (optionally) aligning `scans.scan_type` values to the tier vocabulary.

Tradeoffs:
- **+** Essentially zero risk; no table surgery; `tool_runs` view gives the activity feed a single query surface *today* (live rows, not backfilled).
- **−** No real lineage: FKs never exist between `tool_results` and the rest; `UNION` stays forever; the view cannot carry the FK-typed `tool_run_id` that children would need.
- **−** "Run history" stays two physical tables; any future FK (e.g. linking a report or a webhook event to a dns run) is impossible.
- **−** Doesn't fix the core modeling smell — it papers over it with a view.

### Recommendation

**Option A.** The lineage gap is exactly the problem statement; dev data is tiny so the backfill is trivial; id-reuse keeps it lossless and backward-compatible. Option B is a fine stopgap if the team wants zero schema risk this quarter — the view can even be created first and swapped out later — but it does not unify the model.

## 3. Chosen-option implementation (schema-only)

To be written once the option is chosen:

1. Alembic migration (additive + backfill as above, `if_not_exists`/`if_exists` where applicable, downgrade = drop the added columns/tables — idempotent on re-run).
2. `cybersec/database/models.py`: new `ToolRun`; add `tool_run_id` to `ScanResult`, `ToolResult`, `Report`; `Scan`/`ToolResult` kept as legacy carriers.

## 4. Call sites to update in the follow-up pass (flagged, not touched here)

- `cybersec/apps/api/routes/tools.py` — `_save_tool_result()` must create a `ToolRun` parent (status running→completed, started_at/completed_at) and attach the `ToolResult` payload via `tool_run_id`.
- `cybersec/apps/api/routes/webapp.py` — `webapp_scan_start` / `webapp_scan` create `Scan` with `scan_type='web'`; switch to `ToolRun(tool_name='webapp')`; `_persist_web_scan`/inline persist write `ScanResult` → `tool_run_id`.
- `cybersec/apps/cli/main.py` — `_save()` creates `Scan(scan_type='port')` + `ScanResult`; switch to `ToolRun(tool_name='port_scan')`.
- `cybersec/core/recovery.py` — dead-worker scan recovery queries `scans.status='running'` / `worker_id`; re-point to `tool_runs` (or a view) and update `WorkerHeartbeat.active_scans` semantics.
- `cybersec/apps/api/routes/reports.py` — `Report.scan_id` → `tool_run_id`; export join keys change.
- `cybersec/apps/api/routes/user.py` — history query reads `ToolResult`; migrate to `ToolRun` (optionally LEFT JOIN payloads).
- `cybersec/integrations/ai/context_builder.py` — reads `scan.scan_type`; use `tool_run.tool_name`.
- `cybersec/apps/api/schemas/tool.py` — `ToolResultOut` unchanged for now; follow-up may add `tool_run_id`.
- Legacy column cleanup (drop `scans.scan_type`, rename `scan_id` → `tool_run_id`) happens in a **later** migration after routes are on the new path.
