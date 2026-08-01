# Auth Hardening Changelog

Incremental security improvements to authentication after the production
auth outage documented in [AUTHENTICATION_AUDIT_REPORT.md](./AUTHENTICATION_AUDIT_REPORT.md).

---

## 2026-08-01 — Drop legacy `users.hashed_password` column

### Problem

The `hashed_password` column on `users` is dead capability left over from the
pre-Clerk password auth system. `routes/auth.py` is a no-op router (zero
routes), nothing reads or writes the column except `user_sync.py`, which
unconditionally sets it to `NULL`. Keeping it means password auth could be
accidentally reactivated in a future change.

### Change

Removed legacy password auth column post-Clerk migration — password auth is no
longer possible even at the schema level.

| Area | Detail |
|------|--------|
| Migration | `alembic/versions/2026_8_1_0000-remove_hashed_password.py` drops `users.hashed_password` (downgrade restores it as nullable) |
| Model | `hashed_password` column removed from `User` in `cybersec/database/models.py` |
| Sync | `cybersec/apps/api/user_sync.py` no longer sets `hashed_password` (was always `None`) |
| Deps | `passlib[bcrypt]` removed from `Dockerfile` pip install line (never listed in `pyproject.toml`/`requirements.txt`; no imports remain anywhere) |
| Docs | `README.md` auth row no longer claims bcrypt; `infrastructure/db/supabase_tables.sql` reference schema no longer defines the column |

### Rollout

Schema migration — take a DB backup checkpoint before applying. Safe because
the column was already nullable and NULL for every Clerk-managed row; dropping
it destroys no data that the application can read.

### Files touched

- `alembic/versions/2026_8_1_0000-remove_hashed_password.py` (new)
- `cybersec/database/models.py`
- `cybersec/apps/api/user_sync.py`
- `Dockerfile`
- `README.md`
- `infrastructure/db/supabase_tables.sql`
- `AUTH_HARDENING_CHANGELOG.md` (this file)

---

## 2026-08-01 — JWT audience verification (`CLERK_AUDIENCE`)

### Problem

`get_optional_user` decoded Clerk JWTs with `options={"verify_aud": False}`,
so any token with a valid signature and issuer was accepted regardless of
audience. That is safe for default Clerk session tokens (which omit `aud`),
but it is a silent gap if tokens are ever shared across apps or if a custom
template adds an audience claim that production should enforce.

### Change

| Area | Detail |
|------|--------|
| Setting | `CLERK_AUDIENCE: str = ""` in `cybersec/config/settings.py` |
| Decode | When set, `jwt.decode(..., audience=settings.CLERK_AUDIENCE)` and PyJWT verifies `aud`. When empty, previous permissive behavior is kept. |
| Startup | `main.py` lifespan logs a **warning** if `CLERK_AUDIENCE` is unset so the gap is not silent in prod logs. |
| Tests | `tests/apps/api/test_jwt_audience.py` — wrong/missing `aud` → `None`; matching `aud` → user; empty setting still accepts tokens without `aud`. |

### Backward compatibility

Default is `""`. Deployments that have not configured audience verification
continue to work. Enabling verification is opt-in via env + Clerk dashboard.

### Required Clerk dashboard step (to enable)

1. Open [Clerk Dashboard](https://dashboard.clerk.com) → **JWT Templates**.
2. Create a template (or edit an existing one) and add a custom claim:
   - Name: `aud`
   - Value: a stable app identifier, e.g. `"cybersec-toolkit-api"` (string).
3. Set environment variable:
   ```bash
   CLERK_AUDIENCE=cybersec-toolkit-api
   ```
4. On the frontend, request tokens from that template so the claim is present:
   ```js
   await getToken({ template: "cybersec-toolkit-api" })  // template name as configured
   ```

Official docs: [Clerk JWT templates](https://clerk.com/docs/backend-requests/jwt-templates)

### Files touched

- `cybersec/config/settings.py`
- `cybersec/apps/api/deps/__init__.py`
- `cybersec/apps/api/main.py`
- `.env.example`
- `tests/apps/api/test_jwt_audience.py`
- `AUTH_HARDENING_CHANGELOG.md` (this file)
