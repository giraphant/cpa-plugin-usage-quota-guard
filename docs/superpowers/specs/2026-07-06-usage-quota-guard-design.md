# CPA Usage Quota Guard Design

## Goal

Build a native CLIProxyAPI/CPA plugin that manages downstream API keys, tracks per-key token usage, enforces monthly token quotas, and reduces repeated upstream 429 hits by avoiding temporarily banned route candidates.

## CPA-grounded constraints

The plugin uses only CLIProxyAPI v7 dynamic plugin capabilities:

- `frontend_auth_provider_exclusive`
- `usage_plugin`
- `scheduler`
- `management_api`

It does not modify CPA source code, call internal `MarkResult`, write `.cds` cooldown files, or act as an upstream executor.

CPA v7.2.50 frontend auth cannot return custom HTTP status/errors. Quota denial therefore returns `Authenticated: false`, and CPA decides the downstream auth failure status/body.

## Architecture

### Frontend auth and quota gate

The plugin is the exclusive frontend auth provider. It extracts downstream keys from accepted sources (`Authorization: Bearer`, `X-Api-Key`, `X-Goog-Api-Key`, `key`, `auth_token`), computes `HMAC-SHA256(plugin_secret, raw_key)`, and authenticates against SQLite.

Unknown keys are auto-registered as `pending` and rejected by default. Active keys pass only if their current-month `monthly_usage.total_tokens` is below `monthly_token_limit`, or if their limit is `NULL`.

Successful frontend auth returns `Principal = key_hash`, so CPA usage records contain the hash rather than the raw key.

### Usage accounting

`usage.handle` receives completed CPA usage records, converts token counters into a local `usage_events` row, and upserts `monthly_usage`.

The request that crosses quota is allowed to finish because true token usage is only known after completion. Subsequent requests are rejected by frontend auth.

### Route health

`usage.handle` also observes failed upstream records. If a route-health rule matches, such as Codex 429, the plugin writes a `route_bans` row with an expiry.

Codex rules prefer reset headers (`x-codex-primary-reset-at`, `x-codex-secondary-reset-at`) when available, then fall back to configured durations with min/max clamps.

`scheduler.pick` sorts candidates by priority and ID, skips active bans, and returns the first usable candidate. If all candidates are banned or unusable, it returns `Handled: false` and lets CPA decide fallback/error behavior.

### Management API and page

The plugin registers authenticated JSON routes under `/v0/management/plugins/usage-quota-guard/*` for key management and route-ban management.

It also registers `/v0/resource/plugins/usage-quota-guard/dashboard` as a static shell. CPA resource routes are unauthenticated, so sensitive data is fetched only from authenticated management APIs.

## Data model

- `api_keys`: key hash, fingerprint, display name, monthly token limit, status, first/last seen.
- `usage_events`: short-retention request-level usage details.
- `monthly_usage`: durable per-key monthly aggregates.
- `route_bans`: active and historical upstream target bans.
- `schema_migrations`: schema bookkeeping placeholder for future migrations.

## Security model

The plugin does not store plaintext downstream API keys. Plaintext keys are only accepted transiently in management add-key calls and inbound frontend auth requests.

The SQLite database is useful only together with the HMAC secret. Both must be backed up; losing the secret prevents matching existing hashes.

## Limitations

- Frontend-auth denials cannot currently force a custom 429 response in CPA v7.2.50.
- Scheduler plugins cannot return a filtered candidate list or set CPA internal cooldown. This plugin picks a non-banned candidate when possible and otherwise defers to CPA.
- Management page is intentionally simple; full UI polish can be added without changing core data structures.
