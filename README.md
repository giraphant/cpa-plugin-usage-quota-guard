# CPA Usage Quota Guard

`cpa-plugin-usage-quota-guard` is a native CLIProxyAPI/CPA dynamic-library plugin for personal or small-team CPA deployments.

It provides two guardrails in one plugin:

1. **Downstream usage quota** — the plugin becomes the exclusive frontend auth provider, manages downstream API keys, records token usage, and blocks keys that have already consumed their monthly token quota.
2. **Upstream route health** — the plugin observes completed usage records, records temporary route bans after 429/quota failures, and uses the scheduler capability to pick a non-banned auth candidate when possible.

The plugin uses only CPA's official plugin ABI. It does not patch or fork `router-for-me/CLIProxyAPI`.

## Quota period

`quota.period` selects the accounting window for `monthly_token_limit`:

- `monthly` (default): `YYYY-MM`, e.g. `2026-07`.
- `weekly`: ISO week `YYYY-Www`, e.g. `2026-W27` (Monday start).

The limit field is still named `monthly_token_limit` for backward compatibility, but its meaning is "per configured period". Switching period does not migrate historical rows; usage already recorded under the old period key simply ages out.

## Quota metric

`quota.metric` selects which token stream the limit is compared against:

- `output_tokens` (default): only output tokens count. Output maps almost linearly to cost, while cached input is cheap, so this is the fairest proxy for spend when splitting one upstream key between several downstream users.
- `total_tokens`: input + output + reasoning (legacy behavior).

The dashboard splits usage into Input / Cached / Output columns regardless of metric, so you can see what each downstream key actually consumes. The `Limit` column header shows the active metric.

## Current CPA limitation

CPA's `frontend_auth_provider` API returns only `Authenticated`/`Principal`/`Metadata`. It cannot return a custom HTTP status or JSON error body. Therefore over-quota, pending, disabled, and unknown keys are rejected by returning `Authenticated: false`; CPA then controls the downstream HTTP status/body for auth failure.

The plugin still stores `quota.over_quota_status` and `quota.over_quota_message` in config for future compatibility, but CPA v7.2.50 does not expose a way for a frontend-auth plugin to emit that custom 429 directly.

## Build

```bash
go test ./...
go build -buildmode=c-shared -o usage-quota-guard-v0.1.7.dylib ./cmd/plugin
```

On Linux, build a `.so` instead:

```bash
go build -buildmode=c-shared -o usage-quota-guard-v0.1.7.so ./cmd/plugin
```

CPA plugin filenames should follow CPA's versioned convention, for example `usage-quota-guard-v0.1.7.dylib`.

## Install through CPA plugin store

CPA's management UI can install third-party plugins from `plugins.store-sources`. After this repo is pushed to GitHub, add this registry URL in CPA:

```text
https://raw.githubusercontent.com/giraphant/cpa-plugin-usage-quota-guard/main/dist/plugin-store/registry.json
```

The checked-in `dist/plugin-store/registry.json` uses CPA's `github-release` install mode. Release assets are built by GitHub Actions for:

- `linux/amd64`
- `linux/arm64`
- `darwin/arm64`

CPA will download the matching release asset named like:

```text
usage-quota-guard_0.1.7_linux_amd64.zip
```

and verify it with the release `checksums.txt` file.

To publish a new version, push a tag:

```bash
git tag v0.1.7
git push origin v0.1.7
```

## CPA config example

```yaml
plugins:
  enabled: true
  configs:
    usage-quota-guard:
      enabled: true
      priority: 100

      storage:
        sqlite_path: "./data/usage-quota-guard.sqlite"

      secret:
        secret_file: "./data/usage-quota-guard.secret"
        secret_env: "USAGE_QUOTA_GUARD_SECRET"

      frontend_auth:
        exclusive: true
        accepted_sources:
          - authorization_bearer
          - x_api_key
          - x_goog_api_key
          - query_key
          - query_auth_token

      unknown_key_registration: true
      unknown_key_access: "deny"
      default_monthly_token_limit: null

      usage:
        detail_retention_days: 90
        timezone: "Asia/Shanghai"

      quota:
        period: "monthly"   # "monthly" (YYYY-MM) or "weekly" (ISO week YYYY-Www)
        metric: "output_tokens"  # "output_tokens" (default) or "total_tokens"
        over_quota_status: 429
        over_quota_message: "Token quota exceeded for this API key."

      route_health:
        enabled: true
        mode: "plugin_scheduler"
        rules:
          - name: "codex_429"
            provider: "codex"
            status_codes: [429]
            duration_strategy: "codex_reset_headers"
            fallback_duration: "5h"
            min_duration: "5m"
            max_duration: "24h"
          - name: "generic_429"
            status_codes: [429]
            duration_strategy: "retry_after_header"
            fallback_duration: "10m"
            min_duration: "1m"
            max_duration: "1h"
```

## Downstream key lifecycle

The plugin never stores plaintext API keys. When a key is added or seen, it stores:

- `key_hash = HMAC-SHA256(plugin_secret, raw_api_key)`
- a short display fingerprint such as `sk-...abcd`
- display name, status, and monthly quota

Unknown keys default to `pending` and are rejected. This lets the management page show fingerprints for attempted unknown keys without accidentally allowing arbitrary callers.

### Add a downstream key

```bash
curl -X POST http://127.0.0.1:8317/v0/management/plugins/usage-quota-guard/api-keys \
  -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "sk-your-downstream-key",
    "display_name": "alice",
    "monthly_token_limit": 5000000,
    "status": "active"
  }'
```

The response is redacted and does not include the plaintext key.

### List keys

```bash
curl http://127.0.0.1:8317/v0/management/plugins/usage-quota-guard/api-keys \
  -H "X-Management-Key: $CPA_MANAGEMENT_KEY"
```

### Update a key

```bash
curl -X PATCH http://127.0.0.1:8317/v0/management/plugins/usage-quota-guard/api-keys \
  -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "key_hash": "hmac_...",
    "display_name": "alice-prod",
    "monthly_token_limit": 10000000,
    "status": "active"
  }'
```

### Delete a key

Adding the same API key twice is rejected with `409 api_key_already_exists`; use edit instead. To remove a key entirely (for example to clean up duplicates left over from before the secret was persisted):

```bash
curl -X DELETE http://127.0.0.1:8317/v0/management/plugins/usage-quota-guard/api-keys \
  -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"key_hash": "hmac_..."}'
```

The key's historical usage rows are retained; only the `api_keys` entry is removed.

## Route health APIs

List active route bans:

```bash
curl 'http://127.0.0.1:8317/v0/management/plugins/usage-quota-guard/bans?active=true' \
  -H "X-Management-Key: $CPA_MANAGEMENT_KEY"
```

Manual unban:

```bash
curl -X POST http://127.0.0.1:8317/v0/management/plugins/usage-quota-guard/unban \
  -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target_key":"auth:codex-account:model:gpt-5","reason":"manual"}'
```

## Management page

The plugin registers a static resource page at:

```text
/v0/resource/plugins/usage-quota-guard/dashboard
```

CPA serves plugin resource pages without management auth, so the page is only a shell. It fetches data from authenticated `/v0/management/plugins/usage-quota-guard/*` APIs.

The dashboard is a zero-dependency embedded console with summary cards, search/status filters, quota usage bars, side-drawer editing, copy helpers, empty/loading states, and active route-ban controls.

## Data retention

- `usage_events`: 90 days by default.
- `monthly_usage`: retained indefinitely.
- `route_bans`: retained as history unless manually removed.
- `api_keys`: retained until deleted via the management API or dashboard.

## Safety notes

Back up both the SQLite database and `secret_file`. If the HMAC secret is lost, existing `key_hash` values cannot be recomputed from incoming keys.
