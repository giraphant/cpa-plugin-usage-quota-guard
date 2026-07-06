# CPA Usage Quota Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `cpa-plugin-usage-quota-guard`, a CLIProxyAPI dynamic-library plugin that manages downstream API keys, enforces monthly token quotas, records usage in SQLite, and avoids upstream auth candidates that are temporarily banned after 429/quota failures.

**Architecture:** The plugin uses only official CLIProxyAPI plugin capabilities: `frontend_auth_provider_exclusive`, `usage_plugin`, `scheduler`, and `management_api`. It does not modify CPA source code; it accepts configuration-level intrusion by becoming the downstream key authority. SQLite stores key fingerprints, monthly aggregates, short-lived usage events, and route bans.

**Tech Stack:** Go 1.26, CLIProxyAPI v7 plugin ABI/API, cgo `-buildmode=c-shared`, `github.com/mattn/go-sqlite3`, `gopkg.in/yaml.v3`, standard-library HTML/JSON/crypto packages.

## Global Constraints

- Do not fork or edit `router-for-me/CLIProxyAPI`; use only the official dynamic-library plugin ABI.
- First version declares exactly these capabilities: `frontend_auth_provider_exclusive`, `usage_plugin`, `scheduler`, `management_api`.
- Downstream API keys are never stored in plaintext; store `HMAC-SHA256(plugin_secret, api_key)` and a display fingerprint only.
- Unknown keys default to `pending` and are rejected; they are still auto-registered for later approval in the management UI.
- Quota is monthly token quota; allow the request that crosses quota to finish, then reject subsequent requests at frontend auth.
- Current CPA frontend-auth API cannot return a custom 429 body/status; over-quota denial is performed by returning unauthenticated, so CPA controls the HTTP status. Document this limitation.
- Usage events are retained for 90 days by default; monthly aggregates are retained indefinitely.
- Route health is scheduler-level only: observe 429 in `usage.handle`, persist route bans, then pick a non-banned candidate if possible. Do not write CPA `.cds` cooldown files or call internal `MarkResult`.
- Management HTML resource is unauthenticated in CPA; it must be a static shell only. All data APIs must be authenticated `/v0/management/...` routes.

---

## File Structure

- `cmd/plugin/main.go`: cgo ABI entrypoints and method dispatch.
- `internal/abi/envelope.go`: JSON RPC envelope helpers and plugin registration structs.
- `internal/config/config.go`: YAML config parsing and defaults.
- `internal/auth/extract.go`: inbound API-key extraction and fingerprinting helpers.
- `internal/store/store.go`: SQLite connection, migrations, key/quota/usage/ban operations.
- `internal/usage/convert.go`: converts CPA `pluginapi.UsageRecord` to internal usage event and route-ban observations.
- `internal/routehealth/routehealth.go`: target-key generation and ban-duration rules.
- `internal/management/handler.go`: management registration and JSON/HTML handlers.
- `internal/plugin/runtime.go`: runtime state and implementation of frontend auth, usage, scheduler, and management calls.
- `web/dashboard.html`: static management shell.
- Tests under each internal package.

### Task 1: Module and ABI Scaffold

**Files:**
- Create: `go.mod`, `go.sum`
- Create: `internal/abi/envelope.go`
- Create: `cmd/plugin/main.go`
- Test: `internal/abi/envelope_test.go`

**Interfaces:**
- Produces `abi.OKEnvelope(v any) ([]byte, error)` and `abi.ErrorEnvelope(code, message string) []byte`.
- Produces cgo exports `cliproxy_plugin_init`, `cliproxyPluginCall`, `cliproxyPluginFree`, `cliproxyPluginShutdown`.

- [ ] Write envelope tests verifying OK and error envelopes marshal to CPA-compatible JSON.
- [ ] Implement envelope helpers.
- [ ] Implement cgo entrypoint dispatch that forwards method/request bytes to `plugin.HandleMethod`.
- [ ] Run `go test ./internal/abi` and `go build -buildmode=c-shared -o usage-quota-guard.dylib ./cmd/plugin`.

### Task 2: Configuration Defaults

**Files:**
- Create: `internal/config/config.go`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces `config.Load(raw []byte) (config.Config, error)`.
- Produces `Config.CurrentMonth(t time.Time) string`.

- [ ] Test empty config defaults: SQLite path `./data/usage-quota-guard.sqlite`, secret file `./data/usage-quota-guard.secret`, unknown registration true, unknown access `deny`, detail retention 90, timezone `Asia/Shanghai`, route health enabled.
- [ ] Test YAML overrides for SQLite path, unknown access, retention, timezone, and route-health durations.
- [ ] Implement config structs, defaults, validation, and month calculation.
- [ ] Run `go test ./internal/config`.

### Task 3: API-Key Extraction

**Files:**
- Create: `internal/auth/extract.go`
- Test: `internal/auth/extract_test.go`

**Interfaces:**
- Produces `auth.ExtractAPIKey(headers http.Header, query url.Values, sources []string) (string, string, bool)`.
- Produces `auth.Fingerprint(key string) string`.

- [ ] Test `Authorization: Bearer`, `X-Api-Key`, `X-Goog-Api-Key`, query `key`, and query `auth_token` extraction order.
- [ ] Test fingerprint never returns the full key and keeps suffix visibility.
- [ ] Implement extraction and fingerprinting.
- [ ] Run `go test ./internal/auth`.

### Task 4: SQLite Store

**Files:**
- Create: `internal/store/store.go`
- Test: `internal/store/store_test.go`

**Interfaces:**
- Produces `store.Open(cfg config.Config) (*store.Store, error)`.
- Produces key methods: `AuthenticateKey(rawKey string, now time.Time)`, `AddAPIKey(rawKey, displayName string, limit *int64, status string, now time.Time)`, `ListAPIKeys(month string)`.
- Produces usage methods: `RecordUsage(event UsageEvent)`, `PruneUsageEvents(before time.Time)`.
- Produces ban methods: `AddOrExtendBan(ban RouteBan)`, `ActiveBan(targetKey string, now time.Time)`, `ListRouteBans(activeOnly bool, now time.Time)`, `UnbanRoute(targetKey, reason string, now time.Time)`.

- [ ] Test migrations create all tables and WAL is enabled.
- [ ] Test unknown key registers as `pending` and is denied by default.
- [ ] Test active key with quota below usage is denied.
- [ ] Test usage event increments monthly aggregate.
- [ ] Test active route ban lookup and manual unban.
- [ ] Implement store with HMAC secret file generation, migrations, transactions, and SQLite operations.
- [ ] Run `go test ./internal/store`.

### Task 5: Usage Conversion and Route Health

**Files:**
- Create: `internal/usage/convert.go`
- Create: `internal/routehealth/routehealth.go`
- Test: `internal/usage/convert_test.go`
- Test: `internal/routehealth/routehealth_test.go`

**Interfaces:**
- Produces `usage.FromCPA(record pluginapi.UsageRecord, cfg config.Config) store.UsageEvent`.
- Produces `routehealth.ObservationFromUsage(record pluginapi.UsageRecord, cfg config.Config, now time.Time) (store.RouteBan, bool)`.
- Produces `routehealth.TargetKey(provider, model, authID, authType string) string` and `CandidateTargetKey(candidate pluginapi.SchedulerAuthCandidate, model string) string`.

- [ ] Test total-token fallback when `TotalTokens` is zero.
- [ ] Test Codex 429 with reset headers produces ban until reset.
- [ ] Test generic 429 fallback duration and max clamp.
- [ ] Test scheduler candidate target key uses auth ID when present.
- [ ] Implement conversion and route-health logic.
- [ ] Run `go test ./internal/usage ./internal/routehealth`.

### Task 6: Runtime Capability Methods

**Files:**
- Create: `internal/plugin/runtime.go`
- Test: `internal/plugin/runtime_test.go`

**Interfaces:**
- Produces `plugin.HandleMethod(method string, request []byte) ([]byte, error)`.
- Handles `plugin.register`, `plugin.reconfigure`, `frontend_auth.identifier`, `frontend_auth.authenticate`, `usage.handle`, `scheduler.pick`, `management.register`, `management.handle`, `plugin.shutdown`.

- [ ] Test `plugin.register` advertises all four capabilities and metadata.
- [ ] Test frontend auth returns authenticated with principal equal to `key_hash` for an active key.
- [ ] Test over-quota/pending/disabled keys return unauthenticated.
- [ ] Test `usage.handle` records usage and creates route ban on Codex 429.
- [ ] Test `scheduler.pick` selects the highest-priority non-banned candidate.
- [ ] Implement runtime state, method dispatch, lifecycle reconfiguration, and shutdown cleanup.
- [ ] Run `go test ./internal/plugin`.

### Task 7: Management API and Static Dashboard

**Files:**
- Create: `internal/management/handler.go`
- Create: `web/dashboard.html`
- Test: `internal/management/handler_test.go`

**Interfaces:**
- Produces `management.Register() pluginapi.ManagementRegistrationResponse`.
- Produces `management.Handle(req pluginapi.ManagementRequest, st *store.Store, cfg config.Config) pluginapi.ManagementResponse`.

- [ ] Test registration exposes authenticated routes and one static resource route.
- [ ] Test `POST /plugins/usage-quota-guard/api-keys` adds a key and response is redacted.
- [ ] Test `PATCH /plugins/usage-quota-guard/api-keys` updates display name, status, and limit.
- [ ] Test ban list and unban endpoints.
- [ ] Implement JSON handlers and static dashboard shell.
- [ ] Run `go test ./internal/management`.

### Task 8: Documentation and End-to-End Build

**Files:**
- Create: `README.md`
- Create: `docs/superpowers/specs/2026-07-06-usage-quota-guard-design.md`
- Modify: all code as needed from integration failures.

**Interfaces:**
- Produces `usage-quota-guard.dylib` on macOS with `go build -buildmode=c-shared -o usage-quota-guard.dylib ./cmd/plugin`.

- [ ] Write README with install, config, key-management API, CPA limitation about auth-denial status, and build commands.
- [ ] Write final design spec summarizing the actual CPA-grounded design.
- [ ] Run `go test ./...`.
- [ ] Run `go build -buildmode=c-shared -o usage-quota-guard.dylib ./cmd/plugin`.
- [ ] Run `git status --short` and report changed files.

## Self-Review

- Spec coverage: downstream key management, monthly quotas, usage events, monthly aggregate, route bans, scheduler-level 429 avoidance, management UI/API, no CPA fork are covered by Tasks 2-8.
- Placeholder scan: no TBD/TODO/fill-later placeholders are present.
- Type consistency: task interfaces consistently use `config.Config`, `store.Store`, `store.UsageEvent`, `store.RouteBan`, and CPA `pluginapi` request/response types.
