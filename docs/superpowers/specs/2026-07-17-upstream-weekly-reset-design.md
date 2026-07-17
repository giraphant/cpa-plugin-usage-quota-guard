# Upstream-Aligned Weekly Usage Reset Design

## Goal

Add two quota reset capabilities:

1. An administrator can reset one downstream API key's usage for the active quota period.
2. When `quota.period: weekly`, local quota accounting follows the Codex upstream weekly reset boundary and resets all downstream keys together.

Historical request events remain intact in both cases.

## Decisions

- Manual reset scope: one downstream API key.
- Automatic reset scope: every downstream API key sharing the upstream account.
- Upstream weekly signal: Codex `x-codex-secondary-reset-at`; the primary header represents the shorter window and is not used.
- Automatic reset changes the active aggregate period instead of deleting historical aggregates.
- Before the first valid upstream header is observed, weekly accounting retains the existing ISO-week behavior.
- No upstream-account mapping is added. The plugin continues to model one shared upstream quota cycle.

## Existing Constraints

Quota enforcement and dashboard totals read `monthly_usage` by a string period key. Weekly mode currently uses an ISO-week key from `config.Config.CurrentPeriod`. Usage details are separately retained in `usage_events`.

A reset must not depend only on seeing a response after the upstream boundary: if every downstream key is already over quota, frontend authentication prevents any request from reaching the upstream service. The next boundary therefore has to be persisted and applied during authentication.

## Storage

Add a singleton state table:

```sql
CREATE TABLE IF NOT EXISTS quota_cycle_state (
  scope TEXT PRIMARY KEY,
  period TEXT NOT NULL,
  next_reset_at TEXT NULL,
  previous_period TEXT NULL,
  period_started_at TEXT NULL,
  updated_at TEXT NOT NULL
);
```

The only initial scope is `codex-weekly`.

- `period` is the active `monthly_usage.month` value.
- `next_reset_at` is the next known upstream weekly boundary in UTC.
- `previous_period` and `period_started_at` retain one prior cycle so delayed asynchronous usage callbacks are attributed by their request timestamp instead of consuming the new quota.
- Absence of a state row means no upstream boundary has been learned; the existing ISO-week period is used.

The store serializes reads and transitions of this singleton state with one mutex. A per-account lock is unnecessary until multiple independent upstream quota accounts are represented.

## Active Period Resolution

The Store becomes the single authority for the effective quota period.

- Monthly mode returns the existing configured monthly period unchanged.
- Weekly mode with no `codex-weekly` state row returns the existing ISO-week period.
- Weekly mode with state returns its persisted `period`.
- If `next_reset_at` is due, the Store atomically moves the old key to `previous_period`, records the boundary in `period_started_at`, changes `period` to a key derived from that boundary, and clears `next_reset_at`. The old aggregate rows remain historical and all downstream keys naturally read zero in the new period.
- Clearing `next_reset_at` prevents repeated transitions before a later upstream response supplies the following boundary.
- A usage event whose request timestamp predates `period_started_at` resolves to `previous_period`; this preserves correct attribution for callbacks delivered after the boundary.

Authentication, usage recording, management listing, and manual reset all resolve the period through the Store. `RecordUsage` assigns the effective period itself so callers cannot record an aggregate under a stale ISO-week key.

## Observing the Upstream Boundary

Before recording a Codex usage event in weekly mode, both the queued usage handler and synchronous response interceptors read `x-codex-secondary-reset-at` through the same reset timestamp parser.

- Missing, invalid, or non-future timestamps are ignored.
- First observation creates state using the current ISO-week period and stores the next boundary. It does not reset existing usage.
- Repeating the same boundary is a no-op.
- An older boundary is ignored.
- A later boundary updates `next_reset_at`.
- If a later boundary proves that the previously stored cycle has already rolled over before local time-based resolution applied it, the Store advances the period first, then stores the new boundary.
- If authentication already advanced the period and cleared the old boundary, the next response only stores the new boundary and does not reset twice.

Boundary observation runs before the triggering usage is recorded, so the first request of a new upstream cycle is counted in the new local cycle.

## Stock CPA Usage Delivery

CPA v7.2.50 through v7.2.83 can invoke the queued dynamic-plugin usage callback after its request context has been canceled. To keep successful accounting functional on an unmodified host, the plugin also registers synchronous response and stream-chunk interceptors.

- Interceptors leave response bodies and headers unchanged.
- They recover the downstream key from the original request headers, parse OpenAI/Codex, Claude, and Gemini usage from JSON or terminal SSE chunks, and observe the secondary reset header inline.
- Streaming accounting keeps only usage-bearing chunks in per-request plugin state until a terminal usage chunk arrives, preserving split Claude input/output and cache counters even after the host's bounded history has evicted early chunks.
- Query-parameter credential sources are rejected during configuration because CPA does not expose query parameters to response interceptors.
- A response must include an upstream request ID; otherwise fallback recording is skipped because it cannot be safely deduplicated.
- `RecordUsage` deduplicates by `(request_id, key_hash)`, allowing either the synchronous interceptor or asynchronous callback to arrive first without double counting. The same request ID may still be recorded for different downstream keys.
- Response interceptors only see successful responses. Failed requests and 429-derived route bans remain dependent on the asynchronous usage callback.
- The synchronous path timestamps usage when the response is intercepted because the ABI does not expose the original request start time there. A request that begins before and completes after a reset boundary can therefore be attributed to the new period; the asynchronous callback retains the more precise request-time attribution when it arrives first.

## Manual Reset

Register a management route:

```text
POST /v0/management/plugins/usage-quota-guard/api-keys/reset-usage
Content-Type: application/json

{"key_hash":"hmac_..."}
```

The Store verifies that the API key exists, resolves the active period, and deletes only that key's matching `monthly_usage` row.

- Existing key, including one already at zero: `200 {"ok":true}`.
- Invalid JSON or missing `key_hash`: `400`.
- Unknown key: `404 api_key_not_found`.
- Storage failure: `500`.

`usage_events` and aggregates from inactive periods are not deleted.

## Dashboard

Each downstream key row receives a `Reset usage` action. It requires confirmation, calls the management route, shows the existing toast feedback, and reloads the key list after success.

No global manual reset control is added.

## Error Handling and Fallbacks

- Upstream header problems never fail an otherwise valid usage event; the plugin continues with its current or ISO fallback period.
- Persistent storage errors while resolving or transitioning a known cycle are returned, because silently writing usage to the wrong period would corrupt quota enforcement.
- Timestamp comparisons use absolute UTC times; the configured usage timezone remains relevant only to ISO fallback periods.
- Monthly quota behavior is unchanged.

## Tests

Add the smallest tests that cover the state transitions and public behavior:

1. Store manual reset returns usage to zero, restores authentication, and retains the request-level event.
2. First secondary reset header initializes state without resetting current usage.
3. Reaching the stored boundary changes the active period for all keys exactly once.
4. A delayed callback whose request began before the boundary remains in the previous period.
5. State and the due transition survive reopening the SQLite database.
6. Runtime observes the boundary before recording usage, preserving the first request in the new cycle.
7. Management route registration and success, missing-key, and unknown-key responses.
8. Dashboard HTML contains and dispatches the reset action.
9. Successful JSON and terminal SSE response interception records usage, while a later duplicate usage callback does not increment it again.
10. Existing monthly and weekly fallback tests continue to pass.

Run `go test ./...` and build the dynamic library. Before preparing the PR, run the local Codex CLI against the complete uncommitted diff, fix confirmed findings, and rerun tests.

## Out of Scope

- Multiple independently resetting upstream accounts.
- Primary/short-window quota synchronization.
- Deleting or rewriting request history.
- A global manual reset button.
- Background polling of the upstream service.
