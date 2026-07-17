---
name: verify
description: Runtime verification recipe for the usage-quota-guard CPA plugin.
---

# Verify usage-quota-guard

1. Build the plugin:

   ```sh
   go build -buildmode=c-shared -o "$TMPDIR/plugins/usage-quota-guard.dylib" ./cmd/plugin
   ```

2. Run an isolated, unmodified CPA server with plugin support, a temporary SQLite path/secret, exclusive frontend auth, and a fake Codex upstream. Have the fake upstream return unique request IDs, token usage, and `x-codex-secondary-reset-at` for both JSON and SSE responses.

3. Add downstream keys through the live Dashboard, authenticate through a supported header source, then drive these flows through CPA HTTP endpoints:
   - successful non-stream and stream responses each create exactly one usage event and aggregate once;
   - one key reaches its output-token limit and the next request is rejected;
   - Dashboard **重置用量** clears only the active aggregate, preserves `usage_events`, and restores access;
   - two exhausted keys recover after the persisted secondary reset boundary, with old aggregate rows retained;
   - reset API `{}` returns 400 and an unknown `key_hash` returns 404.

4. Capture the HTTP responses, SQLite rows, and a Dashboard screenshot. When diagnosing accounting, state whether the synchronous response interceptor or asynchronous UsagePlugin callback inserted the event.

## CPA host gotcha

CPA v7.2.50 through v7.2.83 may invoke queued dynamic-plugin usage callbacks with an already canceled request context. Stock builds still account for successful responses through the synchronous response and stream-chunk interceptors when an upstream request ID is present. Failed responses and 429-derived route bans still depend on the asynchronous UsagePlugin callback and can be missed on affected hosts.
