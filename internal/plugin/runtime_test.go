package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"gopkg.in/yaml.v3"

	guardabi "github.com/giraphant/cpa-plugin-usage-quota-guard/internal/abi"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/store"
)

func configureTestRuntime(t *testing.T) *store.Store {
	t.Helper()
	_, st := configureTestRuntimeWithRegistration(t)
	return st
}

func configureTestRuntimeWithRegistration(t *testing.T) ([]byte, *store.Store) {
	t.Helper()
	ResetForTests()
	cfg := map[string]any{
		"storage": map[string]any{"sqlite_path": filepath.Join(t.TempDir(), "test.sqlite")},
		"secret":  map[string]any{"secret_file": filepath.Join(t.TempDir(), "secret")},
		"usage":   map[string]any{"timezone": "UTC"},
	}
	yamlBytes, _ := yaml.Marshal(cfg)
	request, _ := json.Marshal(guardabi.LifecycleRequest{ConfigYAML: yamlBytes, SchemaVersion: pluginabi.SchemaVersion})
	raw, err := HandleMethod(pluginabi.MethodPluginRegister, request)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	st, err := StoreForTests()
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	return raw, st
}

func unwrap[T any](t *testing.T, raw []byte) T {
	t.Helper()
	var env guardabi.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal env: %v", err)
	}
	if !env.OK {
		t.Fatalf("envelope error: %+v", env.Error)
	}
	var out T
	if err := json.Unmarshal(env.Result, &out); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return out
}

func TestRegisterCapabilities(t *testing.T) {
	raw, _ := configureTestRuntimeWithRegistration(t)
	reg := unwrap[guardabi.Registration](t, raw)
	if !reg.Capabilities.FrontendAuthProvider || !reg.Capabilities.FrontendAuthProviderExclusive || !reg.Capabilities.ResponseInterceptor || !reg.Capabilities.StreamChunkInterceptor || !reg.Capabilities.UsagePlugin || !reg.Capabilities.Scheduler || !reg.Capabilities.ManagementAPI {
		t.Fatalf("missing capabilities: %+v", reg.Capabilities)
	}
}

func TestFrontendAuthActiveKey(t *testing.T) {
	st := configureTestRuntime(t)
	key, err := st.AddAPIKey("sk-active", "alice", nil, store.KeyStatusActive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := pluginapi.FrontendAuthRequest{Headers: http.Header{"Authorization": []string{"Bearer sk-active"}}}
	body, _ := json.Marshal(req)
	raw, err := HandleMethod(pluginabi.MethodFrontendAuthAuthenticate, body)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	resp := unwrap[pluginapi.FrontendAuthResponse](t, raw)
	if !resp.Authenticated || resp.Principal != key.KeyHash {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestFrontendAuthBypassesModelListWithoutAPIKey(t *testing.T) {
	configureTestRuntime(t)
	req := pluginapi.FrontendAuthRequest{Method: http.MethodGet, Path: "/v1/models"}
	body, _ := json.Marshal(req)
	raw, err := HandleMethod(pluginabi.MethodFrontendAuthAuthenticate, body)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	resp := unwrap[pluginapi.FrontendAuthResponse](t, raw)
	if !resp.Authenticated {
		t.Fatalf("model list request was not bypassed: %+v", resp)
	}
	if resp.Metadata["bypass"] != "models" {
		t.Fatalf("metadata = %+v", resp.Metadata)
	}
}

func TestFrontendAuthRejectsPendingDisabledOverQuota(t *testing.T) {
	st := configureTestRuntime(t)
	now := time.Now()
	limit := int64(1)
	active, _ := st.AddAPIKey("sk-over", "over", &limit, store.KeyStatusActive, now)
	_ = st.RecordUsage(store.UsageEvent{KeyHash: active.KeyHash, Timestamp: now, OutputTokens: 1, TotalTokens: 1})
	_, _ = st.AddAPIKey("sk-disabled", "disabled", nil, store.KeyStatusDisabled, now)
	for _, rawKey := range []string{"sk-unknown", "sk-disabled", "sk-over"} {
		req := pluginapi.FrontendAuthRequest{Headers: http.Header{"Authorization": []string{"Bearer " + rawKey}}}
		body, _ := json.Marshal(req)
		raw, err := HandleMethod(pluginabi.MethodFrontendAuthAuthenticate, body)
		if err != nil {
			t.Fatalf("auth %s: %v", rawKey, err)
		}
		resp := unwrap[pluginapi.FrontendAuthResponse](t, raw)
		if resp.Authenticated {
			t.Fatalf("%s authenticated unexpectedly", rawKey)
		}
	}
}

func TestUsageHandleRecordsAndBans(t *testing.T) {
	st := configureTestRuntime(t)
	now := time.Now()
	key, _ := st.AddAPIKey("sk-use", "use", nil, store.KeyStatusActive, now)
	record := pluginapi.UsageRecord{APIKey: key.KeyHash, Provider: "codex", Model: "gpt-5", AuthID: "auth-a", RequestedAt: now, Failed: true, Failure: pluginapi.UsageFailure{StatusCode: 429}, Detail: pluginapi.UsageDetail{TotalTokens: 9}}
	body, _ := json.Marshal(record)
	if _, err := HandleMethod(pluginabi.MethodUsageHandle, body); err != nil {
		t.Fatalf("usage: %v", err)
	}
	used, _ := st.MonthlyUsage(key.KeyHash, now.UTC().Format("2006-01"))
	if used != 9 {
		t.Fatalf("used = %d", used)
	}
	_, active, err := st.ActiveBan("auth:auth-a:model:gpt-5", time.Now())
	if err != nil || !active {
		t.Fatalf("ban active=%v err=%v", active, err)
	}
}

func TestResponseInterceptorsRecordUsageAndDeduplicateUsageCallback(t *testing.T) {
	st := configureTestRuntime(t)
	now := time.Now()
	key, err := st.AddAPIKey("sk-intercept", "intercept", nil, store.KeyStatusActive, now)
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"X-Request-Id": []string{"req-intercept"}}
	response := pluginapi.ResponseInterceptRequest{
		Model:           "gpt-5",
		RequestHeaders:  http.Header{"Authorization": []string{"Bearer sk-intercept"}},
		ResponseHeaders: headers,
		Body:            []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"prompt_tokens_details":{"cached_tokens":3}}}`),
		StatusCode:      http.StatusOK,
	}
	body, _ := json.Marshal(response)
	if _, err := HandleMethod(pluginabi.MethodResponseInterceptAfter, body); err != nil {
		t.Fatalf("response interceptor: %v", err)
	}
	usageRecord := pluginapi.UsageRecord{
		APIKey:          key.KeyHash,
		Provider:        "codex",
		Model:           "gpt-5",
		RequestedAt:     now,
		ResponseHeaders: headers,
		Detail:          pluginapi.UsageDetail{InputTokens: 10, OutputTokens: 5, CachedTokens: 3, TotalTokens: 15},
	}
	body, _ = json.Marshal(usageRecord)
	if _, err := HandleMethod(pluginabi.MethodUsageHandle, body); err != nil {
		t.Fatalf("usage callback: %v", err)
	}
	period := config.Default().CurrentPeriod(now)
	totals, err := st.PeriodTotals(key.KeyHash, period)
	if err != nil || totals.Input != 7 || totals.CacheRead != 3 || totals.Output != 5 || totals.Total != 15 {
		t.Fatalf("deduplicated totals = %+v err=%v", totals, err)
	}

	streamHeaders := http.Header{"X-Request-Id": []string{"req-stream"}}
	streamStart := pluginapi.StreamChunkInterceptRequest{
		Model:           "claude-opus",
		RequestHeaders:  http.Header{"Authorization": []string{"Bearer sk-intercept"}},
		ResponseHeaders: streamHeaders,
		Body:            []byte("data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":8,\"cache_read_input_tokens\":2,\"cache_creation_input_tokens\":1}}}\n\n"),
		ChunkIndex:      0,
	}
	body, _ = json.Marshal(streamStart)
	if _, err := HandleMethod(pluginabi.MethodResponseInterceptStreamChunk, body); err != nil {
		t.Fatalf("stream start interceptor: %v", err)
	}
	stateKey := "req-stream\x00" + key.KeyHash
	global.streamMu.Lock()
	state, ok := global.streamUsage[stateKey]
	if ok {
		state.updatedAt = time.Now().Add(-interceptedStreamStateTTL - time.Minute)
		global.streamUsage[stateKey] = state
	}
	global.streamMu.Unlock()
	if !ok {
		t.Fatal("stream usage state was not retained")
	}
	stream := pluginapi.StreamChunkInterceptRequest{
		Model:           "claude-opus",
		RequestHeaders:  streamStart.RequestHeaders,
		ResponseHeaders: streamHeaders,
		Body:            []byte("data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n"),
		ChunkIndex:      1,
	}
	body, _ = json.Marshal(stream)
	if _, err := HandleMethod(pluginabi.MethodResponseInterceptStreamChunk, body); err != nil {
		t.Fatalf("stream terminal interceptor: %v", err)
	}
	totals, err = st.PeriodTotals(key.KeyHash, period)
	if err != nil || totals.Input != 15 || totals.CacheRead != 5 || totals.CacheWrite != 1 || totals.Output != 8 || totals.Total != 29 {
		t.Fatalf("stream totals = %+v err=%v", totals, err)
	}
	var events int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM usage_events WHERE key_hash = ?`, key.KeyHash).Scan(&events); err != nil || events != 2 {
		t.Fatalf("events=%d err=%v", events, err)
	}
}

func TestStreamInterceptorObservesResetWithoutAccountingID(t *testing.T) {
	cfg := config.Default()
	cfg.Quota.Period = config.QuotaPeriodWeekly
	cfg.Usage.Timezone = "UTC"
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "test.sqlite")
	cfg.Secret.SecretFile = filepath.Join(t.TempDir(), "secret")
	st, err := store.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runtime := &Runtime{cfg: cfg, store: st}
	boundary := time.Now().UTC().Add(time.Hour)
	req := pluginapi.StreamChunkInterceptRequest{ResponseHeaders: http.Header{
		"X-Codex-Secondary-Reset-At": []string{boundary.Format(time.RFC3339Nano)},
	}}
	body, _ := json.Marshal(req)
	if _, err := runtime.interceptStreamChunk(body); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err := st.DB().QueryRow(`SELECT next_reset_at FROM quota_cycle_state WHERE scope = 'codex-weekly'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	got, err := time.Parse(time.RFC3339Nano, stored)
	if err != nil || !got.Equal(boundary) {
		t.Fatalf("stored reset = %q, want %s, err=%v", stored, boundary.Format(time.RFC3339Nano), err)
	}
}

func TestUsageHandleRecordsFirstRequestAfterWeeklyReset(t *testing.T) {
	cfg := config.Default()
	cfg.Quota.Period = config.QuotaPeriodWeekly
	cfg.Usage.Timezone = "UTC"
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "test.sqlite")
	cfg.Secret.SecretFile = filepath.Join(t.TempDir(), "secret")
	st, err := store.Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	runtime := &Runtime{cfg: cfg, store: st}

	now := time.Now().UTC()
	setupTime := now.Add(-2 * time.Hour)
	oldBoundary := now.Add(-time.Minute)
	if err := st.ObserveUpstreamWeeklyReset(oldBoundary, setupTime); err != nil {
		t.Fatal(err)
	}
	key, err := st.AddAPIKey("sk-weekly", "weekly", nil, store.KeyStatusActive, setupTime)
	if err != nil {
		t.Fatal(err)
	}
	oldPeriod, _ := st.CurrentPeriod(setupTime)
	if err := st.RecordUsage(store.UsageEvent{KeyHash: key.KeyHash, Timestamp: setupTime, OutputTokens: 5}); err != nil {
		t.Fatal(err)
	}

	nextBoundary := now.Add(7 * 24 * time.Hour)
	record := pluginapi.UsageRecord{
		APIKey:      key.KeyHash,
		Provider:    "codex",
		RequestedAt: now,
		ResponseHeaders: http.Header{
			"X-Codex-Secondary-Reset-At": []string{nextBoundary.Format(time.RFC3339)},
		},
		Detail: pluginapi.UsageDetail{OutputTokens: 9, TotalTokens: 9},
	}
	body, _ := json.Marshal(record)
	if _, err := runtime.handleUsage(body); err != nil {
		t.Fatalf("usage: %v", err)
	}
	period, err := st.CurrentPeriod(now)
	if err != nil {
		t.Fatal(err)
	}
	if period == oldPeriod {
		t.Fatalf("period did not advance: %q", period)
	}
	totals, err := st.PeriodTotals(key.KeyHash, period)
	if err != nil || totals.Output != 9 {
		t.Fatalf("new period totals = %+v err=%v", totals, err)
	}
}

func TestSchedulerPickAvoidsBannedCandidate(t *testing.T) {
	st := configureTestRuntime(t)
	now := time.Now()
	_ = st.AddOrExtendBan(store.RouteBan{TargetKey: "auth:a:model:gpt-5", Reason: "test", BannedAt: now, ExpiresAt: now.Add(time.Hour)})
	req := pluginapi.SchedulerPickRequest{Model: "gpt-5", Candidates: []pluginapi.SchedulerAuthCandidate{{ID: "a", Provider: "codex", Priority: 100}, {ID: "b", Provider: "codex", Priority: 50}}}
	body, _ := json.Marshal(req)
	raw, err := HandleMethod(pluginabi.MethodSchedulerPick, body)
	if err != nil {
		t.Fatalf("pick: %v", err)
	}
	resp := unwrap[pluginapi.SchedulerPickResponse](t, raw)
	if !resp.Handled || resp.AuthID != "b" {
		t.Fatalf("unexpected pick: %+v", resp)
	}
}
