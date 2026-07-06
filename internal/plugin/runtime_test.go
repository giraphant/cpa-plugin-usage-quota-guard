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
	if !reg.Capabilities.FrontendAuthProvider || !reg.Capabilities.FrontendAuthProviderExclusive || !reg.Capabilities.UsagePlugin || !reg.Capabilities.Scheduler || !reg.Capabilities.ManagementAPI {
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

func TestFrontendAuthRejectsPendingDisabledOverQuota(t *testing.T) {
	st := configureTestRuntime(t)
	now := time.Now()
	limit := int64(1)
	active, _ := st.AddAPIKey("sk-over", "over", &limit, store.KeyStatusActive, now)
	_ = st.RecordUsage(store.UsageEvent{KeyHash: active.KeyHash, Timestamp: now, TotalTokens: 1})
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
