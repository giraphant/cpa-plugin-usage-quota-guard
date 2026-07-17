package management

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/store"
)

func testStore(t *testing.T) (*store.Store, config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "test.sqlite")
	cfg.Secret.SecretFile = filepath.Join(t.TempDir(), "secret")
	st, err := store.Open(cfg)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, cfg
}

func TestRegisterRoutes(t *testing.T) {
	reg := Register()
	if len(reg.Routes) == 0 || len(reg.Resources) != 1 {
		t.Fatalf("unexpected registration: %+v", reg)
	}
	if reg.Resources[0].Path != "/dashboard" {
		t.Fatalf("resource path = %q", reg.Resources[0].Path)
	}
	for _, route := range reg.Routes {
		if route.Method == http.MethodPost && route.Path == "/plugins/usage-quota-guard/api-keys/reset-usage" {
			return
		}
	}
	t.Fatal("reset usage route is not registered")
}

func TestDashboardHTMLIsInteractive(t *testing.T) {
	st, cfg := testStore(t)
	resp := Handle(pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/resource/plugins/usage-quota-guard/dashboard"}, st, cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := string(resp.Body)
	if !strings.Contains(body, "id=\"management-key\"") || !strings.Contains(body, "loadKeys") || strings.Contains(body, "intentionally unauthenticated") {
		t.Fatalf("dashboard is not interactive enough: %s", body)
	}
	if !strings.Contains(body, "deleteKey") || !strings.Contains(body, "editKey") || !strings.Contains(body, "resetUsage") {
		t.Fatalf("dashboard missing key controls: %s", body)
	}
	if !strings.Contains(body, "localStorage") {
		t.Fatalf("dashboard does not persist management key: %s", body)
	}
	for _, marker := range []string{
		"id=\"summary-total\"",
		"id=\"key-search\"",
		"id=\"status-filter\"",
		"class=\"usage-bar\"",
		"id=\"edit-drawer\"",
		"id=\"toast\"",
		"id=\"keys-empty\"",
		"copyText(",
		"renderSummary(",
		"applyFilters(",
		"rel=\"icon\"",
		"id=\"management-key-form\"",
		"min-width: 0",
		"overflow-wrap: anywhere",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("dashboard missing UX marker %q", marker)
		}
	}
}

func TestAddAPIKeyRedactsResponse(t *testing.T) {
	st, cfg := testStore(t)
	resp := Handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: prefix + "/api-keys", Body: []byte(`{"api_key":"sk-secret-value","display_name":"alice","monthly_token_limit":100,"status":"active"}`)}, st, cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(resp.Body))
	}
	if string(resp.Body) == "" || strings.Contains(string(resp.Body), "sk-secret-value") {
		t.Fatalf("response leaked key: %s", string(resp.Body))
	}
	var item store.APIKey
	if err := json.Unmarshal(resp.Body, &item); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if item.DisplayName != "alice" || item.Fingerprint == "" {
		t.Fatalf("unexpected item: %+v", item)
	}
}

func TestPatchAPIKey(t *testing.T) {
	st, cfg := testStore(t)
	item, err := st.AddAPIKey("sk-secret", "old", nil, store.KeyStatusActive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	limit := int64(42)
	body, _ := json.Marshal(map[string]any{"key_hash": item.KeyHash, "display_name": "new", "monthly_token_limit": limit, "status": store.KeyStatusDisabled})
	resp := Handle(pluginapi.ManagementRequest{Method: http.MethodPatch, Path: prefix + "/api-keys", Body: body}, st, cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", resp.StatusCode, string(resp.Body))
	}
	var got store.APIKey
	_ = json.Unmarshal(resp.Body, &got)
	if got.DisplayName != "new" || got.Status != store.KeyStatusDisabled || got.MonthlyTokenLimit == nil || *got.MonthlyTokenLimit != 42 {
		t.Fatalf("unexpected key: %+v", got)
	}
}

func TestAddDuplicateAPIKeyReturns409(t *testing.T) {
	st, cfg := testStore(t)
	body := []byte(`{"api_key":"sk-dup","display_name":"alice","status":"active"}`)
	if resp := Handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: prefix + "/api-keys", Body: body}, st, cfg); resp.StatusCode != http.StatusOK {
		t.Fatalf("first add status = %d body=%s", resp.StatusCode, string(resp.Body))
	}
	resp := Handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: prefix + "/api-keys", Body: body}, st, cfg)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate add status = %d body=%s, want 409", resp.StatusCode, string(resp.Body))
	}
}

func TestDeleteAPIKeyRoute(t *testing.T) {
	st, cfg := testStore(t)
	item, err := st.AddAPIKey("sk-del", "bob", nil, store.KeyStatusActive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"key_hash": item.KeyHash})
	resp := Handle(pluginapi.ManagementRequest{Method: http.MethodDelete, Path: prefix + "/api-keys", Body: body}, st, cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", resp.StatusCode, string(resp.Body))
	}
	list := Handle(pluginapi.ManagementRequest{Method: http.MethodGet, Path: prefix + "/api-keys"}, st, cfg)
	if strings.Contains(string(list.Body), item.KeyHash) {
		t.Fatalf("deleted key still listed: %s", string(list.Body))
	}
}

func TestResetAPIKeyUsageRoute(t *testing.T) {
	st, cfg := testStore(t)
	now := time.Now()
	limit := int64(5)
	item, err := st.AddAPIKey("sk-reset", "reset", &limit, store.KeyStatusActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordUsage(store.UsageEvent{KeyHash: item.KeyHash, Timestamp: now, OutputTokens: 5}); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"key_hash": item.KeyHash})
	resp := Handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: prefix + "/api-keys/reset-usage", Body: body}, st, cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset status = %d body=%s", resp.StatusCode, string(resp.Body))
	}
	period, err := st.CurrentPeriod(now)
	if err != nil {
		t.Fatal(err)
	}
	used, err := st.MonthlyUsage(item.KeyHash, period)
	if err != nil || used != 0 {
		t.Fatalf("used after reset = %d err=%v", used, err)
	}
	if resp := Handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: prefix + "/api-keys/reset-usage", Body: []byte(`{}`)}, st, cfg); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing key status = %d", resp.StatusCode)
	}
	missing, _ := json.Marshal(map[string]string{"key_hash": "hmac_missing"})
	if resp := Handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: prefix + "/api-keys/reset-usage", Body: missing}, st, cfg); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown key status = %d body=%s", resp.StatusCode, string(resp.Body))
	}
}

func TestBanListAndUnban(t *testing.T) {

	st, cfg := testStore(t)
	now := time.Now()
	ban := store.RouteBan{TargetKey: "auth:a:model:gpt", Reason: "test", BannedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := st.AddOrExtendBan(ban); err != nil {
		t.Fatal(err)
	}
	resp := Handle(pluginapi.ManagementRequest{Method: http.MethodGet, Path: prefix + "/bans", Query: url.Values{"active": []string{"true"}}}, st, cfg)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), ban.TargetKey) {
		t.Fatalf("list response status=%d body=%s", resp.StatusCode, string(resp.Body))
	}
	body, _ := json.Marshal(map[string]string{"target_key": ban.TargetKey})
	resp = Handle(pluginapi.ManagementRequest{Method: http.MethodPost, Path: prefix + "/unban", Body: body}, st, cfg)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unban status=%d body=%s", resp.StatusCode, string(resp.Body))
	}
}
