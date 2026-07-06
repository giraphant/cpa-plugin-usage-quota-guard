package management

import (
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/store"
)

//go:embed dashboard.html
var dashboardHTML []byte

const prefix = "/v0/management/plugins/usage-quota-guard"

func Register() pluginapi.ManagementRegistrationResponse {
	return pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{Method: http.MethodGet, Path: "/plugins/usage-quota-guard/api-keys"},
			{Method: http.MethodPost, Path: "/plugins/usage-quota-guard/api-keys"},
			{Method: http.MethodPatch, Path: "/plugins/usage-quota-guard/api-keys"},
			{Method: http.MethodDelete, Path: "/plugins/usage-quota-guard/api-keys"},
			{Method: http.MethodGet, Path: "/plugins/usage-quota-guard/bans"},
			{Method: http.MethodPost, Path: "/plugins/usage-quota-guard/unban"},
		},
		Resources: []pluginapi.ResourceRoute{{Path: "/dashboard", Menu: "Usage Quota Guard", Description: "Manage downstream key quotas and route bans."}},
	}
}

func Handle(req pluginapi.ManagementRequest, st *store.Store, cfg config.Config) pluginapi.ManagementResponse {
	path := strings.TrimPrefix(req.Path, prefix)
	if path == "" {
		path = req.Path
	}
	if req.Method == http.MethodGet && strings.HasSuffix(req.Path, "/dashboard") {
		return html(http.StatusOK, dashboardHTML)
	}
	if st == nil {
		return jsonResp(http.StatusServiceUnavailable, map[string]any{"error": "store is not initialized"})
	}
	switch {
	case req.Method == http.MethodGet && path == "/api-keys":
		month := req.Query.Get("month")
		if month == "" {
			month = cfg.CurrentPeriod(time.Now())
		}
		items, err := st.ListAPIKeys(month)
		if err != nil {
			return jsonResp(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, map[string]any{"items": items, "month": month, "period": month})
	case req.Method == http.MethodPost && path == "/api-keys":
		var body struct {
			APIKey            string `json:"api_key"`
			DisplayName       string `json:"display_name"`
			MonthlyTokenLimit *int64 `json:"monthly_token_limit"`
			Status            string `json:"status"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		}
		if strings.TrimSpace(body.APIKey) == "" {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "api_key is required"})
		}
		item, err := st.AddAPIKey(body.APIKey, body.DisplayName, body.MonthlyTokenLimit, body.Status, time.Now())
		if err != nil {
			if errors.Is(err, store.ErrKeyAlreadyExists) {
				return jsonResp(http.StatusConflict, map[string]any{"error": "api_key_already_exists", "message": "This API key already exists. Use edit instead of adding it again."})
			}
			return jsonResp(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, item)
	case req.Method == http.MethodPatch && path == "/api-keys":
		var body struct {
			KeyHash           string `json:"key_hash"`
			DisplayName       string `json:"display_name"`
			MonthlyTokenLimit *int64 `json:"monthly_token_limit"`
			Status            string `json:"status"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		}
		if strings.TrimSpace(body.KeyHash) == "" {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "key_hash is required"})
		}
		item, err := st.UpdateAPIKey(body.KeyHash, body.DisplayName, body.MonthlyTokenLimit, body.Status, time.Now())
		if err != nil {
			return jsonResp(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, item)
	case req.Method == http.MethodDelete && path == "/api-keys":
		var body struct {
			KeyHash string `json:"key_hash"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		}
		if strings.TrimSpace(body.KeyHash) == "" {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "key_hash is required"})
		}
		if err := st.DeleteAPIKey(body.KeyHash); err != nil {
			if errors.Is(err, store.ErrKeyNotFound) {
				return jsonResp(http.StatusNotFound, map[string]any{"error": "api_key_not_found", "message": "This API key no longer exists."})
			}
			return jsonResp(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, map[string]any{"ok": true})
	case req.Method == http.MethodGet && path == "/bans":
		active := req.Query.Get("active") == "true" || req.Query.Get("active") == "1"
		items, err := st.ListRouteBans(active, time.Now())
		if err != nil {
			return jsonResp(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, map[string]any{"items": items})
	case req.Method == http.MethodPost && path == "/unban":
		var body struct {
			TargetKey string `json:"target_key"`
			Reason    string `json:"reason"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		}
		if strings.TrimSpace(body.TargetKey) == "" {
			return jsonResp(http.StatusBadRequest, map[string]any{"error": "target_key is required"})
		}
		if err := st.UnbanRoute(body.TargetKey, body.Reason, time.Now()); err != nil {
			return jsonResp(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		}
		return jsonResp(http.StatusOK, map[string]any{"ok": true})
	default:
		return jsonResp(http.StatusNotFound, map[string]any{"error": "not found"})
	}
}

func jsonResp(status int, v any) pluginapi.ManagementResponse {
	raw, _ := json.Marshal(v)
	return pluginapi.ManagementResponse{StatusCode: status, Headers: http.Header{"Content-Type": []string{"application/json; charset=utf-8"}}, Body: raw}
}

func html(status int, body []byte) pluginapi.ManagementResponse {
	return pluginapi.ManagementResponse{StatusCode: status, Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}, Body: body}
}
