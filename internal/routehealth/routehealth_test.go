package routehealth

import (
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
)

func TestCodex429ResetHeaders(t *testing.T) {
	now := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	cfg := config.Default()
	record := pluginapi.UsageRecord{
		Provider: "codex",
		Model:    "gpt-5",
		AuthID:   "auth-a",
		Failed:   true,
		Failure:  pluginapi.UsageFailure{StatusCode: 429},
		ResponseHeaders: http.Header{
			"X-Codex-Primary-Used-Percent": []string{"100"},
			"X-Codex-Primary-Reset-At":     []string{now.Add(2 * time.Hour).Format(time.RFC3339)},
		},
	}
	ban, ok := ObservationFromUsage(record, cfg, now)
	if !ok {
		t.Fatalf("expected ban")
	}
	if ban.TargetKey != "auth:auth-a:model:gpt-5" {
		t.Fatalf("target key = %q", ban.TargetKey)
	}
	if !ban.ExpiresAt.Equal(now.Add(2 * time.Hour)) {
		t.Fatalf("expires = %s", ban.ExpiresAt)
	}
}

func TestGeneric429FallbackAndClamp(t *testing.T) {
	now := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	cfg := config.Default()
	cfg.RouteHealth.Rules = []config.RouteHealthRule{{Name: "generic", StatusCodes: []int{429}, DurationStrategy: "retry_after_header", FallbackDuration: config.Duration{2 * time.Hour}, MaxDuration: config.Duration{time.Hour}}}
	record := pluginapi.UsageRecord{Provider: "glm", Model: "gpt", Failed: true, Failure: pluginapi.UsageFailure{StatusCode: 429}}
	ban, ok := ObservationFromUsage(record, cfg, now)
	if !ok {
		t.Fatalf("expected ban")
	}
	if got := ban.ExpiresAt.Sub(now); got != time.Hour {
		t.Fatalf("duration = %s", got)
	}
}

func TestCandidateTargetKeyUsesAuthID(t *testing.T) {
	candidate := pluginapi.SchedulerAuthCandidate{ID: "auth-a", Provider: "codex", Attributes: map[string]string{"auth_type": "oauth"}}
	if got := CandidateTargetKey(candidate, "gpt-5"); got != "auth:auth-a:model:gpt-5" {
		t.Fatalf("target key = %q", got)
	}
}
