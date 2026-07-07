package usage

import (
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
)

func TestFromCPATotalTokenFallback(t *testing.T) {
	record := pluginapi.UsageRecord{
		Provider:    "codex",
		Model:       "gpt-5",
		APIKey:      "hmac_key",
		RequestedAt: time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC),
		Detail: pluginapi.UsageDetail{
			InputTokens:     10,
			OutputTokens:    20,
			ReasoningTokens: 5,
			TotalTokens:     0,
		},
	}
	event := FromCPA(record, config.Default())
	if event.TotalTokens != 35 {
		t.Fatalf("TotalTokens = %d, want 35", event.TotalTokens)
	}
	if event.Month != "2026-07" {
		t.Fatalf("Month = %q", event.Month)
	}
}

func TestFromCPATotalTokenFallbackIncludesDetailedCacheTokens(t *testing.T) {
	record := pluginapi.UsageRecord{
		Provider:    "claude",
		Model:       "claude-sonnet-4-5",
		APIKey:      "hmac_key",
		RequestedAt: time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC),
		Detail: pluginapi.UsageDetail{
			InputTokens:         10,
			OutputTokens:        20,
			ReasoningTokens:     5,
			CacheReadTokens:     100,
			CacheCreationTokens: 40,
			TotalTokens:         0,
		},
	}
	event := FromCPA(record, config.Default())
	if event.TotalTokens != 175 {
		t.Fatalf("TotalTokens = %d, want 175", event.TotalTokens)
	}
}
