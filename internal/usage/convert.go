package usage

import (
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/store"
)

func FromCPA(record pluginapi.UsageRecord, cfg config.Config) store.UsageEvent {
	total := record.Detail.TotalTokens
	if total == 0 {
		total = record.Detail.InputTokens + record.Detail.OutputTokens + record.Detail.ReasoningTokens
	}
	statusCode := 0
	errorType := ""
	if record.Failed {
		statusCode = record.Failure.StatusCode
		errorType = failureType(statusCode, record.Failure.Body)
	}
	return store.UsageEvent{
		RequestID:           requestID(record),
		KeyHash:             strings.TrimSpace(record.APIKey),
		Timestamp:           record.RequestedAt,
		Month:               cfg.CurrentPeriod(record.RequestedAt),
		Provider:            strings.TrimSpace(record.Provider),
		Model:               strings.TrimSpace(record.Model),
		AuthID:              strings.TrimSpace(record.AuthID),
		AuthType:            strings.TrimSpace(record.AuthType),
		StatusCode:          statusCode,
		Failed:              record.Failed,
		ErrorType:           errorType,
		InputTokens:         record.Detail.InputTokens,
		OutputTokens:        record.Detail.OutputTokens,
		ReasoningTokens:     record.Detail.ReasoningTokens,
		CachedTokens:        record.Detail.CachedTokens,
		CacheReadTokens:     record.Detail.CacheReadTokens,
		CacheCreationTokens: record.Detail.CacheCreationTokens,
		TotalTokens:         total,
		LatencyMS:           record.Latency.Milliseconds(),
	}
}

func requestID(record pluginapi.UsageRecord) string {
	if record.ResponseHeaders != nil {
		for _, name := range []string{"X-Request-Id", "X-Request-ID", "Openai-Request-Id", "Request-Id"} {
			if value := record.ResponseHeaders.Get(name); value != "" {
				return value
			}
		}
	}
	return ""
}

func failureType(status int, body string) string {
	if status == 429 {
		return "rate_limited"
	}
	if status >= 500 {
		return "upstream_5xx"
	}
	if strings.TrimSpace(body) != "" {
		return "upstream_error"
	}
	return "failed"
}
