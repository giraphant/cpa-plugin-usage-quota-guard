package usage

import (
	"net/http"
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

func TestFromInterceptedResponseParsesOpenAIAndCodexStreamUsage(t *testing.T) {
	now := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	headers := http.Header{"X-Request-Id": []string{"req-1"}}
	event, ok := FromInterceptedResponse([]byte(`{"usage":{"prompt_tokens":10,"completion_tokens":4,"total_tokens":14,"prompt_tokens_details":{"cached_tokens":3}}}`), headers, "hmac_key", "codex", "gpt-5", http.StatusOK, false, now)
	if !ok || event.RequestID != "req-1" || event.InputTokens != 10 || event.OutputTokens != 4 || event.CachedTokens != 3 || event.TotalTokens != 14 || event.Stream {
		t.Fatalf("openai event = %+v ok=%v", event, ok)
	}

	streamBody := []byte("data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":8,\"output_tokens\":5,\"total_tokens\":13,\"input_tokens_details\":{\"cached_tokens\":2}}}}\n\n")
	event, ok = FromInterceptedResponse(streamBody, headers, "hmac_key", "codex", "gpt-5", http.StatusOK, true, now)
	if !ok || event.InputTokens != 8 || event.OutputTokens != 5 || event.CachedTokens != 2 || event.TotalTokens != 13 || !event.Stream {
		t.Fatalf("stream event = %+v ok=%v", event, ok)
	}
}

func TestFromInterceptedResponseParsesGeminiAndClaudeUsage(t *testing.T) {
	now := time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)
	headers := http.Header{"X-Request-Id": []string{"req-formats"}}
	gemini := []byte(`{"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"thoughtsTokenCount":2,"totalTokenCount":17,"cachedContentTokenCount":3}}`)
	event, ok := FromInterceptedResponse(gemini, headers, "hmac_key", "codex", "gemini-2.5-pro", http.StatusOK, false, now)
	if !ok || event.InputTokens != 10 || event.OutputTokens != 5 || event.ReasoningTokens != 2 || event.CachedTokens != 3 || event.TotalTokens != 17 {
		t.Fatalf("gemini event = %+v ok=%v", event, ok)
	}

	claude := []byte(`{"usage":{"input_tokens":13,"output_tokens":4,"cache_read_input_tokens":22000,"cache_creation_input_tokens":31}}`)
	event, ok = FromInterceptedResponse(claude, headers, "hmac_key", "codex", "claude-opus", http.StatusOK, false, now)
	if !ok || event.InputTokens != 13 || event.OutputTokens != 4 || event.CacheReadTokens != 22000 || event.CacheCreationTokens != 31 || event.TotalTokens != 22048 {
		t.Fatalf("claude event = %+v ok=%v", event, ok)
	}
}

func TestTerminalStreamUsageDetection(t *testing.T) {
	if HasTerminalStreamUsage([]byte(`data: {"type":"message_start","message":{"usage":{"input_tokens":13}}}`)) {
		t.Fatal("message_start must wait for terminal usage")
	}
	if !HasTerminalStreamUsage([]byte(`data: {"type":"message_delta","usage":{"output_tokens":4}}`)) {
		t.Fatal("message_delta usage should be terminal")
	}
	if !HasTerminalStreamUsage([]byte(`data: {"type":"message_delta","usage":{"output_tokens":0}}`)) {
		t.Fatal("zero-output message_delta usage should be terminal")
	}
	if HasTerminalStreamUsage([]byte(`data: {"usageMetadata":{"promptTokenCount":10}}`)) {
		t.Fatal("non-terminal Gemini usage must wait for finishReason")
	}
	if !HasTerminalStreamUsage([]byte(`data: {"candidates":[{"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"totalTokenCount":10}}`)) {
		t.Fatal("terminal Gemini usage was not detected")
	}
}

func TestFromInterceptedResponseParsesJSONContainingDataPrefix(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"content":"literal data: text"}}],"usage":{"prompt_tokens":6,"completion_tokens":2,"total_tokens":8}}`)
	event, ok := FromInterceptedResponse(body, http.Header{"X-Request-Id": []string{"req-data"}}, "hmac_key", "codex", "gpt-5", http.StatusOK, false, time.Now())
	if !ok || event.InputTokens != 6 || event.OutputTokens != 2 || event.TotalTokens != 8 {
		t.Fatalf("event = %+v ok=%v", event, ok)
	}
}

func TestFromInterceptedResponseIgnoresChunksWithoutUsage(t *testing.T) {
	if event, ok := FromInterceptedResponse([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n"), nil, "hmac_key", "codex", "gpt-5", http.StatusOK, true, time.Now()); ok {
		t.Fatalf("unexpected event: %+v", event)
	}
}
