package usage

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/store"
)

func FromCPA(record pluginapi.UsageRecord, cfg config.Config) store.UsageEvent {
	total := record.Detail.TotalTokens
	if total == 0 {
		total = record.Detail.InputTokens + record.Detail.OutputTokens + record.Detail.ReasoningTokens + record.Detail.CacheReadTokens + record.Detail.CacheCreationTokens
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
	return RequestID(record.ResponseHeaders)
}

func RequestID(headers http.Header) string {
	for _, name := range []string{"X-Request-Id", "Openai-Request-Id", "Request-Id"} {
		if value := strings.TrimSpace(headers.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func FromInterceptedResponse(body []byte, headers http.Header, keyHash, provider, model string, statusCode int, stream bool, now time.Time) (store.UsageEvent, bool) {
	usage, ok := parseResponseUsage(body)
	if !ok {
		return store.UsageEvent{}, false
	}
	input := usage.InputTokens
	if input == 0 {
		input = usage.PromptTokens
	}
	output := usage.OutputTokens
	if output == 0 {
		output = usage.CompletionTokens
	}
	cached := usage.InputTokensDetails.CachedTokens
	if cached == 0 {
		cached = usage.PromptTokensDetails.CachedTokens
	}
	reasoning := usage.OutputTokensDetails.ReasoningTokens
	if reasoning == 0 {
		reasoning = usage.CompletionTokensDetails.ReasoningTokens
	}
	total := usage.TotalTokens
	if total == 0 {
		total = input + output + reasoning + usage.CacheReadInputTokens + usage.CacheCreationInputTokens
	}
	return store.UsageEvent{
		RequestID:           RequestID(headers),
		KeyHash:             strings.TrimSpace(keyHash),
		Timestamp:           now,
		Provider:            strings.TrimSpace(provider),
		Model:               strings.TrimSpace(model),
		StatusCode:          statusCode,
		InputTokens:         input,
		OutputTokens:        output,
		ReasoningTokens:     reasoning,
		CachedTokens:        cached,
		CacheReadTokens:     usage.CacheReadInputTokens,
		CacheCreationTokens: usage.CacheCreationInputTokens,
		TotalTokens:         total,
		Stream:              stream,
	}, true
}

type responseUsage struct {
	InputTokens              int64                `json:"input_tokens"`
	PromptTokens             int64                `json:"prompt_tokens"`
	OutputTokens             int64                `json:"output_tokens"`
	CompletionTokens         int64                `json:"completion_tokens"`
	TotalTokens              int64                `json:"total_tokens"`
	CacheReadInputTokens     int64                `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64                `json:"cache_creation_input_tokens"`
	InputTokensDetails       responseTokenDetails `json:"input_tokens_details"`
	PromptTokensDetails      responseTokenDetails `json:"prompt_tokens_details"`
	OutputTokensDetails      responseTokenDetails `json:"output_tokens_details"`
	CompletionTokensDetails  responseTokenDetails `json:"completion_tokens_details"`
}

type responseTokenDetails struct {
	CachedTokens    int64 `json:"cached_tokens"`
	ReasoningTokens int64 `json:"reasoning_tokens"`
}

type geminiUsage struct {
	PromptTokens    int64 `json:"promptTokenCount"`
	OutputTokens    int64 `json:"candidatesTokenCount"`
	ReasoningTokens int64 `json:"thoughtsTokenCount"`
	TotalTokens     int64 `json:"totalTokenCount"`
	CachedTokens    int64 `json:"cachedContentTokenCount"`
}

type responseCandidate struct {
	FinishReason string `json:"finishReason"`
}

type responseUsageEnvelope struct {
	Usage   responseUsage `json:"usage"`
	Message struct {
		Usage responseUsage `json:"usage"`
	} `json:"message"`
	Response struct {
		Usage              responseUsage       `json:"usage"`
		UsageMetadata      geminiUsage         `json:"usageMetadata"`
		UsageMetadataSnake geminiUsage         `json:"usage_metadata"`
		Candidates         []responseCandidate `json:"candidates"`
	} `json:"response"`
	UsageMetadata      geminiUsage         `json:"usageMetadata"`
	UsageMetadataSnake geminiUsage         `json:"usage_metadata"`
	Candidates         []responseCandidate `json:"candidates"`
}

type terminalUsageEnvelope struct {
	Usage    json.RawMessage `json:"usage"`
	Response struct {
		Usage              json.RawMessage     `json:"usage"`
		UsageMetadata      json.RawMessage     `json:"usageMetadata"`
		UsageMetadataSnake json.RawMessage     `json:"usage_metadata"`
		Candidates         []responseCandidate `json:"candidates"`
	} `json:"response"`
	UsageMetadata      json.RawMessage     `json:"usageMetadata"`
	UsageMetadataSnake json.RawMessage     `json:"usage_metadata"`
	Candidates         []responseCandidate `json:"candidates"`
}

func parseResponseUsage(body []byte) (responseUsage, bool) {
	var merged responseUsage
	found := false
	for _, candidate := range responseJSONCandidates(body) {
		var payload responseUsageEnvelope
		if json.Unmarshal(candidate, &payload) != nil {
			continue
		}
		for _, usage := range []responseUsage{
			payload.Usage,
			payload.Message.Usage,
			payload.Response.Usage,
			geminiResponseUsage(payload.UsageMetadata),
			geminiResponseUsage(payload.UsageMetadataSnake),
			geminiResponseUsage(payload.Response.UsageMetadata),
			geminiResponseUsage(payload.Response.UsageMetadataSnake),
		} {
			if hasResponseUsage(usage) {
				merged = mergeResponseUsage(merged, usage)
				found = true
			}
		}
	}
	return merged, found
}

func HasInterceptedUsage(body []byte) bool {
	_, ok := parseResponseUsage(body)
	return ok
}

func HasTerminalStreamUsage(body []byte) bool {
	for _, candidate := range responseJSONCandidates(body) {
		var payload terminalUsageEnvelope
		if json.Unmarshal(candidate, &payload) != nil {
			continue
		}
		if hasJSONValue(payload.Usage) || hasJSONValue(payload.Response.Usage) {
			return true
		}
		if (hasJSONValue(payload.UsageMetadata) || hasJSONValue(payload.UsageMetadataSnake)) && hasFinishReason(payload.Candidates) {
			return true
		}
		if (hasJSONValue(payload.Response.UsageMetadata) || hasJSONValue(payload.Response.UsageMetadataSnake)) && hasFinishReason(payload.Response.Candidates) {
			return true
		}
	}
	return false
}

func hasJSONValue(raw json.RawMessage) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 0 && !bytes.Equal(raw, []byte("null"))
}

func geminiResponseUsage(usage geminiUsage) responseUsage {
	return responseUsage{
		InputTokens:  usage.PromptTokens,
		OutputTokens: usage.OutputTokens,
		TotalTokens:  usage.TotalTokens,
		InputTokensDetails: responseTokenDetails{
			CachedTokens: usage.CachedTokens,
		},
		OutputTokensDetails: responseTokenDetails{
			ReasoningTokens: usage.ReasoningTokens,
		},
	}
}

func mergeResponseUsage(current, next responseUsage) responseUsage {
	current.InputTokens = max(current.InputTokens, next.InputTokens)
	current.PromptTokens = max(current.PromptTokens, next.PromptTokens)
	current.OutputTokens = max(current.OutputTokens, next.OutputTokens)
	current.CompletionTokens = max(current.CompletionTokens, next.CompletionTokens)
	current.TotalTokens = max(current.TotalTokens, next.TotalTokens)
	current.CacheReadInputTokens = max(current.CacheReadInputTokens, next.CacheReadInputTokens)
	current.CacheCreationInputTokens = max(current.CacheCreationInputTokens, next.CacheCreationInputTokens)
	current.InputTokensDetails.CachedTokens = max(current.InputTokensDetails.CachedTokens, next.InputTokensDetails.CachedTokens)
	current.PromptTokensDetails.CachedTokens = max(current.PromptTokensDetails.CachedTokens, next.PromptTokensDetails.CachedTokens)
	current.OutputTokensDetails.ReasoningTokens = max(current.OutputTokensDetails.ReasoningTokens, next.OutputTokensDetails.ReasoningTokens)
	current.CompletionTokensDetails.ReasoningTokens = max(current.CompletionTokensDetails.ReasoningTokens, next.CompletionTokensDetails.ReasoningTokens)
	return current
}

func hasGeminiUsage(usage geminiUsage) bool {
	return usage.PromptTokens != 0 || usage.OutputTokens != 0 || usage.ReasoningTokens != 0 || usage.TotalTokens != 0 || usage.CachedTokens != 0
}

func hasFinishReason(candidates []responseCandidate) bool {
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate.FinishReason) != "" {
			return true
		}
	}
	return false
}

func responseJSONCandidates(body []byte) [][]byte {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil
	}
	if json.Valid(body) {
		return [][]byte{body}
	}
	lines := bytes.Split(body, []byte{'\n'})
	out := make([][]byte, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		candidate := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(candidate) > 0 && !bytes.Equal(candidate, []byte("[DONE]")) {
			out = append(out, candidate)
		}
	}
	return out
}

func hasResponseUsage(usage responseUsage) bool {
	return usage.InputTokens != 0 || usage.PromptTokens != 0 || usage.OutputTokens != 0 || usage.CompletionTokens != 0 || usage.TotalTokens != 0 || usage.CacheReadInputTokens != 0 || usage.CacheCreationInputTokens != 0 || usage.InputTokensDetails.CachedTokens != 0 || usage.PromptTokensDetails.CachedTokens != 0 || usage.OutputTokensDetails.ReasoningTokens != 0 || usage.CompletionTokensDetails.ReasoningTokens != 0
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
