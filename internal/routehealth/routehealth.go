package routehealth

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"

	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/store"
)

func TargetKey(provider, model, authID, authType string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	model = strings.TrimSpace(model)
	authID = strings.TrimSpace(authID)
	authType = strings.ToLower(strings.TrimSpace(authType))
	if authID != "" {
		return "auth:" + authID + ":model:" + model
	}
	return "provider:" + provider + ":model:" + model + ":auth_type:" + authType
}

func CandidateTargetKey(candidate pluginapi.SchedulerAuthCandidate, model string) string {
	authType := ""
	if candidate.Attributes != nil {
		authType = candidate.Attributes["auth_type"]
		if authType == "" {
			authType = candidate.Attributes["type"]
		}
	}
	return TargetKey(candidate.Provider, model, candidate.ID, authType)
}

func ObservationFromUsage(record pluginapi.UsageRecord, cfg config.Config, now time.Time) (store.RouteBan, bool) {
	if !cfg.RouteHealth.Enabled || !record.Failed {
		return store.RouteBan{}, false
	}
	status := record.Failure.StatusCode
	if status == 0 {
		return store.RouteBan{}, false
	}
	for _, rule := range cfg.RouteHealth.Rules {
		if !ruleMatches(rule, record.Provider, status) {
			continue
		}
		duration := durationForRule(rule, record.ResponseHeaders, now)
		if duration <= 0 {
			continue
		}
		return store.RouteBan{
			TargetKey:       TargetKey(record.Provider, record.Model, record.AuthID, record.AuthType),
			Provider:        record.Provider,
			Model:           record.Model,
			AuthID:          record.AuthID,
			AuthType:        record.AuthType,
			Reason:          rule.Name,
			StatusCode:      status,
			BannedAt:        now,
			ExpiresAt:       now.Add(duration),
			SourceRequestID: record.ResponseHeaders.Get("X-Request-Id"),
		}, true
	}
	return store.RouteBan{}, false
}

func ruleMatches(rule config.RouteHealthRule, provider string, status int) bool {
	if rule.Provider != "" && !strings.EqualFold(strings.TrimSpace(rule.Provider), strings.TrimSpace(provider)) {
		return false
	}
	for _, code := range rule.StatusCodes {
		if code == status {
			return true
		}
	}
	return false
}

func durationForRule(rule config.RouteHealthRule, headers http.Header, now time.Time) time.Duration {
	var d time.Duration
	switch strings.ToLower(strings.TrimSpace(rule.DurationStrategy)) {
	case "codex_reset_headers":
		d = codexResetDuration(headers, now)
	case "retry_after_header":
		d = retryAfterDuration(headers)
	case "fixed":
		d = rule.FallbackDuration.Duration
	default:
		d = rule.FallbackDuration.Duration
	}
	if d <= 0 {
		d = rule.FallbackDuration.Duration
	}
	if rule.MinDuration.Duration > 0 && d < rule.MinDuration.Duration {
		d = rule.MinDuration.Duration
	}
	if rule.MaxDuration.Duration > 0 && d > rule.MaxDuration.Duration {
		d = rule.MaxDuration.Duration
	}
	return d
}

func codexResetDuration(headers http.Header, now time.Time) time.Duration {
	if headers == nil {
		return 0
	}
	candidates := []string{}
	primaryUsed := strings.TrimSuffix(headers.Get("x-codex-primary-used-percent"), "%")
	secondaryUsed := strings.TrimSuffix(headers.Get("x-codex-secondary-used-percent"), "%")
	if percentFull(primaryUsed) {
		candidates = append(candidates, headers.Get("x-codex-primary-reset-at"))
	}
	if percentFull(secondaryUsed) {
		candidates = append(candidates, headers.Get("x-codex-secondary-reset-at"))
	}
	if len(candidates) == 0 {
		candidates = append(candidates, headers.Get("x-codex-primary-reset-at"), headers.Get("x-codex-secondary-reset-at"))
	}
	var latest time.Time
	for _, value := range candidates {
		if t, ok := parseResetAt(value); ok && t.After(latest) {
			latest = t
		}
	}
	if latest.IsZero() || !latest.After(now) {
		return 0
	}
	return latest.Sub(now)
}

func retryAfterDuration(headers http.Header) time.Duration {
	if headers == nil {
		return 0
	}
	value := strings.TrimSpace(headers.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		return time.Until(t)
	}
	return 0
}

func percentFull(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	return err == nil && parsed >= 100
}

func parseResetAt(value string) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if unix, err := strconv.ParseInt(value, 10, 64); err == nil {
		if unix > 1_000_000_000_000 {
			return time.UnixMilli(unix), true
		}
		return time.Unix(unix, 0), true
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, time.RFC1123} {
		if t, err := time.Parse(layout, value); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
