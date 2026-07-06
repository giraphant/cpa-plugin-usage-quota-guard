package auth

import (
	"net/http"
	"net/url"
	"strings"
)

const (
	SourceAuthorizationBearer = "authorization_bearer"
	SourceXAPIKey             = "x_api_key"
	SourceXGoogAPIKey         = "x_goog_api_key"
	SourceQueryKey            = "query_key"
	SourceQueryAuthToken      = "query_auth_token"
)

func ExtractAPIKey(headers http.Header, query url.Values, sources []string) (string, string, bool) {
	if len(sources) == 0 {
		sources = []string{SourceAuthorizationBearer, SourceXAPIKey, SourceXGoogAPIKey, SourceQueryKey, SourceQueryAuthToken}
	}
	for _, source := range sources {
		switch strings.ToLower(strings.TrimSpace(source)) {
		case SourceAuthorizationBearer:
			if key := bearer(headers.Get("Authorization")); key != "" {
				return key, SourceAuthorizationBearer, true
			}
		case SourceXAPIKey:
			if key := strings.TrimSpace(headers.Get("X-Api-Key")); key != "" {
				return key, SourceXAPIKey, true
			}
		case SourceXGoogAPIKey:
			if key := strings.TrimSpace(headers.Get("X-Goog-Api-Key")); key != "" {
				return key, SourceXGoogAPIKey, true
			}
		case SourceQueryKey:
			if key := strings.TrimSpace(query.Get("key")); key != "" {
				return key, SourceQueryKey, true
			}
		case SourceQueryAuthToken:
			if key := strings.TrimSpace(query.Get("auth_token")); key != "" {
				return key, SourceQueryAuthToken, true
			}
		}
	}
	return "", "", false
}

func bearer(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Fields(value)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

func Fingerprint(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if len(key) <= 8 {
		return "..." + key
	}
	prefix := key[:min(3, len(key))]
	suffix := key[len(key)-4:]
	return prefix + "-..." + suffix
}
