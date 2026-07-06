package auth

import (
	"net/http"
	"net/url"
	"testing"
)

func TestExtractAPIKeyOrder(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer auth-key")
	headers.Set("X-Api-Key", "x-key")
	query := url.Values{"key": []string{"query-key"}}
	key, source, ok := ExtractAPIKey(headers, query, nil)
	if !ok || key != "auth-key" || source != SourceAuthorizationBearer {
		t.Fatalf("got key=%q source=%q ok=%v", key, source, ok)
	}
}

func TestExtractAPIKeySources(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		query   url.Values
		source  string
		want    string
	}{
		{"x api", http.Header{"X-Api-Key": []string{"x-key"}}, nil, SourceXAPIKey, "x-key"},
		{"x goog", http.Header{"X-Goog-Api-Key": []string{"goog-key"}}, nil, SourceXGoogAPIKey, "goog-key"},
		{"query key", nil, url.Values{"key": []string{"query-key"}}, SourceQueryKey, "query-key"},
		{"query token", nil, url.Values{"auth_token": []string{"token-key"}}, SourceQueryAuthToken, "token-key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, source, ok := ExtractAPIKey(tt.headers, tt.query, []string{tt.source})
			if !ok || key != tt.want || source != tt.source {
				t.Fatalf("got key=%q source=%q ok=%v", key, source, ok)
			}
		})
	}
}

func TestFingerprintRedactsKey(t *testing.T) {
	key := "sk-abcdefghijklmnopqrstuvwxyz"
	fp := Fingerprint(key)
	if fp == key {
		t.Fatalf("fingerprint exposed full key")
	}
	if fp[len(fp)-4:] != "wxyz" {
		t.Fatalf("fingerprint = %q, want visible suffix", fp)
	}
}
