package abi

import (
	"encoding/json"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type Envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *EnvelopeError  `json:"error,omitempty"`
}

type EnvelopeError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable,omitempty"`
	HTTPStatus int    `json:"http_status,omitempty"`
}

type LifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type Registration struct {
	SchemaVersion uint32       `json:"schema_version"`
	Metadata      Metadata     `json:"metadata"`
	Capabilities  Capabilities `json:"capabilities"`
}

type Metadata = pluginapi.Metadata

type Capabilities struct {
	FrontendAuthProvider          bool `json:"frontend_auth_provider"`
	FrontendAuthProviderExclusive bool `json:"frontend_auth_provider_exclusive"`
	ResponseInterceptor           bool `json:"response_interceptor"`
	StreamChunkInterceptor        bool `json:"response_stream_interceptor"`
	Scheduler                     bool `json:"scheduler"`
	UsagePlugin                   bool `json:"usage_plugin"`
	ManagementAPI                 bool `json:"management_api"`
}

type IdentifierResponse struct {
	Identifier string `json:"identifier"`
}

func OKEnvelope(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Envelope{OK: true, Result: raw})
}

func OKEnvelopeJSON(result string) ([]byte, error) {
	return json.Marshal(Envelope{OK: true, Result: json.RawMessage(result)})
}

func ErrorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(Envelope{OK: false, Error: &EnvelopeError{Code: code, Message: message}})
	return raw
}

func PluginRegistration(version string) Registration {
	return Registration{
		SchemaVersion: pluginabi.SchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             "usage-quota-guard",
			Version:          version,
			Author:           "giraphant",
			GitHubRepository: "https://github.com/giraphant/cpa-plugin-usage-quota-guard",
			Logo:             "https://raw.githubusercontent.com/router-for-me/CLIProxyAPI/main/docs/logo.png",
			ConfigFields: []pluginapi.ConfigField{
				{Name: "storage.sqlite_path", Type: pluginapi.ConfigFieldTypeString, Description: "SQLite file path used by usage-quota-guard."},
				{Name: "secret.secret_file", Type: pluginapi.ConfigFieldTypeString, Description: "File storing the HMAC secret used for downstream API-key hashes."},
				{Name: "unknown_key_access", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"deny", "allow"}, Description: "Whether unknown keys are allowed after auto-registration."},
				{Name: "usage.detail_retention_days", Type: pluginapi.ConfigFieldTypeInteger, Description: "Number of days to retain per-request usage events."},
			},
		},
		Capabilities: Capabilities{
			FrontendAuthProvider:          true,
			FrontendAuthProviderExclusive: true,
			ResponseInterceptor:           true,
			StreamChunkInterceptor:        true,
			Scheduler:                     true,
			UsagePlugin:                   true,
			ManagementAPI:                 true,
		},
	}
}
