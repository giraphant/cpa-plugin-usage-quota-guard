package config

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	UnknownAccessDeny  = "deny"
	UnknownAccessAllow = "allow"

	QuotaPeriodMonthly = "monthly"
	QuotaPeriodWeekly  = "weekly"

	QuotaMetricTotal  = "total_tokens"
	QuotaMetricOutput = "output_tokens"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value == nil || strings.TrimSpace(value.Value) == "" {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value.Value))
	if err != nil {
		return err
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return d.Duration.String(), nil
}

type Config struct {
	Enabled                  bool          `yaml:"enabled"`
	Priority                 int           `yaml:"priority"`
	Storage                  StorageConfig `yaml:"storage"`
	Secret                   SecretConfig  `yaml:"secret"`
	FrontendAuth             AuthConfig    `yaml:"frontend_auth"`
	UnknownKeyRegistration   bool          `yaml:"unknown_key_registration"`
	UnknownKeyAccess         string        `yaml:"unknown_key_access"`
	DefaultMonthlyTokenLimit *int64        `yaml:"default_monthly_token_limit"`
	Usage                    UsageConfig   `yaml:"usage"`
	Quota                    QuotaConfig   `yaml:"quota"`
	RouteHealth              RouteHealth   `yaml:"route_health"`
}

type StorageConfig struct {
	SQLitePath string `yaml:"sqlite_path"`
}

type SecretConfig struct {
	SecretFile string `yaml:"secret_file"`
	SecretEnv  string `yaml:"secret_env"`
}

type AuthConfig struct {
	Exclusive       bool     `yaml:"exclusive"`
	AcceptedSources []string `yaml:"accepted_sources"`
}

type UsageConfig struct {
	DetailRetentionDays int    `yaml:"detail_retention_days"`
	Timezone            string `yaml:"timezone"`
}

type QuotaConfig struct {
	Period           string `yaml:"period"`
	Metric           string `yaml:"metric"`
	OverQuotaStatus  int    `yaml:"over_quota_status"`
	OverQuotaMessage string `yaml:"over_quota_message"`
}

type RouteHealth struct {
	Enabled bool              `yaml:"enabled"`
	Mode    string            `yaml:"mode"`
	Rules   []RouteHealthRule `yaml:"rules"`
}

type RouteHealthRule struct {
	Name             string   `yaml:"name"`
	Provider         string   `yaml:"provider"`
	StatusCodes      []int    `yaml:"status_codes"`
	DurationStrategy string   `yaml:"duration_strategy"`
	FallbackDuration Duration `yaml:"fallback_duration"`
	MinDuration      Duration `yaml:"min_duration"`
	MaxDuration      Duration `yaml:"max_duration"`
}

func Load(raw []byte) (Config, error) {
	cfg := Default()
	if len(raw) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return Config{}, err
		}
		if err := applyFlatDottedFields(raw, &cfg); err != nil {
			return Config{}, err
		}
	}
	if cfg.Storage.SQLitePath == "" {
		cfg.Storage.SQLitePath = "./data/usage-quota-guard.sqlite"
	}
	if cfg.Secret.SecretFile == "" {
		cfg.Secret.SecretFile = "./data/usage-quota-guard.secret"
	}
	if cfg.Secret.SecretEnv == "" {
		cfg.Secret.SecretEnv = "USAGE_QUOTA_GUARD_SECRET"
	}
	if len(cfg.FrontendAuth.AcceptedSources) == 0 {
		cfg.FrontendAuth.AcceptedSources = defaultAcceptedSources()
	}
	if cfg.UnknownKeyAccess == "" {
		cfg.UnknownKeyAccess = UnknownAccessDeny
	}
	cfg.UnknownKeyAccess = strings.ToLower(strings.TrimSpace(cfg.UnknownKeyAccess))
	if cfg.Usage.DetailRetentionDays <= 0 {
		cfg.Usage.DetailRetentionDays = 90
	}
	if cfg.Usage.Timezone == "" {
		cfg.Usage.Timezone = "Asia/Shanghai"
	}
	if cfg.Quota.OverQuotaStatus == 0 {
		cfg.Quota.OverQuotaStatus = 429
	}
	if cfg.Quota.OverQuotaMessage == "" {
		cfg.Quota.OverQuotaMessage = "Token quota exceeded for this API key."
	}
	cfg.Quota.Period = strings.ToLower(strings.TrimSpace(cfg.Quota.Period))
	if cfg.Quota.Period == "" {
		cfg.Quota.Period = QuotaPeriodMonthly
	}
	cfg.Quota.Metric = strings.ToLower(strings.TrimSpace(cfg.Quota.Metric))
	if cfg.Quota.Metric == "" {
		cfg.Quota.Metric = QuotaMetricOutput
	}
	if cfg.RouteHealth.Mode == "" {
		cfg.RouteHealth.Mode = "plugin_scheduler"
	}
	if cfg.RouteHealth.Enabled && len(cfg.RouteHealth.Rules) == 0 {
		cfg.RouteHealth.Rules = defaultRouteHealthRules()
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Default() Config {
	return Config{
		Enabled:                true,
		Storage:                StorageConfig{SQLitePath: "./data/usage-quota-guard.sqlite"},
		Secret:                 SecretConfig{SecretFile: "./data/usage-quota-guard.secret", SecretEnv: "USAGE_QUOTA_GUARD_SECRET"},
		FrontendAuth:           AuthConfig{Exclusive: true, AcceptedSources: defaultAcceptedSources()},
		UnknownKeyRegistration: true,
		UnknownKeyAccess:       UnknownAccessDeny,
		Usage:                  UsageConfig{DetailRetentionDays: 90, Timezone: "Asia/Shanghai"},
		Quota:                  QuotaConfig{Period: QuotaPeriodMonthly, Metric: QuotaMetricOutput, OverQuotaStatus: 429, OverQuotaMessage: "Token quota exceeded for this API key."},
		RouteHealth:            RouteHealth{Enabled: true, Mode: "plugin_scheduler", Rules: defaultRouteHealthRules()},
	}
}

func defaultAcceptedSources() []string {
	return []string{"authorization_bearer", "x_api_key", "x_goog_api_key", "query_key", "query_auth_token"}
}

func defaultRouteHealthRules() []RouteHealthRule {
	return []RouteHealthRule{
		{Name: "codex_429", Provider: "codex", StatusCodes: []int{429}, DurationStrategy: "codex_reset_headers", FallbackDuration: Duration{5 * time.Hour}, MinDuration: Duration{5 * time.Minute}, MaxDuration: Duration{24 * time.Hour}},
		{Name: "generic_429", StatusCodes: []int{429}, DurationStrategy: "retry_after_header", FallbackDuration: Duration{10 * time.Minute}, MinDuration: Duration{time.Minute}, MaxDuration: Duration{time.Hour}},
	}
}

func applyFlatDottedFields(raw []byte, cfg *Config) error {
	var fields map[string]any
	if err := yaml.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for key, value := range fields {
		switch strings.TrimSpace(key) {
		case "storage.sqlite_path":
			if s, ok := stringValue(value); ok {
				cfg.Storage.SQLitePath = s
			}
		case "secret.secret_file":
			if s, ok := stringValue(value); ok {
				cfg.Secret.SecretFile = s
			}
		case "secret.secret_env":
			if s, ok := stringValue(value); ok {
				cfg.Secret.SecretEnv = s
			}
		case "usage.detail_retention_days":
			if n, ok := intValue(value); ok {
				cfg.Usage.DetailRetentionDays = n
			}
		}
	}
	return nil
}

func stringValue(value any) (string, bool) {
	s, ok := value.(string)
	return strings.TrimSpace(s), ok
}

func intValue(value any) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	default:
		return 0, false
	}
}

func (c Config) Validate() error {
	if c.Storage.SQLitePath == "" {
		return errors.New("storage.sqlite_path is required")
	}
	if c.Secret.SecretFile == "" && c.Secret.SecretEnv == "" {
		return errors.New("secret.secret_file or secret.secret_env is required")
	}
	if c.UnknownKeyAccess != UnknownAccessDeny && c.UnknownKeyAccess != UnknownAccessAllow {
		return fmt.Errorf("unknown_key_access must be %q or %q", UnknownAccessDeny, UnknownAccessAllow)
	}
	if c.Quota.Period != QuotaPeriodMonthly && c.Quota.Period != QuotaPeriodWeekly {
		return fmt.Errorf("quota.period must be %q or %q", QuotaPeriodMonthly, QuotaPeriodWeekly)
	}
	if c.Quota.Metric != QuotaMetricTotal && c.Quota.Metric != QuotaMetricOutput {
		return fmt.Errorf("quota.metric must be %q or %q", QuotaMetricTotal, QuotaMetricOutput)
	}
	if _, err := time.LoadLocation(c.Usage.Timezone); err != nil {
		return fmt.Errorf("invalid usage.timezone: %w", err)
	}
	return nil
}

func (c Config) CurrentPeriod(t time.Time) string {
	loc, err := time.LoadLocation(c.Usage.Timezone)
	if err != nil {
		loc = time.Local
	}
	tt := t.In(loc)
	if c.Quota.Period == QuotaPeriodWeekly {
		year, week := tt.ISOWeek()
		return fmt.Sprintf("%04d-W%02d", year, week)
	}
	return tt.Format("2006-01")
}

func (c Config) RetentionCutoff(now time.Time) time.Time {
	return now.AddDate(0, 0, -c.Usage.DetailRetentionDays)
}
