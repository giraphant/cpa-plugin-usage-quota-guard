package config

import (
	"regexp"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(nil)
	if err != nil {
		t.Fatalf("Load defaults: %v", err)
	}
	if cfg.Storage.SQLitePath != "./data/usage-quota-guard.sqlite" {
		t.Fatalf("sqlite path = %q", cfg.Storage.SQLitePath)
	}
	if cfg.Secret.SecretFile != "./data/usage-quota-guard.secret" {
		t.Fatalf("secret file = %q", cfg.Secret.SecretFile)
	}
	if !cfg.UnknownKeyRegistration || cfg.UnknownKeyAccess != "deny" {
		t.Fatalf("unexpected unknown policy: registration=%v access=%q", cfg.UnknownKeyRegistration, cfg.UnknownKeyAccess)
	}
	if cfg.Usage.DetailRetentionDays != 90 || cfg.Usage.Timezone != "Asia/Shanghai" {
		t.Fatalf("unexpected usage defaults: %+v", cfg.Usage)
	}
	if !cfg.RouteHealth.Enabled || len(cfg.RouteHealth.Rules) == 0 {
		t.Fatalf("route health defaults not enabled: %+v", cfg.RouteHealth)
	}
}

func TestLoadAcceptsFlatDottedConfigFields(t *testing.T) {
	raw := []byte(`
storage.sqlite_path: /srv/cpa/usage.sqlite
secret.secret_file: /srv/cpa/usage.secret
usage.detail_retention_days: 30
unknown_key_access: allow
`)
	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load flat dotted config: %v", err)
	}
	if cfg.Storage.SQLitePath != "/srv/cpa/usage.sqlite" {
		t.Fatalf("sqlite path = %q", cfg.Storage.SQLitePath)
	}
	if cfg.Secret.SecretFile != "/srv/cpa/usage.secret" {
		t.Fatalf("secret file = %q", cfg.Secret.SecretFile)
	}
	if cfg.Usage.DetailRetentionDays != 30 {
		t.Fatalf("retention = %d", cfg.Usage.DetailRetentionDays)
	}
	if cfg.UnknownKeyAccess != "allow" {
		t.Fatalf("unknown access = %q", cfg.UnknownKeyAccess)
	}
}

func TestLoadOverrides(t *testing.T) {
	raw := []byte(`
storage:
  sqlite_path: /tmp/test.sqlite
secret:
  secret_file: /tmp/test.secret
unknown_key_access: allow
usage:
  detail_retention_days: 14
  timezone: UTC
route_health:
  enabled: true
  rules:
    - name: short_429
      status_codes: [429]
      duration_strategy: fixed
      fallback_duration: 2m
      min_duration: 1m
      max_duration: 10m
`)
	cfg, err := Load(raw)
	if err != nil {
		t.Fatalf("Load overrides: %v", err)
	}
	if cfg.Storage.SQLitePath != "/tmp/test.sqlite" || cfg.UnknownKeyAccess != "allow" {
		t.Fatalf("unexpected overrides: %+v", cfg)
	}
	if cfg.Usage.DetailRetentionDays != 14 || cfg.CurrentPeriod(time.Date(2026, 7, 6, 1, 0, 0, 0, time.UTC)) != "2026-07" {
		t.Fatalf("unexpected usage override")
	}
	if got := cfg.RouteHealth.Rules[0].FallbackDuration.Duration; got != 2*time.Minute {
		t.Fatalf("fallback duration = %s", got)
	}
}

func TestCurrentPeriodMonthlyDefault(t *testing.T) {
	cfg, _ := Load(nil)
	got := cfg.CurrentPeriod(time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC))
	if got != "2026-07" {
		t.Fatalf("monthly period = %q, want 2026-07", got)
	}
}

func TestCurrentPeriodWeeklyFormatAndBoundary(t *testing.T) {
	cfg, _ := Load([]byte("quota:\n  period: weekly\n"))
	sun := cfg.CurrentPeriod(time.Date(2026, 1, 4, 12, 0, 0, 0, time.UTC)) // Sunday, end of ISO W1
	mon := cfg.CurrentPeriod(time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)) // Monday, start of ISO W2
	if !regexp.MustCompile(`^\d{4}-W\d{2}$`).MatchString(mon) {
		t.Fatalf("weekly format = %q", mon)
	}
	if sun == mon {
		t.Fatalf("ISO week should differ across Sun/Mon boundary: sun=%s mon=%s", sun, mon)
	}
}

func TestLoadRejectsInvalidQuotaPeriod(t *testing.T) {
	if _, err := Load([]byte("quota:\n  period: daily\n")); err == nil {
		t.Fatalf("expected error for invalid quota.period")
	}
}
