package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "test.sqlite")
	cfg.Secret.SecretFile = filepath.Join(t.TempDir(), "secret")
	st, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestMigrationsAndWAL(t *testing.T) {
	st := testStore(t)
	var journal string
	if err := st.DB().QueryRow(`PRAGMA journal_mode`).Scan(&journal); err != nil {
		t.Fatalf("journal mode: %v", err)
	}
	if journal != "wal" {
		t.Fatalf("journal mode = %q", journal)
	}
	for _, table := range []string{"api_keys", "usage_events", "monthly_usage", "route_bans", "quota_cycle_state"} {
		var name string
		err := st.DB().QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}
	var index string
	if err := st.DB().QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_usage_events_request_key'`).Scan(&index); err != nil {
		t.Fatalf("usage deduplication index missing: %v", err)
	}
}

func TestUnknownKeyRegistersPendingAndDenied(t *testing.T) {
	st := testStore(t)
	res, err := st.AuthenticateKey("sk-test", time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("AuthenticateKey: %v", err)
	}
	if res.Allowed || res.Reason != "unknown_key" || res.Status != KeyStatusPending {
		t.Fatalf("unexpected auth result: %+v", res)
	}
	var status string
	if err := st.DB().QueryRow(`SELECT status FROM api_keys WHERE key_hash=?`, res.KeyHash).Scan(&status); err != nil {
		t.Fatalf("lookup key: %v", err)
	}
	if status != KeyStatusPending {
		t.Fatalf("status = %q", status)
	}
}

func TestActiveKeyWithQuotaIsDeniedAfterUsage(t *testing.T) {
	st := testStore(t)
	now := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	limit := int64(10)
	key, err := st.AddAPIKey("sk-active", "alice", &limit, KeyStatusActive, now)
	if err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, OutputTokens: 10, TotalTokens: 10}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	res, err := st.AuthenticateKey("sk-active", now)
	if err != nil {
		t.Fatalf("AuthenticateKey: %v", err)
	}
	if res.Allowed || res.Reason != "over_quota" {
		t.Fatalf("unexpected auth result: %+v", res)
	}
}

func TestRecordUsageIncrementsMonthlyAggregate(t *testing.T) {
	st := testStore(t)
	now := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	key, err := st.AddAPIKey("sk-usage", "bob", nil, KeyStatusActive, now)
	if err != nil {
		t.Fatalf("AddAPIKey: %v", err)
	}
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, InputTokens: 3, OutputTokens: 4}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	used, err := st.MonthlyUsage(key.KeyHash, "2026-07")
	if err != nil {
		t.Fatalf("MonthlyUsage: %v", err)
	}
	if used != 7 {
		t.Fatalf("used = %d", used)
	}
}

func TestRecordUsageDeduplicatesRequestPerKey(t *testing.T) {
	st := testStore(t)
	now := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	first, _ := st.AddAPIKey("sk-first", "first", nil, KeyStatusActive, now)
	second, _ := st.AddAPIKey("sk-second", "second", nil, KeyStatusActive, now)
	for _, event := range []UsageEvent{
		{RequestID: "req-shared", KeyHash: first.KeyHash, Timestamp: now, OutputTokens: 5},
		{RequestID: "req-shared", KeyHash: first.KeyHash, Timestamp: now, OutputTokens: 5},
		{RequestID: "req-shared", KeyHash: second.KeyHash, Timestamp: now, OutputTokens: 7},
	} {
		if err := st.RecordUsage(event); err != nil {
			t.Fatal(err)
		}
	}
	firstTotals, _ := st.PeriodTotals(first.KeyHash, "2026-07")
	secondTotals, _ := st.PeriodTotals(second.KeyHash, "2026-07")
	if firstTotals.Output != 5 || secondTotals.Output != 7 {
		t.Fatalf("first=%+v second=%+v", firstTotals, secondTotals)
	}
	var events int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM usage_events WHERE request_id = ?`, "req-shared").Scan(&events); err != nil || events != 2 {
		t.Fatalf("events=%d err=%v", events, err)
	}
}

func TestRouteBanLifecycle(t *testing.T) {
	st := testStore(t)
	now := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	ban := RouteBan{TargetKey: "auth:a:model:gpt", Reason: "codex_429", BannedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := st.AddOrExtendBan(ban); err != nil {
		t.Fatalf("AddOrExtendBan: %v", err)
	}
	got, ok, err := st.ActiveBan(ban.TargetKey, now.Add(time.Minute))
	if err != nil || !ok {
		t.Fatalf("ActiveBan ok=%v err=%v", ok, err)
	}
	if got.Reason != "codex_429" {
		t.Fatalf("reason = %q", got.Reason)
	}
	if err := st.UnbanRoute(ban.TargetKey, "manual", now.Add(2*time.Minute)); err != nil {
		t.Fatalf("UnbanRoute: %v", err)
	}
	_, ok, err = st.ActiveBan(ban.TargetKey, now.Add(3*time.Minute))
	if err != nil {
		t.Fatalf("ActiveBan after unban: %v", err)
	}
	if ok {
		t.Fatalf("ban still active")
	}
}

func TestAddAPIKeyRejectsDuplicate(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	if _, err := st.AddAPIKey("sk-dup", "alice", nil, KeyStatusActive, now); err != nil {
		t.Fatalf("first add: %v", err)
	}
	_, err := st.AddAPIKey("sk-dup", "alice-2", nil, KeyStatusActive, now)
	if !errors.Is(err, ErrKeyAlreadyExists) {
		t.Fatalf("expected ErrKeyAlreadyExists, got %v", err)
	}
}

func TestDeleteAPIKey(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	key, err := st.AddAPIKey("sk-del", "bob", nil, KeyStatusActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteAPIKey(key.KeyHash); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := st.GetAPIKey(key.KeyHash, "2026-07"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows after delete, got %v", err)
	}
	if err := st.DeleteAPIKey(key.KeyHash); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound on second delete, got %v", err)
	}
}

func TestAuthenticateByOutputMetric(t *testing.T) {
	cfg := config.Default()
	cfg.Quota.Metric = config.QuotaMetricOutput
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "test.sqlite")
	cfg.Secret.SecretFile = filepath.Join(t.TempDir(), "secret")
	st, err := Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	now := time.Now()
	limit := int64(10)
	key, err := st.AddAPIKey("sk-o", "o", &limit, KeyStatusActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, InputTokens: 1000, OutputTokens: 5}); err != nil {
		t.Fatalf("record: %v", err)
	}
	res, err := st.AuthenticateKey("sk-o", now)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected allowed under output metric despite high input, got %+v", res)
	}
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, OutputTokens: 6}); err != nil {
		t.Fatalf("record2: %v", err)
	}
	res2, _ := st.AuthenticateKey("sk-o", now)
	if res2.Allowed || res2.Reason != "over_quota" {
		t.Fatalf("expected over_quota by output metric, got %+v", res2)
	}
}

func TestPeriodTotals(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	key, _ := st.AddAPIKey("sk-t", "t", nil, KeyStatusActive, now)
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, InputTokens: 100, OutputTokens: 20, CacheReadTokens: 50, TotalTokens: 170}); err != nil {
		t.Fatalf("record: %v", err)
	}
	totals, err := st.PeriodTotals(key.KeyHash, st.cfg.CurrentPeriod(now))
	if err != nil {
		t.Fatalf("totals: %v", err)
	}
	if totals.Input != 100 || totals.Output != 20 || totals.CacheRead != 50 || totals.Total != 170 {
		t.Fatalf("totals = %+v", totals)
	}
}

func TestRecordUsageTotalFallbackIncludesDetailedCacheTokens(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	key, _ := st.AddAPIKey("sk-cache-total", "cache", nil, KeyStatusActive, now)
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, InputTokens: 10, OutputTokens: 20, ReasoningTokens: 5, CacheReadTokens: 100, CacheCreationTokens: 40}); err != nil {
		t.Fatalf("record: %v", err)
	}
	totals, err := st.PeriodTotals(key.KeyHash, st.cfg.CurrentPeriod(now))
	if err != nil {
		t.Fatalf("totals: %v", err)
	}
	if totals.Total != 175 {
		t.Fatalf("total = %d, want 175", totals.Total)
	}
}

func TestCachedPromptTokensAreAggregatedForOpenAIStyleUsage(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	key, _ := st.AddAPIKey("sk-cache-openai", "cache", nil, KeyStatusActive, now)
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, InputTokens: 100, OutputTokens: 20, CachedTokens: 70, TotalTokens: 120}); err != nil {
		t.Fatalf("record: %v", err)
	}
	totals, err := st.PeriodTotals(key.KeyHash, st.cfg.CurrentPeriod(now))
	if err != nil {
		t.Fatalf("totals: %v", err)
	}
	if totals.CacheRead != 70 {
		t.Fatalf("cache read = %d, want 70", totals.CacheRead)
	}
	if totals.Input != 30 {
		t.Fatalf("uncached input = %d, want 30", totals.Input)
	}
}

func TestAPIKeyCachedUsageIncludesReadsAndWrites(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	key, _ := st.AddAPIKey("sk-cache-display", "cache", nil, KeyStatusActive, now)
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, InputTokens: 100, OutputTokens: 20, CacheReadTokens: 50, CacheCreationTokens: 30, TotalTokens: 200}); err != nil {
		t.Fatalf("record: %v", err)
	}
	got, err := st.GetAPIKey(key.KeyHash, st.cfg.CurrentPeriod(now))
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if got.UsedCachedTokens != 80 {
		t.Fatalf("cached usage = %d, want 80", got.UsedCachedTokens)
	}
}

func TestWeeklyPeriodUsage(t *testing.T) {

	cfg := config.Default()
	cfg.Quota.Period = config.QuotaPeriodWeekly
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "test.sqlite")
	cfg.Secret.SecretFile = filepath.Join(t.TempDir(), "secret")
	st, err := Open(cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()
	now := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC) // Monday, ISO W2
	key, err := st.AddAPIKey("sk-w", "w", nil, KeyStatusActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, InputTokens: 5}); err != nil {
		t.Fatalf("record: %v", err)
	}
	period := cfg.CurrentPeriod(now)
	if !strings.HasPrefix(period, "2026-W") {
		t.Fatalf("period = %q, want ISO week format", period)
	}
	used, err := st.MonthlyUsage(key.KeyHash, period)
	if err != nil || used != 5 {
		t.Fatalf("weekly used = %d err=%v", used, err)
	}
}

func TestResetKeyUsageRestoresQuotaAndKeepsEvents(t *testing.T) {
	st := testStore(t)
	now := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	limit := int64(10)
	key, err := st.AddAPIKey("sk-reset", "reset", &limit, KeyStatusActive, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, OutputTokens: 10}); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetKeyUsage(key.KeyHash, now); err != nil {
		t.Fatalf("reset: %v", err)
	}
	res, err := st.AuthenticateKey("sk-reset", now)
	if err != nil || !res.Allowed {
		t.Fatalf("auth after reset: %+v err=%v", res, err)
	}
	period, err := st.CurrentPeriod(now)
	if err != nil {
		t.Fatal(err)
	}
	used, err := st.MonthlyUsage(key.KeyHash, period)
	if err != nil || used != 0 {
		t.Fatalf("used after reset = %d err=%v", used, err)
	}
	var events int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM usage_events WHERE key_hash = ?`, key.KeyHash).Scan(&events); err != nil || events != 1 {
		t.Fatalf("events = %d err=%v", events, err)
	}
}

func TestUpstreamWeeklyResetAdvancesAllKeysAndPersists(t *testing.T) {
	cfg := config.Default()
	cfg.Quota.Period = config.QuotaPeriodWeekly
	cfg.Usage.Timezone = "UTC"
	cfg.Storage.SQLitePath = filepath.Join(t.TempDir(), "test.sqlite")
	cfg.Secret.SecretFile = filepath.Join(t.TempDir(), "secret")
	st, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	firstLimit, secondLimit := int64(3), int64(4)
	first, _ := st.AddAPIKey("sk-first", "first", &firstLimit, KeyStatusActive, now)
	second, _ := st.AddAPIKey("sk-second", "second", &secondLimit, KeyStatusActive, now)
	_ = st.RecordUsage(UsageEvent{KeyHash: first.KeyHash, Timestamp: now, OutputTokens: 3})
	_ = st.RecordUsage(UsageEvent{KeyHash: second.KeyHash, Timestamp: now, OutputTokens: 4})
	before, err := st.CurrentPeriod(now)
	if err != nil {
		t.Fatal(err)
	}
	boundary := now.Add(time.Hour)
	if err := st.ObserveUpstreamWeeklyReset(boundary, now); err != nil {
		t.Fatal(err)
	}
	stillBefore, _ := st.CurrentPeriod(now.Add(30 * time.Minute))
	if stillBefore != before {
		t.Fatalf("first observation reset period: %q -> %q", before, stillBefore)
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := st.AuthenticateKey("sk-first", boundary)
	if err != nil || !res.Allowed {
		t.Fatalf("auth did not recover at upstream reset: %+v err=%v", res, err)
	}
	after, err := st.CurrentPeriod(boundary)
	if err != nil {
		t.Fatal(err)
	}
	if after == before {
		t.Fatalf("period did not advance: %q", after)
	}
	for _, key := range []APIKey{first, second} {
		used, err := st.MonthlyUsage(key.KeyHash, after)
		if err != nil || used != 0 {
			t.Fatalf("new period usage for %s = %d err=%v", key.DisplayName, used, err)
		}
	}
	again, err := st.CurrentPeriod(boundary.Add(time.Minute))
	if err != nil || again != after {
		t.Fatalf("period advanced twice: got=%q want=%q err=%v", again, after, err)
	}
	if err := st.RecordUsage(UsageEvent{KeyHash: first.KeyHash, Timestamp: boundary.Add(-time.Second), OutputTokens: 2}); err != nil {
		t.Fatal(err)
	}
	newUsage, err := st.MonthlyUsage(first.KeyHash, after)
	if err != nil || newUsage != 0 {
		t.Fatalf("delayed old-cycle usage entered new period: %d err=%v", newUsage, err)
	}
	old, err := st.MonthlyUsage(first.KeyHash, before)
	if err != nil || old != 5 {
		t.Fatalf("old aggregate = %d err=%v", old, err)
	}
}

func TestOpenDBForInMemory(t *testing.T) {

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := OpenDB(db, config.Default(), []byte("secret")); err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
}
