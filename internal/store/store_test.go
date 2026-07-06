package store

import (
	"database/sql"
	"errors"
	"path/filepath"
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
	for _, table := range []string{"api_keys", "usage_events", "monthly_usage", "route_bans"} {
		var name string
		err := st.DB().QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
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
	if err := st.RecordUsage(UsageEvent{KeyHash: key.KeyHash, Timestamp: now, TotalTokens: 10}); err != nil {
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
