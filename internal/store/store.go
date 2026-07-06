package store

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	keyauth "github.com/giraphant/cpa-plugin-usage-quota-guard/internal/auth"
	"github.com/giraphant/cpa-plugin-usage-quota-guard/internal/config"
)

const (
	KeyStatusPending  = "pending"
	KeyStatusActive   = "active"
	KeyStatusDisabled = "disabled"
)

var (
	ErrKeyAlreadyExists = errors.New("api key already exists")
	ErrKeyNotFound      = errors.New("api key not found")
)

type Store struct {
	db     *sql.DB
	cfg    config.Config
	secret []byte
}

type APIKey struct {
	KeyHash           string `json:"key_hash"`
	Fingerprint       string `json:"fingerprint"`
	DisplayName       string `json:"display_name"`
	MonthlyTokenLimit *int64 `json:"monthly_token_limit,omitempty"`
	Status            string `json:"status"`
	FirstSeenAt       string `json:"first_seen_at"`
	LastSeenAt        string `json:"last_seen_at,omitempty"`
	UsedTokens        int64  `json:"used_tokens"`
	RemainingTokens   *int64 `json:"remaining_tokens,omitempty"`
}

type AuthResult struct {
	Allowed     bool
	Reason      string
	KeyHash     string
	Fingerprint string
	DisplayName string
	Status      string
}

type UsageEvent struct {
	RequestID           string
	KeyHash             string
	Timestamp           time.Time
	Month               string
	Provider            string
	Model               string
	AuthID              string
	AuthType            string
	StatusCode          int
	Failed              bool
	ErrorType           string
	InputTokens         int64
	OutputTokens        int64
	ReasoningTokens     int64
	CachedTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64
	TotalTokens         int64
	Stream              bool
	LatencyMS           int64
}

type RouteBan struct {
	TargetKey       string            `json:"target_key"`
	Provider        string            `json:"provider,omitempty"`
	Model           string            `json:"model,omitempty"`
	AuthID          string            `json:"auth_id,omitempty"`
	AuthType        string            `json:"auth_type,omitempty"`
	Reason          string            `json:"reason"`
	StatusCode      int               `json:"status_code,omitempty"`
	BannedAt        time.Time         `json:"banned_at"`
	ExpiresAt       time.Time         `json:"expires_at"`
	UnbannedAt      *time.Time        `json:"unbanned_at,omitempty"`
	UnbanReason     string            `json:"unban_reason,omitempty"`
	SourceRequestID string            `json:"source_request_id,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

func Open(cfg config.Config) (*Store, error) {
	secret, err := loadSecret(cfg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Storage.SQLitePath), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", cfg.Storage.SQLitePath)
	if err != nil {
		return nil, err
	}
	st := &Store{db: db, cfg: cfg, secret: secret}
	if err := st.init(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return st, nil
}

func OpenDB(db *sql.DB, cfg config.Config, secret []byte) (*Store, error) {
	st := &Store{db: db, cfg: cfg, secret: secret}
	if len(st.secret) == 0 {
		st.secret = []byte("test-secret")
	}
	if err := st.init(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) HashKey(rawKey string) string {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(strings.TrimSpace(rawKey)))
	return "hmac_" + hex.EncodeToString(mac.Sum(nil))
}

func (s *Store) AuthenticateKey(rawKey string, now time.Time) (AuthResult, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return AuthResult{Allowed: false, Reason: "missing_key"}, nil
	}
	keyHash := s.HashKey(rawKey)
	fingerprint := keyauth.Fingerprint(rawKey)
	row := s.db.QueryRow(`SELECT fingerprint, display_name, monthly_token_limit, status FROM api_keys WHERE key_hash = ?`, keyHash)
	var fp, displayName, status string
	var limit sql.NullInt64
	err := row.Scan(&fp, &displayName, &limit, &status)
	if errors.Is(err, sql.ErrNoRows) {
		if s.cfg.UnknownKeyRegistration {
			status = KeyStatusPending
			if s.cfg.UnknownKeyAccess == config.UnknownAccessAllow {
				status = KeyStatusActive
			}
			_, err = s.db.Exec(`INSERT INTO api_keys(key_hash, fingerprint, display_name, monthly_token_limit, status, first_seen_at, last_seen_at, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, keyHash, fingerprint, "", s.cfg.DefaultMonthlyTokenLimit, status, ts(now), ts(now), ts(now), ts(now))
			if err != nil {
				return AuthResult{}, err
			}
		}
		if s.cfg.UnknownKeyAccess != config.UnknownAccessAllow {
			return AuthResult{Allowed: false, Reason: "unknown_key", KeyHash: keyHash, Fingerprint: fingerprint, Status: KeyStatusPending}, nil
		}
		return AuthResult{Allowed: true, Reason: "ok", KeyHash: keyHash, Fingerprint: fingerprint, Status: KeyStatusActive}, nil
	}
	if err != nil {
		return AuthResult{}, err
	}
	if status != KeyStatusActive {
		return AuthResult{Allowed: false, Reason: status, KeyHash: keyHash, Fingerprint: fp, DisplayName: displayName, Status: status}, nil
	}
	month := s.cfg.CurrentPeriod(now)
	used, err := s.MonthlyUsage(keyHash, month)
	if err != nil {
		return AuthResult{}, err
	}
	if limit.Valid && used >= limit.Int64 {
		return AuthResult{Allowed: false, Reason: "over_quota", KeyHash: keyHash, Fingerprint: fp, DisplayName: displayName, Status: status}, nil
	}
	_, _ = s.db.Exec(`UPDATE api_keys SET last_seen_at = ?, updated_at = ? WHERE key_hash = ?`, ts(now), ts(now), keyHash)
	return AuthResult{Allowed: true, Reason: "ok", KeyHash: keyHash, Fingerprint: fp, DisplayName: displayName, Status: status}, nil
}

func (s *Store) AddAPIKey(rawKey, displayName string, limit *int64, status string, now time.Time) (APIKey, error) {
	if status == "" {
		status = KeyStatusActive
	}
	keyHash := s.HashKey(rawKey)
	fp := keyauth.Fingerprint(rawKey)
	res, err := s.db.Exec(`INSERT INTO api_keys(key_hash, fingerprint, display_name, monthly_token_limit, status, first_seen_at, last_seen_at, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)
		ON CONFLICT(key_hash) DO NOTHING`,
		keyHash, fp, displayName, limit, status, ts(now), ts(now), ts(now), ts(now))
	if err != nil {
		return APIKey{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return APIKey{}, ErrKeyAlreadyExists
	}
	return s.GetAPIKey(keyHash, s.cfg.CurrentPeriod(now))
}

func (s *Store) DeleteAPIKey(keyHash string) error {
	res, err := s.db.Exec(`DELETE FROM api_keys WHERE key_hash = ?`, keyHash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrKeyNotFound
	}
	return nil
}

func (s *Store) UpdateAPIKey(keyHash, displayName string, limit *int64, status string, now time.Time) (APIKey, error) {
	_, err := s.db.Exec(`UPDATE api_keys SET display_name = COALESCE(NULLIF(?, ''), display_name), monthly_token_limit = ?, status = COALESCE(NULLIF(?, ''), status), updated_at = ? WHERE key_hash = ?`, displayName, limit, status, ts(now), keyHash)
	if err != nil {
		return APIKey{}, err
	}
	return s.GetAPIKey(keyHash, s.cfg.CurrentPeriod(now))
}

func (s *Store) GetAPIKey(keyHash, month string) (APIKey, error) {
	var key APIKey
	var limit sql.NullInt64
	var last sql.NullString
	err := s.db.QueryRow(`SELECT key_hash, fingerprint, display_name, monthly_token_limit, status, first_seen_at, last_seen_at FROM api_keys WHERE key_hash = ?`, keyHash).Scan(&key.KeyHash, &key.Fingerprint, &key.DisplayName, &limit, &key.Status, &key.FirstSeenAt, &last)
	if err != nil {
		return APIKey{}, err
	}
	if limit.Valid {
		key.MonthlyTokenLimit = &limit.Int64
	}
	if last.Valid {
		key.LastSeenAt = last.String
	}
	key.UsedTokens, _ = s.MonthlyUsage(keyHash, month)
	if key.MonthlyTokenLimit != nil {
		remaining := *key.MonthlyTokenLimit - key.UsedTokens
		if remaining < 0 {
			remaining = 0
		}
		key.RemainingTokens = &remaining
	}
	return key, nil
}

func (s *Store) ListAPIKeys(month string) ([]APIKey, error) {
	rows, err := s.db.Query(`SELECT key_hash FROM api_keys ORDER BY COALESCE(last_seen_at, first_seen_at) DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var keyHash string
		if err := rows.Scan(&keyHash); err != nil {
			return nil, err
		}
		key, err := s.GetAPIKey(keyHash, month)
		if err != nil {
			return nil, err
		}
		out = append(out, key)
	}
	return out, rows.Err()
}

func (s *Store) MonthlyUsage(keyHash, month string) (int64, error) {
	var used sql.NullInt64
	err := s.db.QueryRow(`SELECT total_tokens FROM monthly_usage WHERE key_hash = ? AND month = ?`, keyHash, month).Scan(&used)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if !used.Valid {
		return 0, nil
	}
	return used.Int64, nil
}

func (s *Store) RecordUsage(event UsageEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	if event.Month == "" {
		event.Month = s.cfg.CurrentPeriod(event.Timestamp)
	}
	if event.TotalTokens == 0 {
		event.TotalTokens = event.InputTokens + event.OutputTokens + event.ReasoningTokens
	}
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO usage_events(request_id,key_hash,ts,month,provider,model,auth_id,auth_type,status_code,failed,error_type,input_tokens,output_tokens,reasoning_tokens,cached_tokens,cache_read_tokens,cache_creation_tokens,total_tokens,stream,latency_ms)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, event.RequestID, event.KeyHash, ts(event.Timestamp), event.Month, event.Provider, event.Model, event.AuthID, event.AuthType, event.StatusCode, boolInt(event.Failed), event.ErrorType, event.InputTokens, event.OutputTokens, event.ReasoningTokens, event.CachedTokens, event.CacheReadTokens, event.CacheCreationTokens, event.TotalTokens, boolInt(event.Stream), event.LatencyMS)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO monthly_usage(key_hash, month, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, total_tokens, request_count, error_count, last_event_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(key_hash, month) DO UPDATE SET input_tokens=input_tokens+excluded.input_tokens, output_tokens=output_tokens+excluded.output_tokens, cache_read_tokens=cache_read_tokens+excluded.cache_read_tokens, cache_write_tokens=cache_write_tokens+excluded.cache_write_tokens, total_tokens=total_tokens+excluded.total_tokens, request_count=request_count+1, error_count=error_count+excluded.error_count, last_event_at=excluded.last_event_at, updated_at=excluded.updated_at`,
		event.KeyHash, event.Month, event.InputTokens, event.OutputTokens, event.CacheReadTokens, event.CacheCreationTokens, event.TotalTokens, 1, boolInt(event.Failed), ts(event.Timestamp), ts(time.Now()))
	if err != nil {
		return err
	}
	_, _ = tx.Exec(`UPDATE api_keys SET last_seen_at = ?, updated_at = ? WHERE key_hash = ?`, ts(event.Timestamp), ts(time.Now()), event.KeyHash)
	return tx.Commit()
}

func (s *Store) PruneUsageEvents(before time.Time) error {
	_, err := s.db.Exec(`DELETE FROM usage_events WHERE ts < ?`, ts(before))
	return err
}

func (s *Store) AddOrExtendBan(ban RouteBan) error {
	if ban.TargetKey == "" {
		return errors.New("target key is required")
	}
	if ban.BannedAt.IsZero() {
		ban.BannedAt = time.Now()
	}
	_, err := s.db.Exec(`INSERT INTO route_bans(target_key,provider,model,auth_id,auth_type,reason,status_code,banned_at,expires_at,source_request_id,metadata_json)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`, ban.TargetKey, ban.Provider, ban.Model, ban.AuthID, ban.AuthType, ban.Reason, ban.StatusCode, ts(ban.BannedAt), ts(ban.ExpiresAt), ban.SourceRequestID, metadataString(ban.Metadata))
	return err
}

func (s *Store) ActiveBan(targetKey string, now time.Time) (RouteBan, bool, error) {
	row := s.db.QueryRow(`SELECT target_key, provider, model, auth_id, auth_type, reason, status_code, banned_at, expires_at, source_request_id FROM route_bans WHERE target_key = ? AND unbanned_at IS NULL AND expires_at > ? ORDER BY expires_at DESC LIMIT 1`, targetKey, ts(now))
	ban, err := scanBan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return RouteBan{}, false, nil
	}
	if err != nil {
		return RouteBan{}, false, err
	}
	return ban, true, nil
}

func (s *Store) ListRouteBans(activeOnly bool, now time.Time) ([]RouteBan, error) {
	query := `SELECT target_key, provider, model, auth_id, auth_type, reason, status_code, banned_at, expires_at, source_request_id FROM route_bans`
	args := []any{}
	if activeOnly {
		query += ` WHERE unbanned_at IS NULL AND expires_at > ?`
		args = append(args, ts(now))
	}
	query += ` ORDER BY banned_at DESC LIMIT 200`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RouteBan
	for rows.Next() {
		ban, err := scanBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ban)
	}
	return out, rows.Err()
}

func (s *Store) UnbanRoute(targetKey, reason string, now time.Time) error {
	if reason == "" {
		reason = "manual"
	}
	_, err := s.db.Exec(`UPDATE route_bans SET unbanned_at = ?, unban_reason = ? WHERE target_key = ? AND unbanned_at IS NULL`, ts(now), reason, targetKey)
	return err
}

func (s *Store) init() error {
	if _, err := s.db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;`); err != nil {
		return err
	}
	for _, stmt := range migrations {
		if _, err := s.db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

var migrations = []string{
	`CREATE TABLE IF NOT EXISTS api_keys (key_hash TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, display_name TEXT NOT NULL DEFAULT '', monthly_token_limit INTEGER NULL, status TEXT NOT NULL DEFAULT 'pending', first_seen_at TEXT NOT NULL, last_seen_at TEXT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);`,
	`CREATE TABLE IF NOT EXISTS usage_events (id INTEGER PRIMARY KEY AUTOINCREMENT, request_id TEXT, key_hash TEXT NOT NULL, ts TEXT NOT NULL, month TEXT NOT NULL, provider TEXT, model TEXT, auth_id TEXT, auth_type TEXT, status_code INTEGER, failed INTEGER NOT NULL DEFAULT 0, error_type TEXT, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, reasoning_tokens INTEGER NOT NULL DEFAULT 0, cached_tokens INTEGER NOT NULL DEFAULT 0, cache_read_tokens INTEGER NOT NULL DEFAULT 0, cache_creation_tokens INTEGER NOT NULL DEFAULT 0, total_tokens INTEGER NOT NULL DEFAULT 0, stream INTEGER NOT NULL DEFAULT 0, latency_ms INTEGER);`,
	`CREATE TABLE IF NOT EXISTS monthly_usage (key_hash TEXT NOT NULL, month TEXT NOT NULL, input_tokens INTEGER NOT NULL DEFAULT 0, output_tokens INTEGER NOT NULL DEFAULT 0, cache_read_tokens INTEGER NOT NULL DEFAULT 0, cache_write_tokens INTEGER NOT NULL DEFAULT 0, total_tokens INTEGER NOT NULL DEFAULT 0, request_count INTEGER NOT NULL DEFAULT 0, error_count INTEGER NOT NULL DEFAULT 0, last_event_at TEXT, updated_at TEXT NOT NULL, PRIMARY KEY (key_hash, month));`,
	`CREATE TABLE IF NOT EXISTS route_bans (id INTEGER PRIMARY KEY AUTOINCREMENT, target_key TEXT NOT NULL, provider TEXT, model TEXT, auth_id TEXT, auth_type TEXT, reason TEXT NOT NULL, status_code INTEGER, banned_at TEXT NOT NULL, expires_at TEXT NOT NULL, unbanned_at TEXT NULL, unban_reason TEXT NULL, source_request_id TEXT NULL, metadata_json TEXT NULL);`,
	`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);`,
	`CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status);`,
	`CREATE INDEX IF NOT EXISTS idx_api_keys_last_seen ON api_keys(last_seen_at);`,
	`CREATE INDEX IF NOT EXISTS idx_usage_events_key_ts ON usage_events(key_hash, ts);`,
	`CREATE INDEX IF NOT EXISTS idx_usage_events_ts ON usage_events(ts);`,
	`CREATE INDEX IF NOT EXISTS idx_usage_events_month ON usage_events(month);`,
	`CREATE INDEX IF NOT EXISTS idx_monthly_usage_month_tokens ON monthly_usage(month, total_tokens);`,
	`CREATE INDEX IF NOT EXISTS idx_route_bans_target_active ON route_bans(target_key, unbanned_at, expires_at);`,
	`CREATE INDEX IF NOT EXISTS idx_route_bans_expires ON route_bans(expires_at);`,
}

func loadSecret(cfg config.Config) ([]byte, error) {
	if cfg.Secret.SecretEnv != "" {
		if value := os.Getenv(cfg.Secret.SecretEnv); value != "" {
			return []byte(value), nil
		}
	}
	if cfg.Secret.SecretFile == "" {
		return nil, errors.New("secret file is required")
	}
	if raw, err := os.ReadFile(cfg.Secret.SecretFile); err == nil && len(strings.TrimSpace(string(raw))) > 0 {
		return []byte(strings.TrimSpace(string(raw))), nil
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Secret.SecretFile), 0o700); err != nil {
		return nil, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	encoded := hex.EncodeToString(buf)
	if err := os.WriteFile(cfg.Secret.SecretFile, []byte(encoded), 0o600); err != nil {
		return nil, err
	}
	return []byte(encoded), nil
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func metadataString(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	parts := make([]string, 0, len(m))
	for k, v := range m {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, ";")
}

type scanner interface{ Scan(dest ...any) error }

func scanBan(row scanner) (RouteBan, error) {
	var ban RouteBan
	var bannedAt, expiresAt string
	err := row.Scan(&ban.TargetKey, &ban.Provider, &ban.Model, &ban.AuthID, &ban.AuthType, &ban.Reason, &ban.StatusCode, &bannedAt, &expiresAt, &ban.SourceRequestID)
	if err != nil {
		return RouteBan{}, err
	}
	ban.BannedAt, _ = time.Parse(time.RFC3339Nano, bannedAt)
	ban.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiresAt)
	return ban, nil
}

func StatusFromHTTP(status int) string {
	if status == 0 {
		return ""
	}
	return http.StatusText(status)
}
