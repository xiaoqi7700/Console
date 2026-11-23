package vault

// 凭据保险库（v0.7.1）：加密存储站点/主机上拿到的账号、token、密钥。
//
// 设计目标：
//   - 落库即加密（XChaCha20-Poly1305），主密钥在 data/vault.key（0600），
//     也可用环境变量 POJUN_VAULT_KEY（32 字节 hex/base64）覆盖；
//   - API/工具默认只返回掩码，取明文必须显式 reveal 并写审计；
//   - 按任务隔离：worker 只能看本任务或全局（task_id=0）的凭据；
//   - 记录 admin/root 等级别，便于攻击链判断“这条凭据能做什么”。

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/Autumn-27/artex/db"
)

var aad = []byte("pojun-vault-v1")

type Store struct {
	key []byte
	pg  *db.DB
}

// Item 是凭据的元数据；Secret 只在 Get/Reveal 时填充。
type Item struct {
	ID         int64           `json:"id"`
	TaskID     int64           `json:"task_id,omitempty"`
	AssetID    int64           `json:"asset_id,omitempty"`
	Kind       string          `json:"kind"`
	Username   string          `json:"username,omitempty"`
	Secret     string          `json:"secret,omitempty"`
	SecretHint string          `json:"secret_hint,omitempty"`
	Privilege  string          `json:"privilege,omitempty"`
	Meta       json.RawMessage `json:"meta,omitempty"`
	ExpiresAt  *time.Time      `json:"expires_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	LastUsedAt *time.Time      `json:"last_used_at,omitempty"`
}

type SaveInput struct {
	TaskID    int64
	AssetID   int64
	Kind      string
	Username  string
	Secret    string
	Privilege string
	Note      string
	Meta      json.RawMessage
	ExpiresAt *time.Time
}

type AuditEntry struct {
	ID           int64     `json:"id"`
	CredentialID int64     `json:"credential_id"`
	TaskID       int64     `json:"task_id,omitempty"`
	IntentID     int64     `json:"intent_id,omitempty"`
	Actor        string    `json:"actor"`
	Action       string    `json:"action"`
	At           time.Time `json:"at"`
}

func Open(keyDir, dataDir string, pg *db.DB) (*Store, error) {
	key, err := loadKey(keyDir, dataDir)
	if err != nil {
		return nil, err
	}
	s := &Store{key: key, pg: pg}
	if pg != nil {
		if err := s.ensureSchema(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func loadKey(keyDir, dataDir string) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv("POJUN_VAULT_KEY")); raw != "" {
		if b, err := hex.DecodeString(raw); err == nil && len(b) == chacha20poly1305.KeySize {
			return b, nil
		}
		if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == chacha20poly1305.KeySize {
			return b, nil
		}
		return nil, fmt.Errorf("POJUN_VAULT_KEY 必须是 %d 字节的 hex/base64", chacha20poly1305.KeySize)
	}
	if keyDir == "" {
		keyDir = dataDir
	}
	if keyDir == "" {
		return nil, errors.New("vault: keyDir 为空")
	}
	path := filepath.Join(keyDir, "vault.key")
	// 旧版本把主密钥放在可浏览的 data 目录，工作区接口能下载/删除它。
	// 启动时迁移到 keyDir（与 jwt.key 同级），并删除旧文件（v0.7.6）。
	if legacy := filepath.Join(dataDir, "vault.key"); dataDir != "" && legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if b, rerr := os.ReadFile(legacy); rerr == nil && len(b) >= chacha20poly1305.KeySize {
				if werr := os.WriteFile(path, b[:chacha20poly1305.KeySize], 0o600); werr == nil {
					_ = os.Remove(legacy)
				}
			}
		}
	}
	if b, err := os.ReadFile(path); err == nil && len(b) >= chacha20poly1305.KeySize {
		return b[:chacha20poly1305.KeySize], nil
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func (s *Store) ensureSchema() error {
	_, err := s.pg.Exec(`
CREATE TABLE IF NOT EXISTS credentials (
  id BIGSERIAL PRIMARY KEY,
  task_id BIGINT NOT NULL DEFAULT 0,
  asset_id BIGINT NOT NULL DEFAULT 0,
  kind TEXT NOT NULL,
  username TEXT NOT NULL DEFAULT '',
  secret_enc BYTEA NOT NULL,
  secret_hint TEXT NOT NULL DEFAULT '',
  privilege TEXT NOT NULL DEFAULT '',
  meta JSONB NOT NULL DEFAULT '{}',
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_credentials_task ON credentials(task_id, asset_id);
CREATE TABLE IF NOT EXISTS credential_access_log (
  id BIGSERIAL PRIMARY KEY,
  credential_id BIGINT NOT NULL,
  task_id BIGINT NOT NULL DEFAULT 0,
  intent_id BIGINT NOT NULL DEFAULT 0,
  actor TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_credential_audit ON credential_access_log(credential_id, at DESC);`)
	return err
}

func (s *Store) encrypt(plain string) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(plain), aad), nil
}

func (s *Store) decrypt(blob []byte) (string, error) {
	aead, err := chacha20poly1305.NewX(s.key)
	if err != nil {
		return "", err
	}
	if len(blob) < aead.NonceSize() {
		return "", errors.New("vault: 密文长度非法")
	}
	nonce, ct := blob[:aead.NonceSize()], blob[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return "", errors.New("vault: 解密失败（主密钥不匹配？）")
	}
	return string(plain), nil
}

func maskSecret(s string) string {
	r := []rune(s)
	switch {
	case len(r) == 0:
		return ""
	case len(r) <= 4:
		return "****"
	default:
		return "****" + string(r[len(r)-2:])
	}
}

func normalizeKind(k string) string {
	k = strings.ToLower(strings.TrimSpace(k))
	switch k {
	case "password", "pass", "pwd":
		return "password"
	case "token", "jwt", "bearer", "cookie", "session":
		return "token"
	case "key", "ssh", "private_key", "cloud_ak", "ak":
		return "key"
	case "hash", "ntlm":
		return "hash"
	default:
		if k == "" {
			return "password"
		}
		return k
	}
}

func normalizePrivilege(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "admin", "administrator":
		return "admin"
	case "root", "system", "sa":
		return "root"
	case "user", "normal":
		return "user"
	default:
		return p
	}
}

func (s *Store) Save(ctx context.Context, in SaveInput, actor string) (int64, error) {
	if strings.TrimSpace(in.Secret) == "" {
		return 0, errors.New("secret 不能为空")
	}
	enc, err := s.encrypt(in.Secret)
	if err != nil {
		return 0, err
	}
	meta := in.Meta
	if len(meta) == 0 {
		meta = json.RawMessage(`{}`)
	}
	if note := strings.TrimSpace(in.Note); note != "" {
		m := map[string]any{}
		_ = json.Unmarshal(meta, &m)
		m["note"] = note
		if b, err := json.Marshal(m); err == nil {
			meta = b
		}
	}
	var id int64
	err = s.pg.QueryRowContext(ctx, `
INSERT INTO credentials(task_id,asset_id,kind,username,secret_enc,secret_hint,privilege,meta,expires_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		in.TaskID, in.AssetID, normalizeKind(in.Kind), strings.TrimSpace(in.Username),
		enc, maskSecret(in.Secret), normalizePrivilege(in.Privilege), meta, in.ExpiresAt).Scan(&id)
	if err != nil {
		return 0, err
	}
	_, _ = s.pg.ExecContext(ctx,
		`INSERT INTO credential_access_log(credential_id,task_id,actor,action) VALUES($1,$2,$3,'save')`,
		id, in.TaskID, actor)
	return id, nil
}

// List 返回掩码元数据；taskID>0 时看本任务与全局，taskID=0 只看全局，
// taskID<0 表示管理端全量（不按任务过滤）。
func (s *Store) List(ctx context.Context, taskID, assetID int64, kind string) ([]Item, error) {
	q := `SELECT id,task_id,asset_id,kind,username,secret_hint,privilege,meta,expires_at,created_at,last_used_at
FROM credentials WHERE 1=1`
	args := []any{}
	switch {
	case taskID > 0:
		args = append(args, taskID)
		q += fmt.Sprintf(" AND (task_id=$%d OR task_id=0)", len(args))
	case taskID == 0:
		q += " AND task_id=0"
	}
	if assetID > 0 {
		args = append(args, assetID)
		q += fmt.Sprintf(" AND asset_id=$%d", len(args))
	}
	if k := strings.TrimSpace(kind); k != "" {
		args = append(args, normalizeKind(k))
		q += fmt.Sprintf(" AND kind=$%d", len(args))
	}
	q += " ORDER BY id DESC LIMIT 500"
	rows, err := s.pg.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Item{}
	for rows.Next() {
		var it Item
		var meta []byte
		var exp, used sql.NullTime
		if err := rows.Scan(&it.ID, &it.TaskID, &it.AssetID, &it.Kind, &it.Username,
			&it.SecretHint, &it.Privilege, &meta, &exp, &it.CreatedAt, &used); err != nil {
			return nil, err
		}
		it.Meta = meta
		if exp.Valid {
			t := exp.Time
			it.ExpiresAt = &t
		}
		if used.Valid {
			t := used.Time
			it.LastUsedAt = &t
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ListByHost 按站点（域名/IP）查询凭据：匹配资产的 domain / root_domain / ip /
// bound_domains，以及凭据 meta 里显式记录的 host。返回掩码元数据，不含明文。
//
// 任务语义与 List 一致：taskID>0 看本任务与全局，taskID=0 只看全局，
// taskID<0 为管理端全量。
func (s *Store) ListByHost(ctx context.Context, taskID int64, host, kind string) ([]Item, error) {
	h := normalizeHost(host)
	if h == "" {
		return nil, errors.New("vault: host 为空")
	}
	q := `SELECT c.id,c.task_id,c.asset_id,c.kind,c.username,c.secret_hint,c.privilege,c.meta,c.expires_at,c.created_at,c.last_used_at
FROM credentials c
LEFT JOIN assets a ON a.id = c.asset_id
WHERE (
    lower(COALESCE(a.domain,'')) = $1
 OR lower(COALESCE(a.root_domain,'')) = $1
 OR COALESCE(a.ip,'') = $1
 OR $1 = ANY(a.bound_domains)
 OR lower(COALESCE(a.domain,'')) LIKE '%.' || $1
 OR lower(COALESCE(c.meta->>'host','')) = $1
)`
	args := []any{h}
	switch {
	case taskID > 0:
		args = append(args, taskID)
		q += fmt.Sprintf(" AND (c.task_id=$%d OR c.task_id=0)", len(args))
	case taskID == 0:
		q += " AND c.task_id=0"
	}
	if k := strings.TrimSpace(kind); k != "" {
		args = append(args, normalizeKind(k))
		q += fmt.Sprintf(" AND c.kind=$%d", len(args))
	}
	q += " ORDER BY c.id DESC LIMIT 500"
	rows, err := s.pg.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Item{}
	for rows.Next() {
		var it Item
		var meta []byte
		var exp, used sql.NullTime
		if err := rows.Scan(&it.ID, &it.TaskID, &it.AssetID, &it.Kind, &it.Username,
			&it.SecretHint, &it.Privilege, &meta, &exp, &it.CreatedAt, &used); err != nil {
			return nil, err
		}
		it.Meta = meta
		if exp.Valid {
			t := exp.Time
			it.ExpiresAt = &t
		}
		if used.Valid {
			t := used.Time
			it.LastUsedAt = &t
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// normalizeHost 从 URL / 带端口的主机里取出小写主机名。
func normalizeHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

func (s *Store) Get(ctx context.Context, id int64, taskID int64) (*Item, error) {
	q := `SELECT id,task_id,asset_id,kind,username,secret_enc,secret_hint,privilege,meta,expires_at,created_at,last_used_at
FROM credentials WHERE id=$1`
	args := []any{id}
	// taskID >= 0：只允许本任务或全局（task_id=0）条目；taskID < 0 才是管理员
	// 全量读取。旧实现用 0 表示"不过滤"，导致 taskID=0 的 auto/custom agent
	// 能按 id 枚举任意任务明文（v0.7.6）。
	if taskID >= 0 {
		q += " AND (task_id=$2 OR task_id=0)"
		args = append(args, taskID)
	}
	var it Item
	var enc, meta []byte
	var exp, used sql.NullTime
	err := s.pg.QueryRowContext(ctx, q, args...).Scan(&it.ID, &it.TaskID, &it.AssetID, &it.Kind,
		&it.Username, &enc, &it.SecretHint, &it.Privilege, &meta, &exp, &it.CreatedAt, &used)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	plain, err := s.decrypt(enc)
	if err != nil {
		return nil, err
	}
	it.Secret = plain
	it.Meta = meta
	if exp.Valid {
		t := exp.Time
		it.ExpiresAt = &t
	}
	if used.Valid {
		t := used.Time
		it.LastUsedAt = &t
	}
	return &it, nil
}

func (s *Store) Touch(ctx context.Context, id, taskID, intentID int64, actor string) {
	_, _ = s.pg.ExecContext(ctx, `UPDATE credentials SET last_used_at=now() WHERE id=$1`, id)
	_, _ = s.pg.ExecContext(ctx,
		`INSERT INTO credential_access_log(credential_id,task_id,intent_id,actor,action) VALUES($1,$2,$3,$4,'use')`,
		id, taskID, intentID, actor)
}

func (s *Store) Reveal(ctx context.Context, id, taskID int64, actor string) (*Item, error) {
	it, err := s.Get(ctx, id, taskID)
	if err != nil || it == nil {
		return it, err
	}
	_, _ = s.pg.ExecContext(ctx,
		`INSERT INTO credential_access_log(credential_id,task_id,actor,action) VALUES($1,$2,$3,'reveal')`,
		id, taskID, actor)
	return it, nil
}

func (s *Store) Delete(ctx context.Context, id int64, actor string) error {
	res, err := s.pg.ExecContext(ctx, `DELETE FROM credentials WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	_, _ = s.pg.ExecContext(ctx,
		`INSERT INTO credential_access_log(credential_id,task_id,actor,action) VALUES($1,0,$2,'delete')`,
		id, actor)
	return nil
}

func (s *Store) Audit(ctx context.Context, credentialID int64, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pg.QueryContext(ctx, `
SELECT id,credential_id,task_id,intent_id,actor,action,at FROM credential_access_log
WHERE credential_id=$1 ORDER BY id DESC LIMIT $2`, credentialID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.CredentialID, &e.TaskID, &e.IntentID, &e.Actor, &e.Action, &e.At); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
