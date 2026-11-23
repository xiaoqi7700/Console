package traffic

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Offline identity scan (issue #40).
//
// ScanIdentity walks the traffic index with a keyset cursor, reads captured
// request/response heads and bodies, and counts literal A/B/C wordlist hits per
// host. It is strictly read-only and never opens a proxy: the index is opened
// with a mode=ro + query_only DSN, blobs are opened from the traffic directory,
// and no network call is made.
//
// The index is a global capture store with no task column, so per-task output is
// an optional external aggregation via Options.TaskMap (host -> task IDs). The
// report states that limitation instead of inventing attribution.

const (
	IdentitySchemaVersion        = 1
	IdentityNormalizationVersion = "ascii-fold-v1"
	identityFindingsCap          = 200
	identitySamplesCap           = 500
	identitySamplesPerHostList   = 3
	identityDefaultBatch         = 200
	// IdentityDefaultMaxBodyBytes covers every body the recorder can store:
	// go-mitmproxy streams (and the recorder therefore skips) a body once it
	// reaches its 5 MiB StreamLargeBodies threshold, so recorded bodies are
	// always smaller than 5 MiB.
	IdentityDefaultMaxBodyBytes = 5 << 20
)

// IdentityScanOptions configures an offline scan.
type IdentityScanOptions struct {
	// DBPath points at index.sqlite directly; DataDir is the deployment data
	// directory (index at <DataDir>/traffic/_index/index.sqlite).
	DBPath string
	// TrafficDir is the recorder directory holding _blobs; it defaults to the
	// parent of _index when the index lives at the standard path.
	TrafficDir string
	DataDir    string

	Lexicon      *IdentityLexicon
	Allowlist    *IdentityAllowlist
	Tiers        []string
	Hosts        []string
	Since        int64
	Until        int64
	Limit        int
	Batch        int
	MaxBodyBytes int64
	TaskMap      map[string][]int64
	Now          func() time.Time
}

// IdentityDBInfo records which index was scanned and how it was opened.
type IdentityDBInfo struct {
	Path       string `json:"path"`
	Mode       string `json:"mode"`
	TrafficDir string `json:"traffic_dir,omitempty"`
}

// IdentityLexiconInfo records the wordlist generation used for a report.
type IdentityLexiconInfo struct {
	Version string         `json:"version"`
	Source  string         `json:"source"`
	Counts  map[string]int `json:"counts"`
}

// IdentityScanStats counts work done, independent of coverage.
type IdentityScanStats struct {
	Rows           int64 `json:"rows"`
	Batches        int64 `json:"batches"`
	Scanned        int64 `json:"scanned"`
	Truncated      bool  `json:"truncated"`
	BinarySkipped  int64 `json:"binary_skipped"`
	BlobMissing    int64 `json:"blob_missing"`
	BodyMissing    int64 `json:"body_missing"`
	LegacyRows     int64 `json:"legacy_rows"`
	DurationMillis int64 `json:"duration_ms"`
}

// IdentityExcluded breaks down rows that cannot be evaluated for capture
// coverage. Their sum plus Eligible and LegacyRows equals Total.
type IdentityExcluded struct {
	HEAD             int64 `json:"head"`
	Informational1xx int64 `json:"informational_1xx"`
	NoContent        int64 `json:"no_content_204_205"`
	NotModified304   int64 `json:"not_modified_304"`
	FailedStatus0    int64 `json:"failed_status0"`
}

// IdentityCoverage separates "what the recorder captured" from "what this scan
// could read". Both are reported; neither is presented as target-side truth.
type IdentityCoverage struct {
	Total           int64            `json:"total"`
	Eligible        int64            `json:"eligible"`
	Excluded        IdentityExcluded `json:"excluded"`
	WithBody        int64            `json:"with_body"`
	RequestCapture  int64            `json:"request_capture"`
	ResponseCapture int64            `json:"response_capture"`
	CaptureCoverage float64          `json:"capture_coverage"`
	ScanCoverage    float64          `json:"scan_coverage"`
	BodyTruncated   int64            `json:"body_truncated"`
	BodyBytesRead   int64            `json:"body_bytes_read"`
	LegacyRows      int64            `json:"legacy_rows"`
}

// IdentityListStat aggregates one wordlist across all hosts.
type IdentityListStat struct {
	Hits      int64 `json:"hits"`
	Exchanges int64 `json:"exchanges"`
	Findings  int64 `json:"findings"`
}

// IdentitySample is one redacted hit context.
type IdentitySample struct {
	ExchangeID string `json:"exchange_id"`
	TS         int64  `json:"ts"`
	Host       string `json:"host"`
	List       string `json:"list"`
	TermID     string `json:"term_id"`
	Where      string `json:"where"`
	Offset     int    `json:"offset"`
	Snippet    string `json:"snippet"`
}

// IdentityFinding is a promoted hit: any A hit, or >=2 distinct B terms in one
// exchange. C never produces a finding.
type IdentityFinding struct {
	ExchangeID string   `json:"exchange_id"`
	TS         int64    `json:"ts"`
	Host       string   `json:"host"`
	List       string   `json:"list"`
	TermID     string   `json:"term_id"`
	Terms      []string `json:"terms,omitempty"`
	Where      string   `json:"where"`
	Offset     int      `json:"offset"`
	Snippet    string   `json:"snippet"`
	Severity   string   `json:"severity"`
}

// IdentityHostStat is per-host counts. Hits counts distinct (term, exchange)
// pairs; Rules lists the term IDs seen.
type IdentityHostStat struct {
	Host      string           `json:"host"`
	Exchanges int64            `json:"exchanges"`
	Eligible  int64            `json:"eligible"`
	WithBody  int64            `json:"with_body"`
	Hits      map[string]int64 `json:"hits"`
	Findings  int64            `json:"findings"`
	Rules     []string         `json:"rules,omitempty"`
	Samples   []IdentitySample `json:"samples,omitempty"`
}

// IdentityTaskStat is an external host->task aggregation.
type IdentityTaskStat struct {
	TaskID   int64            `json:"task_id"`
	Hosts    []string         `json:"hosts"`
	Shared   bool             `json:"shared"`
	Hits     map[string]int64 `json:"hits"`
	Findings int64            `json:"findings"`
}

// IdentitySuppressedRule records one allowlist rule that fired.
type IdentitySuppressedRule struct {
	TermID string `json:"term_id,omitempty"`
	Host   string `json:"host,omitempty"`
	Reason string `json:"reason"`
	Count  int64  `json:"count"`
}

// IdentitySuppressed records allowlisted hits without silently dropping them.
type IdentitySuppressed struct {
	ByAllowlist int64                    `json:"by_allowlist"`
	Rules       []IdentitySuppressedRule `json:"rules,omitempty"`
}

// IdentityReport is the machine-readable output of ScanIdentity.
type IdentityReport struct {
	SchemaVersion        int                         `json:"schema_version"`
	GeneratedAt          time.Time                   `json:"generated_at"`
	DB                   IdentityDBInfo              `json:"db"`
	Lexicon              IdentityLexiconInfo         `json:"lexicon"`
	NormalizationVersion string                      `json:"normalization_version"`
	Scan                 IdentityScanStats           `json:"scan"`
	Coverage             IdentityCoverage            `json:"coverage"`
	Lists                map[string]IdentityListStat `json:"lists"`
	Hosts                []IdentityHostStat          `json:"hosts"`
	Tasks                []IdentityTaskStat          `json:"tasks,omitempty"`
	UnmappedHosts        []string                    `json:"unmapped_hosts,omitempty"`
	Samples              []IdentitySample            `json:"samples"`
	Findings             []IdentityFinding           `json:"findings"`
	FindingsTotal        int64                       `json:"findings_total"`
	Suppressed           IdentitySuppressed          `json:"suppressed"`
	Warnings             []string                    `json:"warnings"`
	Notes                []string                    `json:"notes"`
}

type identityRow struct {
	rowid       int64
	id          string
	ts          int64
	host        string
	method      string
	urlTemplate string
	url         string
	status      int
	contentType string
	reqLen      int64
	respLen     int64
	path        string
}

type identityBodyRow struct {
	reqHead  string
	reqBody  []byte
	reqBlob  sql.NullString
	respHead string
	respBody []byte
	respBlob sql.NullString
}

type identityHitRecord struct {
	term   IdentityTerm
	where  string
	offset int
	text   string
}

// OpenIndexReadOnly opens a traffic index SQLite file without creating it and
// without any of traffic.Open's side effects (mkdir, proxy, CA generation).
func OpenIndexReadOnly(path string) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("流量索引不存在或不可读：%w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("流量索引路径是目录：%s", abs)
	}
	// Build a file: URI rather than a bare path: modernc.org/sqlite opens bare
	// paths with READWRITE|CREATE, which would create an empty database when the
	// path is wrong. The leading slash keeps Windows drive letters out of the
	// URI authority (file:///C:/... rather than file://C:/...).
	p := filepath.ToSlash(abs)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	u := url.URL{Scheme: "file", Path: p, RawQuery: q.Encode()}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("只读打开流量索引失败（WAL 库需要 -wal/-shm 可读或目录可写；可把 index.sqlite、-wal、-shm 一并复制到可写临时目录后用 --db 指向）：%w", err)
	}
	var queryOnly int
	if err := db.QueryRowContext(ctx, `PRAGMA query_only`).Scan(&queryOnly); err != nil {
		db.Close()
		return nil, fmt.Errorf("检查只读模式失败：%w", err)
	}
	if queryOnly != 1 {
		db.Close()
		return nil, errors.New("流量索引未以 query_only=1 打开，拒绝继续")
	}
	rows, err := db.QueryContext(ctx, `PRAGMA database_list`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("检查数据库列表失败：%w", err)
	}
	var names []string
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			rows.Close()
			db.Close()
			return nil, err
		}
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		db.Close()
		return nil, err
	}
	if len(names) != 1 || names[0] != "main" {
		db.Close()
		return nil, fmt.Errorf("流量索引附加了非 main 数据库：%v", names)
	}
	if err := identityValidateSchema(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func identityValidateSchema(ctx context.Context, db *sql.DB) error {
	required := []struct {
		table string
		cols  []string
	}{
		{"exchanges", []string{"id", "ts", "host", "method", "url_template", "url", "status", "content_type", "req_len", "resp_len", "path"}},
		{"exchange_bodies", []string{"id", "req_head", "req_body", "req_blob", "resp_head", "resp_body", "resp_blob"}},
	}
	for _, want := range required {
		rows, err := db.QueryContext(ctx, `PRAGMA table_info(`+want.table+`)`)
		if err != nil {
			return fmt.Errorf("读取表结构 %s 失败：%w", want.table, err)
		}
		have := map[string]bool{}
		for rows.Next() {
			var cid, notNull, pk int
			var name, typ string
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
				rows.Close()
				return err
			}
			have[name] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(have) == 0 {
			return fmt.Errorf("流量索引缺少表 %s", want.table)
		}
		for _, col := range want.cols {
			if !have[col] {
				return fmt.Errorf("流量索引表 %s 缺少列 %s", want.table, col)
			}
		}
	}
	return nil
}

// ScanIdentity runs one offline scan. It returns an error before doing any work
// if the index cannot be opened strictly read-only.
func ScanIdentity(ctx context.Context, opt IdentityScanOptions) (*IdentityReport, error) {
	started := time.Now()
	var lex *IdentityLexicon
	source := "file"
	if opt.Lexicon == nil {
		lex = BuiltinLexicon()
		source = "builtin"
	} else {
		// Validate a private copy: validate() fills the unexported folded
		// patterns, and mutating a caller-owned lexicon would race if the same
		// value were used by concurrent scans.
		cp := *opt.Lexicon
		cp.Terms = append([]IdentityTerm(nil), opt.Lexicon.Terms...)
		lex = &cp
	}
	if err := lex.validate(); err != nil {
		return nil, err
	}
	if opt.Allowlist != nil {
		cp := *opt.Allowlist
		cp.Rules = append([]IdentityAllowRule(nil), opt.Allowlist.Rules...)
		opt.Allowlist = &cp
		if err := opt.Allowlist.validate(); err != nil {
			return nil, err
		}
	}
	tiers, err := identityTierSet(opt.Tiers)
	if err != nil {
		return nil, err
	}
	terms := make([]IdentityTerm, 0, len(lex.Terms))
	for _, t := range lex.Terms {
		if tiers[t.List] {
			terms = append(terms, t)
		}
	}
	if len(terms) == 0 {
		return nil, errors.New("当前 tiers 没有任何可用词条")
	}
	dbPath, trafficDir, err := identityResolvePaths(opt)
	if err != nil {
		return nil, err
	}
	db, err := OpenIndexReadOnly(dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	batch := opt.Batch
	if batch <= 0 {
		batch = identityDefaultBatch
	}
	if batch > 1000 {
		batch = 1000
	}
	maxBody := opt.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = IdentityDefaultMaxBodyBytes
	}
	hosts := map[string]bool{}
	for _, h := range opt.Hosts {
		if n := normalizeIdentityHost(h); n != "" {
			hosts[n] = true
		}
	}
	now := time.Now
	if opt.Now != nil {
		now = opt.Now
	}
	agg := newIdentityAgg(opt.Allowlist, opt.TaskMap)
	cov := &IdentityCoverage{}
	var stats IdentityScanStats
	var completeWithBody int64
	cursor := int64(0)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rows, err := identityQueryBatch(ctx, db, cursor, opt.Since, opt.Until, hosts, batch)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			break
		}
		stats.Batches++
		stop := false
		if opt.Limit > 0 && stats.Scanned+int64(len(rows)) > int64(opt.Limit) {
			remain := int64(opt.Limit) - stats.Scanned
			if remain < 0 {
				remain = 0
			}
			rows = rows[:remain]
			stop = true
		}

		eligible := make([]identityRow, 0, len(rows))
		ids := make([]string, 0, len(rows))
		for _, r := range rows {
			cursor = r.rowid
			stats.Rows++
			stats.Scanned++
			agg.observe(r.host)
			if strings.TrimSpace(r.path) != "" {
				stats.LegacyRows++
				cov.LegacyRows++
				continue
			}
			switch identityClassify(r) {
			case "head":
				cov.Excluded.HEAD++
				continue
			case "info":
				cov.Excluded.Informational1xx++
				continue
			case "no_content":
				cov.Excluded.NoContent++
				continue
			case "not_modified":
				cov.Excluded.NotModified304++
				continue
			case "failed":
				cov.Excluded.FailedStatus0++
				continue
			}
			cov.Eligible++
			agg.eligible(r.host)
			if r.reqLen > 0 || r.respLen > 0 {
				cov.WithBody++
				agg.withBody(r.host)
			}
			if r.reqLen > 0 {
				cov.RequestCapture++
			}
			if r.respLen > 0 {
				cov.ResponseCapture++
			}
			eligible = append(eligible, r)
			ids = append(ids, r.id)
		}
		bodies, err := identityReadBodies(ctx, db, ids)
		if err != nil {
			return nil, err
		}
		for _, r := range eligible {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			b := bodies[r.id]
			reqCT := identityHeaderContentType(b.reqHead)
			reqData, reqTrunc, reqMissing := identityReadSide(trafficDir, b.reqBody, b.reqBlob, maxBody, r.reqLen)
			respData, respTrunc, respMissing := identityReadSide(trafficDir, b.respBody, b.respBlob, maxBody, r.respLen)
			incomplete := false
			if reqTrunc || respTrunc {
				cov.BodyTruncated++
				incomplete = true
			}
			switch reqMissing {
			case "blob":
				stats.BlobMissing++
				incomplete = true
			case "inline":
				stats.BodyMissing++
				incomplete = true
			}
			switch respMissing {
			case "blob":
				stats.BlobMissing++
				incomplete = true
			case "inline":
				stats.BodyMissing++
				incomplete = true
			}
			cov.BodyBytesRead += int64(len(reqData) + len(respData))
			recs := identityCollectHits(r, b.reqHead, b.respHead, reqCT, reqData, respData, terms, &stats, &incomplete)
			if r.reqLen > 0 || r.respLen > 0 {
				if !incomplete {
					completeWithBody++
				}
			}
			if len(recs) == 0 {
				continue
			}
			sort.Slice(recs, func(i, j int) bool { return recs[i].term.ID < recs[j].term.ID })
			kept := make([]identityHitRecord, 0, len(recs))
			host := normalizeIdentityHost(r.host)
			for _, rec := range recs {
				if rule, ok := agg.suppresses(rec.term.ID, host); ok {
					agg.suppress(rule)
					continue
				}
				agg.addHit(r, rec)
				kept = append(kept, rec)
			}
			agg.promote(r, kept)
		}
		if stop {
			stats.Truncated = true
			break
		}
	}
	stats.DurationMillis = time.Since(started).Milliseconds()

	cov.Total = stats.Scanned
	cov.CaptureCoverage = identityRatio(cov.WithBody, cov.Eligible)
	cov.ScanCoverage = identityRatio(completeWithBody, cov.WithBody)

	return &IdentityReport{
		SchemaVersion:        IdentitySchemaVersion,
		GeneratedAt:          now(),
		DB:                   IdentityDBInfo{Path: dbPath, Mode: "ro", TrafficDir: trafficDir},
		Lexicon:              IdentityLexiconInfo{Version: lex.Version, Source: source, Counts: identityLexiconCounts(terms)},
		NormalizationVersion: IdentityNormalizationVersion,
		Scan:                 stats,
		Coverage:             *cov,
		Lists:                agg.listStats(),
		Hosts:                agg.hostStats(),
		Tasks:                agg.taskStats(),
		UnmappedHosts:        agg.unmappedHosts(),
		Samples:              agg.sampleList(),
		Findings:             agg.findingList(),
		FindingsTotal:        agg.findingsTotal,
		Suppressed:           agg.suppressedReport(),
		Warnings:             identityWarnings(stats, *cov),
		Notes:                identityNotes(opt, tiers),
	}, nil
}

func identityResolvePaths(opt IdentityScanOptions) (dbPath, trafficDir string, err error) {
	switch {
	case strings.TrimSpace(opt.DBPath) != "":
		dbPath = strings.TrimSpace(opt.DBPath)
	case strings.TrimSpace(opt.DataDir) != "":
		dbPath = filepath.Join(strings.TrimSpace(opt.DataDir), "traffic", "_index", "index.sqlite")
	default:
		return "", "", errors.New("必须指定 --db 或 --data（或可推导的 --config）")
	}
	dbPath, err = filepath.Abs(dbPath)
	if err != nil {
		return "", "", err
	}
	trafficDir = strings.TrimSpace(opt.TrafficDir)
	if trafficDir == "" {
		if filepath.Base(filepath.Dir(dbPath)) == "_index" {
			trafficDir = filepath.Dir(filepath.Dir(dbPath))
		} else {
			trafficDir = filepath.Dir(dbPath)
		}
	}
	if abs, err := filepath.Abs(trafficDir); err == nil {
		trafficDir = abs
	}
	return dbPath, trafficDir, nil
}

func identityTierSet(in []string) (map[string]bool, error) {
	if len(in) == 0 {
		return map[string]bool{"A": true, "B": true}, nil
	}
	out := map[string]bool{}
	for _, raw := range in {
		for _, part := range strings.Split(raw, ",") {
			p := strings.ToUpper(strings.TrimSpace(part))
			if p == "" {
				continue
			}
			switch p {
			case "A", "B", "C":
				out[p] = true
			default:
				return nil, fmt.Errorf("未知的 tiers 项 %q（只支持 A/B/C）", p)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("tiers 为空")
	}
	return out, nil
}

func identityQueryBatch(ctx context.Context, db *sql.DB, cursor, since, until int64, hosts map[string]bool, batch int) ([]identityRow, error) {
	q := `SELECT rowid,` + exchangeMetaColsWithReqLen + ` FROM exchanges WHERE rowid>?`
	args := []any{cursor}
	if since > 0 {
		q += ` AND ts>=?`
		args = append(args, since)
	}
	if until > 0 {
		q += ` AND ts<?`
		args = append(args, until)
	}
	if len(hosts) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(hosts)), ",")
		q += ` AND lower(host) IN (` + ph + `)`
		for h := range hosts {
			args = append(args, h)
		}
	}
	q += ` ORDER BY rowid LIMIT ?`
	args = append(args, batch)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("读取流量索引失败：%w", err)
	}
	defer rows.Close()
	var out []identityRow
	for rows.Next() {
		var r identityRow
		if err := rows.Scan(&r.rowid, &r.id, &r.ts, &r.host, &r.method, &r.urlTemplate, &r.url,
			&r.status, &r.contentType, &r.reqLen, &r.respLen, &r.path); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func identityReadBodies(ctx context.Context, db *sql.DB, ids []string) (map[string]identityBodyRow, error) {
	out := map[string]identityBodyRow{}
	if len(ids) == 0 {
		return out, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	q := `SELECT id,COALESCE(req_head,''),req_body,req_blob,COALESCE(resp_head,''),resp_body,resp_blob
	        FROM exchange_bodies WHERE id IN (` + ph + `)`
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("读取流量正文失败：%w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var b identityBodyRow
		if err := rows.Scan(&id, &b.reqHead, &b.reqBody, &b.reqBlob, &b.respHead, &b.respBody, &b.respBlob); err != nil {
			return nil, err
		}
		out[id] = b
	}
	return out, rows.Err()
}

func identityClassify(r identityRow) string {
	if strings.EqualFold(strings.TrimSpace(r.method), "HEAD") {
		return "head"
	}
	switch {
	case r.status == 0:
		return "failed"
	case r.status == 101 || (r.status >= 100 && r.status < 200):
		return "info"
	case r.status == 204 || r.status == 205:
		return "no_content"
	case r.status == 304:
		return "not_modified"
	}
	return "eligible"
}

// identityReadSide returns the readable body, whether it was truncated by the
// configured cap, and a missing reason ("blob" or "inline") when nothing could
// be read. A spilled body is never substituted with its inline preview: the
// preview is only the first 8 KiB and would silently miss deep hits.
func identityReadSide(trafficDir string, inline []byte, blob sql.NullString, limit, claimed int64) ([]byte, bool, string) {
	if blob.Valid && strings.TrimSpace(blob.String) != "" {
		p, err := blobPathIn(trafficDir, blob.String)
		if err != nil {
			return nil, false, "blob"
		}
		f, err := os.Open(p)
		if err != nil {
			return nil, false, "blob"
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return nil, false, "blob"
		}
		size := st.Size()
		read := size
		if limit > 0 && read > limit {
			read = limit
		}
		if read < 0 {
			read = 0
		}
		data, err := io.ReadAll(io.LimitReader(f, read))
		if err != nil {
			return nil, false, "blob"
		}
		if claimed > 0 && len(data) == 0 {
			return nil, false, "blob"
		}
		return data, size > int64(len(data)), ""
	}
	if claimed > 0 && len(inline) == 0 {
		return nil, false, "inline"
	}
	return inline, false, ""
}

func identityHeaderContentType(head string) string {
	for _, line := range strings.Split(head, "\n") {
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(line[:i]), "Content-Type") {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}

func identityCollectHits(row identityRow, reqHead, respHead, reqCT string, reqData, respData []byte, terms []IdentityTerm, stats *IdentityScanStats, incomplete *bool) []identityHitRecord {
	hitByTerm := map[string]identityHitRecord{}
	scan := func(where, text string) {
		if text == "" {
			return
		}
		folded := foldASCII(text)
		for _, t := range terms {
			if off := identityFind(folded, t.folded, t.Boundary); off >= 0 {
				if _, ok := hitByTerm[t.ID]; !ok {
					hitByTerm[t.ID] = identityHitRecord{term: t, where: where, offset: off, text: text}
				}
			}
		}
	}
	scan("url", row.url)
	scan("url_template", row.urlTemplate)
	scan("req_head", reqHead)
	scan("resp_head", respHead)
	if len(reqData) > 0 {
		if isBinaryBody(reqCT, reqData) {
			stats.BinarySkipped++
			*incomplete = true
		} else {
			scan("req_body", string(reqData))
		}
	}
	if len(respData) > 0 {
		if isBinaryBody(row.contentType, respData) {
			stats.BinarySkipped++
			*incomplete = true
		} else {
			scan("resp_body", string(respData))
		}
	}
	out := make([]identityHitRecord, 0, len(hitByTerm))
	for _, rec := range hitByTerm {
		out = append(out, rec)
	}
	return out
}

func identityRatio(n, d int64) float64 {
	if d <= 0 {
		return 0
	}
	return float64(n) / float64(d)
}

func identityLexiconCounts(terms []IdentityTerm) map[string]int {
	out := map[string]int{"A": 0, "B": 0, "C": 0}
	for _, t := range terms {
		out[t.List]++
	}
	return out
}

func identityWarnings(stats IdentityScanStats, cov IdentityCoverage) []string {
	w := []string{
		"分母是已录制的 exchange，不是目标侧真实请求；受录制链路限制（如超大响应不入库），覆盖率为下界。",
		"不做百分号解码与 NFKC，编码变体与全角变体不会命中。",
		"legacy 行（path 非空）未纳入覆盖率分子分母，仅计数。",
	}
	if stats.Truncated {
		w = append(w, "扫描达到 --limit：覆盖率仅针对已扫描行，结果不是全库。")
	}
	if cov.BodyTruncated > 0 {
		w = append(w, "存在被 --max-body-bytes 截断的正文，深处命中可能漏报。")
	}
	if stats.BlobMissing > 0 {
		w = append(w, "存在 blob 文件缺失：索引引用了正文但 _blobs 下找不到对应文件。")
	}
	if stats.BodyMissing > 0 {
		w = append(w, "存在索引声明有正文、但 inline 与 blob 均读不到的行（body_missing），scan_coverage 已扣减。")
	}
	if stats.BinarySkipped > 0 {
		w = append(w, "二进制正文按设计跳过匹配，不计入 scan_coverage。")
	}
	if cov.Total != cov.Eligible+cov.LegacyRows+cov.Excluded.HEAD+cov.Excluded.Informational1xx+cov.Excluded.NoContent+cov.Excluded.NotModified304+cov.Excluded.FailedStatus0 {
		w = append(w, "内部计数未闭合：这是扫描器 bug，请保留本次报告。")
	}
	return w
}

func identityNotes(opt IdentityScanOptions, tiers map[string]bool) []string {
	n := []string{
		"traffic 索引没有 task_id，每任务统计来自外部 --task-map（host → task_id），不是录制时的归属。",
		"A 命中直接成为 finding；同一 exchange 内出现 ≥2 个不同 B 词条才升级为 finding；C 只统计不告警。",
	}
	if len(opt.TaskMap) == 0 {
		n = append(n, "未提供 --task-map：仅输出 per-host 统计。")
	}
	if tiers["C"] {
		n = append(n, "已显式启用 C 表：通用框架/工具默认值会产生大量预期噪声，且不单独告警。")
	}
	return n
}

func normalizeIdentityHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	return strings.ToLower(h)
}
