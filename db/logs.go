package db

import (
	"context"
	"time"
)

// DBLog is one persisted backend log row from the server_logs table.
type DBLog struct {
	ID        int64
	CreatedAt time.Time
	Level     string
	Tag       string
	Text      string
}

// InsertLog appends one log line and returns its auto-assigned id.
func (d *DB) InsertLog(level, tag, text string) (int64, error) {
	var id int64
	err := d.QueryRowContext(context.Background(),
		"INSERT INTO server_logs(level,tag,text) VALUES($1,$2,$3) RETURNING id",
		level, tag, text,
	).Scan(&id)
	return id, err
}

// RecentLogs returns the most recent limit rows, oldest-first.
func (d *DB) RecentLogs(limit int) ([]*DBLog, error) {
	rows, err := d.QueryContext(context.Background(),
		`SELECT id, created_at, level, tag, text
		   FROM server_logs
		  ORDER BY id DESC
		  LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DBLog
	for rows.Next() {
		l := &DBLog{}
		if err := rows.Scan(&l.ID, &l.CreatedAt, &l.Level, &l.Tag, &l.Text); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	// Reverse to oldest-first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// ListLogsBefore returns up to limit rows with id < beforeID, oldest-first.
func (d *DB) ListLogsBefore(beforeID int64, limit int) ([]*DBLog, error) {
	rows, err := d.QueryContext(context.Background(),
		`SELECT id, created_at, level, tag, text
		   FROM server_logs
		  WHERE id < $1
		  ORDER BY id DESC
		  LIMIT $2`, beforeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DBLog
	for rows.Next() {
		l := &DBLog{}
		if err := rows.Scan(&l.ID, &l.CreatedAt, &l.Level, &l.Tag, &l.Text); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	// Reverse to oldest-first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// LogLevelCount 是一段窗口内某个 level/tag 的日志行数。
type LogLevelCount struct {
	Level string
	Tag   string
	Count int64
}

// LogCluster 是一组归一化后相同的日志（用于错误/panic 聚合）。
type LogCluster struct {
	Level    string
	Tag      string
	Text     string
	Count    int64
	FirstAt  time.Time
	LastAt   time.Time
	SampleID int64
}

// LogLevelCounts 返回 since 之后按 level/tag 的行数（诊断包用）。
func (d *DB) LogLevelCounts(since time.Time) ([]LogLevelCount, error) {
	rows, err := d.QueryContext(context.Background(),
		`SELECT level, tag, count(*) FROM server_logs
		  WHERE created_at >= $1 GROUP BY 1,2 ORDER BY 3 DESC LIMIT 200`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogLevelCount
	for rows.Next() {
		var c LogLevelCount
		if err := rows.Scan(&c.Level, &c.Tag, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LogErrorClusters 返回 since 之后按“前 4KB 文本”聚合的错误簇，按次数降序。
// 用 left(text,4000) 聚合，避免同一 panic 栈里的地址/线程号产生上千个不同簇。
func (d *DB) LogErrorClusters(since time.Time, limit int) ([]LogCluster, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := d.QueryContext(context.Background(),
		`SELECT min(id), level, tag, left(text,4000) AS t, count(*), min(created_at), max(created_at)
		   FROM server_logs
		  WHERE created_at >= $1 AND level='error'
		  GROUP BY level, tag, t
		  ORDER BY count(*) DESC, max(created_at) DESC
		  LIMIT $2`, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogCluster
	for rows.Next() {
		var c LogCluster
		if err := rows.Scan(&c.SampleID, &c.Level, &c.Tag, &c.Text, &c.Count, &c.FirstAt, &c.LastAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LogSampleByLevel 返回 since 之后指定 level 的日志，按 tag 每组最多 perTag 条，
// 用于 warn/info 的分层采样（避免某一类刷屏把整段日志挤掉）。
func (d *DB) LogSampleByLevel(since time.Time, level string, perTag int) ([]*DBLog, error) {
	if perTag <= 0 {
		perTag = 20
	}
	if level != "warn" && level != "info" {
		return nil, nil
	}
	rows, err := d.QueryContext(context.Background(),
		`SELECT id, created_at, level, tag, text FROM (
		   SELECT id, created_at, level, tag, text,
		          row_number() OVER (PARTITION BY tag ORDER BY id DESC) AS rn
		     FROM server_logs WHERE created_at >= $1 AND level=$2
		 ) x WHERE rn <= $3 ORDER BY id`, since, level, perTag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*DBLog
	for rows.Next() {
		l := &DBLog{}
		if err := rows.Scan(&l.ID, &l.CreatedAt, &l.Level, &l.Tag, &l.Text); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

