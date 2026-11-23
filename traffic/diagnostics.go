package traffic

import (
	"context"
	"database/sql"
	"time"
)

// DiagnosticsStats 汇总流量索引（只读、无正文）：总量、时间范围、按 host/状态码
// 分布、5xx/连接失败主机。诊断包用它判断“捕获是否在工作、失败集中在哪”。
func (t *Traffic) DiagnosticsStats(since int64, topHosts int) map[string]any {
	out := map[string]any{"enabled": t != nil}
	if t == nil {
		return out
	}
	out["addr"] = t.ProxyAddr()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var total int64
	var minTS, maxTS sql.NullInt64
	if err := t.db.QueryRowContext(ctx, `SELECT count(*), min(ts), max(ts) FROM exchanges WHERE ts >= ?`, since).Scan(&total, &minTS, &maxTS); err != nil {
		out["error"] = err.Error()
		return out
	}
	out["total"] = total
	if minTS.Valid {
		out["first_at"] = time.Unix(minTS.Int64, 0).Format(time.RFC3339)
	}
	if maxTS.Valid {
		out["last_at"] = time.Unix(maxTS.Int64, 0).Format(time.RFC3339)
	}
	if topHosts <= 0 {
		topHosts = 50
	}
	byHost := []map[string]any{}
	if rows, err := t.db.QueryContext(ctx,
		`SELECT COALESCE(host,''), count(*), COALESCE(sum(resp_len),0) FROM exchanges WHERE ts >= ?
		  GROUP BY host ORDER BY count(*) DESC LIMIT ?`, since, topHosts); err == nil {
		for rows.Next() {
			var host string
			var n, bytes int64
			if rows.Scan(&host, &n, &bytes) == nil {
				byHost = append(byHost, map[string]any{"host": host, "count": n, "bytes": bytes})
			}
		}
		rows.Close()
	}
	out["top_hosts"] = byHost
	byStatus := []map[string]any{}
	if rows, err := t.db.QueryContext(ctx,
		`SELECT COALESCE(status,0)/100 AS klass, count(*) FROM exchanges WHERE ts >= ? GROUP BY 1 ORDER BY 2 DESC`, since); err == nil {
		for rows.Next() {
			var klass int
			var n int64
			if rows.Scan(&klass, &n) == nil {
				byStatus = append(byStatus, map[string]any{"class": klass * 100, "count": n})
			}
		}
		rows.Close()
	}
	out["by_status_class"] = byStatus
	failing := []map[string]any{}
	if rows, err := t.db.QueryContext(ctx,
		`SELECT COALESCE(host,''), count(*) FROM exchanges WHERE ts >= ? AND (COALESCE(status,0)=0 OR COALESCE(status,0)>=500)
		  GROUP BY host ORDER BY 2 DESC LIMIT 30`, since); err == nil {
		for rows.Next() {
			var host string
			var n int64
			if rows.Scan(&host, &n) == nil {
				failing = append(failing, map[string]any{"host": host, "count": n})
			}
		}
		rows.Close()
	}
	out["failing_hosts"] = failing
	return out
}
