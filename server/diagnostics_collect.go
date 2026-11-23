package server

import (
	"fmt"
	"runtime"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
)

// diagQuery 执行一条只读查询并把结果转成 []map[string]any（列名 → 值）。
// 统一把 []byte 转 string、time.Time 转 RFC3339，避免 JSON 里出现 base64。
func diagQuery(pg *db.DB, q string, args ...any) ([]map[string]any, error) {
	rows, err := pg.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, 32)
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return out, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			switch v := vals[i].(type) {
			case nil:
				m[c] = nil
			case []byte:
				m[c] = string(v)
			case time.Time:
				m[c] = v.UTC().Format(time.RFC3339)
			default:
				m[c] = v
			}
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// diagSettings 复制 settingsPayload。v0.8：诊断包不再做代理 URL 掩码/日志脱敏，
// 导出即全量（用户明确要求全量诊断）；认证/凭据加密仍由平台安全底座保证。
func (s *Server) diagSettings() map[string]any {
	raw := s.settingsPayload()
	out := make(map[string]any, len(raw)+1)
	for k, v := range raw {
		out[k] = v
	}
	// 代理 URL 可能带 user:pass；诊断包会被用户转发给开发，平台自身凭据必须掩码。
	for _, k := range []string{"global_proxy", "web_search_proxy", "install_proxy"} {
		if v, ok := out[k].(string); ok && v != "" {
			out[k] = maskProxyURL(v)
		}
	}
	out["proxypool_allow_socks5"] = s.socks5Allowed()
	return out
}

// diagMeta 返回进程与数据库规模的运行指标。
func diagMeta(pg *db.DB) map[string]any {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	out := map[string]any{
		"generated_at": time.Now().Format(time.RFC3339),
		"version":      BuildVersion,
		"go_version":   runtime.Version(),
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"uptime_s":     int(time.Since(startTime).Seconds()),
		"goroutines":   runtime.NumGoroutine(),
		"heap_alloc":   ms.HeapAlloc,
		"heap_sys":     ms.HeapSys,
		"gc_count":     ms.NumGC,
	}
	if pg != nil {
		var size int64
		if err := pg.QueryRow(`SELECT pg_database_size(current_database())`).Scan(&size); err == nil {
			out["db_size_bytes"] = size
		}
	}
	return out
}

// diagIntegrity 对关键表做行数统计 + schema 列探测，区分“表空”与“查询/迁移坏了”。
func diagIntegrity(pg *db.DB) (map[string]any, error) {
	out := map[string]any{}
	counts, err := diagQuery(pg, `
		SELECT 'tasks' AS table_name, count(*) FROM tasks WHERE deleted_at IS NULL
		UNION ALL SELECT 'explorations', count(*) FROM explorations
		UNION ALL SELECT 'exploration_nodes', count(*) FROM exploration_nodes
		UNION ALL SELECT 'activity', count(*) FROM activity
		UNION ALL SELECT 'findings', count(*) FROM findings
		UNION ALL SELECT 'server_logs', count(*) FROM server_logs
		UNION ALL SELECT 'intercept_pending', count(*) FROM intercept_pending
		UNION ALL SELECT 'autopilot_events', count(*) FROM autopilot_events
		UNION ALL SELECT 'llm_usage', count(*) FROM llm_usage
		UNION ALL SELECT 'tool_usage', count(*) FROM tool_usage`)
	if err != nil {
		return out, err
	}
	out["table_counts"] = counts
	cols, colErr := diagQuery(pg, `
		SELECT table_name, column_name FROM information_schema.columns
		 WHERE table_schema='public' AND (
		   (table_name='findings' AND column_name IN ('fingerprint','status','report','severity'))
		   OR (table_name='exploration_nodes' AND column_name IN ('blocked_reason','completed_at'))
		   OR (table_name='tasks' AND column_name IN ('timeout_seconds','deadline_at'))
		   OR (table_name='llm_usage' AND column_name IN ('intent_id','worker','status'))
		 ) ORDER BY 1,2`)
	if colErr != nil {
		out["columns_error"] = colErr.Error()
	} else {
		out["columns"] = cols
	}
	logs, logErr := diagQuery(pg, `SELECT count(*) AS rows, min(created_at) AS first_at, max(created_at) AS last_at FROM server_logs`)
	if logErr != nil {
		out["logs_error"] = logErr.Error()
	} else {
		out["server_logs"] = logs
	}
	return out, nil
}

// diagFindingsDebug 直接回答“漏洞到底有没有入库”。
func diagFindingsDebug(pg *db.DB) (map[string]any, error) {
	rows, err := diagQuery(pg, `
		SELECT
		 (SELECT count(*) FROM findings) AS table_rows,
		 (SELECT count(*) FROM findings WHERE task_id IS NULL) AS null_task,
		 (SELECT count(*) FROM findings WHERE status='pending') AS pending,
		 (SELECT count(*) FROM findings WHERE status='confirmed') AS confirmed,
		 (SELECT count(*) FROM findings WHERE fingerprint='') AS no_fingerprint,
		 (SELECT count(*) FROM findings WHERE severity NOT IN ('critical','high','medium','low')) AS bad_severity,
		 (SELECT count(*) FROM exploration_nodes WHERE kind='finding') AS graph_finding_nodes,
		 (SELECT count(*) FROM exploration_nodes n WHERE n.kind='finding'
		    AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.node_id=n.id)) AS node_without_row`)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return map[string]any{}, nil
	}
	return rows[0], nil
}

// diagTasks 返回任务全字段 + 目标/意图/漏洞计数（不再只给 4 列）。
func diagTasks(pg *db.DB) ([]map[string]any, error) {
	return diagQuery(pg, `
		SELECT t.id::text AS id, t.name, t.description, t.goal, t.status, t.paused, t.queued,
		       t.timeout_seconds, t.created_at, t.first_run_at, t.deadline_at, t.completed_at,
		       t.updated_at, t.exploration_id::text AS exploration_id, e.round_no,
		       (SELECT count(*) FROM exploration_nodes n WHERE n.exploration_id=t.exploration_id AND n.kind='goal') AS goals_total,
		       (SELECT count(*) FROM exploration_nodes n WHERE n.exploration_id=t.exploration_id AND n.kind='goal' AND n.state='met') AS goals_met,
		       (SELECT count(*) FROM exploration_nodes n WHERE n.exploration_id=t.exploration_id AND n.kind='intent' AND n.state='open') AS open_intents,
		       (SELECT count(*) FROM exploration_nodes n WHERE n.exploration_id=t.exploration_id AND n.kind='intent' AND n.state='running') AS running_intents,
		       (SELECT count(*) FROM exploration_nodes n WHERE n.exploration_id=t.exploration_id AND n.kind='intent' AND n.state='exhausted') AS exhausted_intents,
		       (SELECT count(*) FROM findings f WHERE f.task_id=t.id) AS findings_total,
		       (SELECT max(a.created_at) FROM activity a WHERE a.exploration_id=t.exploration_id) AS last_activity,
		       (SELECT count(*) FROM activity a WHERE a.exploration_id=t.exploration_id AND a.created_at >= now()-interval '1 hour') AS activity_1h,
		       (SELECT kind||' '||left(coalesce(detail,''),200) FROM autopilot_events ev
		         WHERE ev.task_id=t.id::text ORDER BY id DESC LIMIT 1) AS last_event
		  FROM tasks t JOIN explorations e ON e.id=t.exploration_id
		 WHERE t.deleted_at IS NULL ORDER BY t.id DESC LIMIT 200`)
}

// diagGoals 返回目标明细（含 criteria/状态/证明边数）。
func diagGoals(pg *db.DB) ([]map[string]any, error) {
	return diagQuery(pg, `
		SELECT n.id::text AS id, t.id::text AS task_id,
		       left(coalesce(n.payload->>'text',''),500) AS text,
		       left(coalesce(n.payload->>'criteria',''),500) AS criteria,
		       coalesce(n.payload->>'vulnclass','') AS vulnclass,
		       n.state, n.created_at, n.completed_at,
		       (SELECT count(*) FROM exploration_edges e WHERE e.dst_id=n.id AND e.rel='proves') AS proof_edges
		  FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id
		 WHERE n.kind='goal' AND t.deleted_at IS NULL
		 ORDER BY n.id DESC LIMIT 500`)
}

// diagIntents 返回意图明细：状态、owner、blocked_reason、stop_reason、写回/工具计数。
func diagIntents(pg *db.DB, limit int, since time.Time) ([]map[string]any, error) {
	return diagQuery(pg, `
		SELECT n.id::text AS id, t.id::text AS task_id, n.state, n.priority, n.owner,
		       left(coalesce(n.payload->>'summary',''),500) AS summary,
		       coalesce(n.payload->>'stop_reason','') AS stop_reason,
		       coalesce(n.payload->>'terminal','') AS terminal,
		       coalesce(n.payload->>'wall_ms','') AS wall_ms,
		       coalesce(n.payload->>'continues','') AS continues,
		       coalesce(n.blocked_reason,'') AS blocked_reason,
		       n.created_at, n.completed_at,
		       (SELECT count(*) FROM exploration_edges e WHERE e.src_id=n.id AND e.rel='yields') AS yields,
		       (SELECT count(*) FROM activity a WHERE a.node_id=n.id AND a.kind='tool_use') AS tool_calls,
		       (SELECT count(*) FROM activity a WHERE a.node_id=n.id AND a.kind='tool_result' AND a.is_error) AS tool_errors
		  FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id
		 WHERE n.kind='intent' AND t.deleted_at IS NULL AND n.created_at >= $1
		 ORDER BY n.id DESC LIMIT $2`, since, limit)
}

// diagFindings 返回漏洞元数据（修正 BIGINT::text），不含证据/报告正文。
func diagFindings(pg *db.DB, limit int, since time.Time) ([]map[string]any, error) {
	return diagQuery(pg, `
		SELECT f.id::text AS id, COALESCE(f.task_id::text,'') AS task_id,
		       COALESCE(f.status,'') AS status, COALESCE(f.severity,'') AS severity,
		       COALESCE(f.vulnclass,'') AS vulnclass, left(COALESCE(f.name,''),160) AS name,
		       left(COALESCE(f.fingerprint,''),64) AS fingerprint,
		       COALESCE(jsonb_array_length(f.asset_ids),0) AS asset_count,
		       (COALESCE(f.report,'') <> '') AS has_report,
		       length(COALESCE(f.report,'')) AS report_len,
		       length(COALESCE(f.evidence,'')) AS evidence_len,
		       COALESCE(f.worker,'') AS worker, f.created_at
		  FROM findings f WHERE f.created_at >= $1
		 ORDER BY f.id DESC LIMIT $2`, since, limit)
}

// diagFacts 返回事实摘要（可按窗口放大）。
func diagFacts(pg *db.DB, limit int, since time.Time) ([]map[string]any, error) {
	return diagQuery(pg, `
		SELECT n.id::text AS id, t.id::text AS task_id, n.exploration_id::text AS exploration_id,
		       n.state, left(coalesce(n.payload->>'summary',''),500) AS summary,
		       coalesce(n.payload->>'confidence','') AS confidence, n.created_at
		  FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id
		 WHERE n.kind='fact' AND t.deleted_at IS NULL AND n.created_at >= $1
		 ORDER BY n.id DESC LIMIT $2`, since, limit)
}

// diagActivity 返回工具/模型活动摘要（不含 detail 正文）。
func diagActivity(pg *db.DB, limit int, since time.Time) ([]map[string]any, error) {
	return diagQuery(pg, `
		SELECT a.id::text AS id, t.id::text AS task_id, coalesce(a.worker,'') AS worker,
		       coalesce(a.kind,'') AS kind, coalesce(a.tool,'') AS tool, a.is_error,
		       left(coalesce(a.summary,''),300) AS summary,
		       a.input_tokens, a.output_tokens, a.created_at
		  FROM activity a JOIN tasks t ON t.exploration_id=a.exploration_id
		 WHERE a.created_at >= $1 ORDER BY a.id DESC LIMIT $2`, since, limit)
}

// diagTimeline 合并自主推进事件、意图终态、任务终态与工具错误，按时间倒序。
func diagTimeline(pg *db.DB, limit int, since time.Time) ([]map[string]any, error) {
	return diagQuery(pg, `
		SELECT * FROM (
		  SELECT 'autopilot' AS src, id::text AS ref, task_id, kind, left(coalesce(detail,''),300) AS detail, created_at
		    FROM autopilot_events WHERE created_at >= $1
		  UNION ALL
		  SELECT 'intent', n.id::text, t.id::text, n.state, left(coalesce(n.blocked_reason,n.payload->>'stop_reason',''),300), n.completed_at
		    FROM exploration_nodes n JOIN tasks t ON t.exploration_id=n.exploration_id
		   WHERE n.kind='intent' AND n.completed_at >= $1
		  UNION ALL
		  SELECT 'task', t.id::text, t.id::text, t.status, '', t.completed_at
		    FROM tasks t WHERE t.completed_at >= $1 AND t.deleted_at IS NULL
		  UNION ALL
		  SELECT 'tool_error', a.id::text, t.id::text, coalesce(a.tool,''), left(coalesce(a.summary,''),300), a.created_at
		    FROM activity a JOIN tasks t ON t.exploration_id=a.exploration_id
		   WHERE a.is_error AND a.created_at >= $1
		) x ORDER BY created_at DESC LIMIT $2`, since, limit)
}

// diagLLMUsage 按 任务×角色×模型×profile×status 聚合，并给意图级 top 与熔断状态。
func diagLLMUsage(pg *db.DB, since time.Time) (map[string]any, error) {
	rows, err := diagQuery(pg, `
		SELECT coalesce(task_id,'') AS task_id, coalesce(worker,'') AS role,
		       coalesce(model,'') AS model, coalesce(profile_name,'') AS profile,
		       coalesce(status,'') AS status, count(*) AS calls,
		       sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens,
		       sum(cache_read) AS cache_read, sum(cache_write) AS cache_write,
		       round(avg(latency_ms)) AS avg_latency_ms
		  FROM llm_usage WHERE ts >= $1
		 GROUP BY 1,2,3,4,5 ORDER BY sum(input_tokens+output_tokens) DESC LIMIT 200`, since)
	if err != nil {
		return nil, err
	}
	intents, ierr := diagQuery(pg, `
		SELECT intent_id::text AS intent_id, count(*) AS calls,
		       sum(input_tokens+cache_read+cache_write) AS input_tokens, sum(output_tokens) AS output_tokens
		  FROM llm_usage WHERE ts >= $1 AND intent_id > 0
		 GROUP BY 1 ORDER BY sum(input_tokens+cache_read+cache_write) DESC LIMIT 20`, since)
	out := map[string]any{"by_role_model": rows, "top_intents": intents}
	if ierr != nil {
		out["top_intents_error"] = ierr.Error()
	}
	health, herr := diagQuery(pg, `
		SELECT h.profile_id::text AS profile_id, coalesce(p.name,'') AS name,
		       h.fails, h.trips, h.open_until, left(coalesce(h.last_error,''),300) AS last_error, h.last_at
		  FROM llm_profile_health h LEFT JOIN llm_profiles p ON p.id=h.profile_id`)
	if herr != nil {
		out["health_error"] = herr.Error()
	} else {
		out["profile_health"] = health
	}
	return out, nil
}

// diagLogs 分层导出日志：错误簇（去重）+ warn/info 按 tag 采样 + 级别计数。
func diagLogs(pg *db.DB, since time.Time, detail bool) (map[string]any, error) {
	errLimit := 100
	sampleWarn, sampleInfo := 10, 5
	if detail {
		errLimit, sampleWarn, sampleInfo = 300, 50, 20
	}
	clusters, err := pg.LogErrorClusters(since, errLimit)
	if err != nil {
		return nil, err
	}
	cl := make([]map[string]any, 0, len(clusters))
	for _, c := range clusters {
		cl = append(cl, map[string]any{
			"sample_id": c.SampleID, "level": c.Level, "tag": c.Tag, "text": c.Text,
			"count": c.Count, "first_at": c.FirstAt.UTC().Format(time.RFC3339),
			"last_at": c.LastAt.UTC().Format(time.RFC3339),
		})
	}
	warn, werr := pg.LogSampleByLevel(since, "warn", sampleWarn)
	info, ierr := pg.LogSampleByLevel(since, "info", sampleInfo)
	toRows := func(in []*db.DBLog) []map[string]any {
		out := make([]map[string]any, 0, len(in))
		for _, l := range in {
			out = append(out, map[string]any{
				"ts": l.CreatedAt.UTC().Format(time.RFC3339), "level": l.Level,
				"tag": l.Tag, "text": l.Text,
			})
		}
		return out
	}
	counts, cerr := pg.LogLevelCounts(since)
	crows := make([]map[string]any, 0, len(counts))
	for _, c := range counts {
		crows = append(crows, map[string]any{"level": c.Level, "tag": c.Tag, "count": c.Count})
	}
	out := map[string]any{
		"since": since.Format(time.RFC3339), "error_clusters": cl,
		"warn_samples": toRows(warn), "info_samples": toRows(info), "level_counts": crows,
	}
	if werr != nil {
		out["warn_error"] = werr.Error()
	}
	if ierr != nil {
		out["info_error"] = ierr.Error()
	}
	if cerr != nil {
		out["counts_error"] = cerr.Error()
	}
	return out, nil
}

// diagProxyPool 返回代理池运行态（v0.8：诊断包导出明文 URL，不掩码）+ 出口失败归因。
func (s *Server) diagProxyPool() map[string]any {
	out := map[string]any{}
	if s == nil || s.m == nil || s.m.traffic == nil {
		out["available"] = false
		return out
	}
	st := s.loadProxyPool()
	eff, blocked := s.effectivePoolEntries(st)
	out["available"] = true
	out["enabled"] = st.Enabled
	out["strategy"] = st.Strategy
	out["total"] = len(st.Entries)
	out["effective"] = len(eff)
	out["socks5_blocked"] = blocked
	out["socks5_allowed"] = s.socks5Allowed()
	out["global_proxy_set"] = s.m.GlobalProxy() != ""
	out["capturing"] = s.m.TrafficEnabled()
	out["usable"] = s.m.traffic.ProxyPoolAvailable()
	// 条目 URL 同样掩码 user:pass（诊断包可能被转发；平台自身凭据不导出）。
	masked := make([]traffic.PoolEntry, len(st.Entries))
	copy(masked, st.Entries)
	for i := range masked {
		masked[i].URL = maskProxyURL(masked[i].URL)
	}
	out["entries"] = masked
	return out
}

// diagToolUsage 返回工具调用统计（可按窗口）。
func diagToolUsage(pg *db.DB, since time.Time) ([]map[string]any, error) {
	return diagQuery(pg, `
		SELECT tool_key AS tool, coalesce(agent_key,'') AS agent, count(*) AS count
		  FROM tool_usage WHERE ts >= $1 GROUP BY 1,2 ORDER BY count(*) DESC LIMIT 200`, since)
}

// diagLLMNote 是给 manifest 的一句提示：flash 档做深挖会显著降低判断力。
func diagLLMNote(usage map[string]any) string {
	rows, _ := usage["by_role_model"].([]map[string]any)
	for _, r := range rows {
		role, _ := r["role"].(string)
		model, _ := r["model"].(string)
		if role == "planner" || role == "worker" {
			if model != "" {
				return fmt.Sprintf("planner/worker 当前使用 %s；深挖/利用链判断建议绑定强推理档（设置 → 模型绑定）。", model)
			}
		}
	}
	return ""
}
