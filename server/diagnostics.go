package server

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ═══ 诊断包 v2（v0.6.32）═══
//
// 目标：客户环境出问题时，一份 zip 就能回答「任务为什么停、意图为什么烧、worker 卡在哪、
// 日志被什么刷屏、漏洞到底有没有入库」。全部只读；不含 LLM/代理凭据、流量正文、漏洞证据正文。
//
// 与 v1 的差异：
//   - 修 findings 恒为 [] 的 SQL 类型错误（BIGINT → text），并给每条查询保留错误；
//   - 补 tasks 全字段、goals、intents、activity、engine 快照、traffic、proxy_pool、
//     findings_debug、integrity（表行数/schema 列）、logs 分层聚合（panic 不再淹没日志）；
//   - settings 里的代理 URL 掩码；
//   - ?detail=1 放大轨迹/日志/事实窗口；总包仍控制在几 MB 量级。
//
// 行数上限按 detail 分层；每节独立，某节失败不影响其它节，错误写进 manifest。

const diagnosticsFormatVersion = 2

// startTime 近似进程启动时刻（包初始化即记；诊断包里的 uptime 是排查参考值）。
var startTime = time.Now()

type diagnosticsOptions struct {
	Detail bool
	Since  time.Time
}

func diagnosticsOptionsFrom(r *http.Request) diagnosticsOptions {
	q := r.URL.Query()
	opts := diagnosticsOptions{Detail: q.Get("detail") == "1" || q.Get("detail") == "true"}
	opts.Since = time.Now().Add(-24 * time.Hour)
	switch strings.TrimSpace(q.Get("since")) {
	case "1h":
		opts.Since = time.Now().Add(-time.Hour)
	case "7d":
		opts.Since = time.Now().Add(-7 * 24 * time.Hour)
	case "all":
		opts.Since = time.Unix(0, 0)
	case "24h", "":
	}
	return opts
}

type diagSection struct {
	Data      any
	Rows      int
	Truncated bool
	Error     string
}

type diagBuilder struct {
	opts     diagnosticsOptions
	sections map[string]*diagSection
	order    []string
	notes    []string
}

func newDiagBuilder(opts diagnosticsOptions) *diagBuilder {
	return &diagBuilder{opts: opts, sections: map[string]*diagSection{}}
}

func (b *diagBuilder) add(key string, data any, rows int, err error) {
	sec := &diagSection{Data: data, Rows: rows}
	if err != nil {
		sec.Error = err.Error()
	}
	b.sections[key] = sec
	b.order = append(b.order, key)
}

func (b *diagBuilder) addTruncated(key string, data any, rows int, truncated bool, err error) {
	b.add(key, data, rows, err)
	if b.sections[key] != nil {
		b.sections[key].Truncated = truncated
	}
}

func (b *diagBuilder) note(s string) {
	if strings.TrimSpace(s) != "" {
		b.notes = append(b.notes, s)
	}
}

// collectDiagnostics 采集全部诊断节。pg 为 nil 时只回 meta/settings/engine/proxy 这类
// 不依赖数据库的部分（与旧实现一致）。
func (s *Server) collectDiagnostics(opts diagnosticsOptions) *diagBuilder {
	b := newDiagBuilder(opts)
	pg := s.m.pg
	b.add("meta", diagMeta(pg), 1, nil)
	b.add("settings", s.diagSettings(), 1, nil)
	b.add("engine", s.engine.Snapshot(), 0, nil)
	b.add("proxy_pool", s.diagProxyPool(), 0, nil)
	if s.m.traffic != nil {
		b.add("traffic", s.m.traffic.DiagnosticsStats(opts.Since.Unix(), map[bool]int{true: 200, false: 50}[opts.Detail]), 0, nil)
	} else {
		b.add("traffic", map[string]any{"enabled": false}, 0, nil)
	}
	if pg == nil {
		return b
	}

	tasks, err := diagTasks(pg)
	b.add("tasks", tasks, len(tasks), err)
	goals, err := diagGoals(pg)
	b.add("goals", goals, len(goals), err)

	intentLimit := 1000
	if opts.Detail {
		intentLimit = 5000
	}
	intents, err := diagIntents(pg, intentLimit, opts.Since)
	b.addTruncated("intents", intents, len(intents), len(intents) >= intentLimit, err)

	findingLimit := 5000
	if opts.Detail {
		findingLimit = 20000
	}
	findings, err := diagFindings(pg, findingLimit, opts.Since)
	b.addTruncated("findings", findings, len(findings), len(findings) >= findingLimit, err)
	fdebug, ferr := diagFindingsDebug(pg)
	b.add("findings_debug", fdebug, 1, ferr)

	factLimit := 1000
	if opts.Detail {
		factLimit = 5000
	}
	facts, err := diagFacts(pg, factLimit, opts.Since)
	b.addTruncated("facts", facts, len(facts), len(facts) >= factLimit, err)

	actLimit := 1000
	if opts.Detail {
		actLimit = 5000
	}
	activity, err := diagActivity(pg, actLimit, opts.Since)
	b.addTruncated("activity", activity, len(activity), len(activity) >= actLimit, err)

	tlLimit := 1000
	if opts.Detail {
		tlLimit = 5000
	}
	timeline, err := diagTimeline(pg, tlLimit, opts.Since)
	b.addTruncated("timeline", timeline, len(timeline), len(timeline) >= tlLimit, err)

	autopilot, err := diagQuery(pg, `
		SELECT COALESCE(task_id,'') AS task_id, kind, left(COALESCE(detail,''),300) AS detail, created_at
		  FROM autopilot_events WHERE created_at >= $1 ORDER BY id DESC LIMIT $2`, opts.Since, tlLimit)
	b.addTruncated("autopilot_events", autopilot, len(autopilot), len(autopilot) >= tlLimit, err)

	llm, err := diagLLMUsage(pg, opts.Since)
	b.add("llm_usage", llm, 0, err)
	b.note(diagLLMNote(llm))

	tools, err := diagToolUsage(pg, opts.Since)
	b.add("tool_usage", tools, len(tools), err)

	logs, err := diagLogs(pg, opts.Since, opts.Detail)
	if logs != nil {
		logs["dropped_flood"] = logSink.DroppedLogs()
		logs["dropped_db"] = logSink.dbDropped.Load()
	}
	b.add("logs", logs, 0, err)

	integrity, err := diagIntegrity(pg)
	b.add("integrity", integrity, 0, err)

	// 拦截：读真实审批行并带上规则/判定来源；空表是正常（没有命中规则的调用不进此表）。
	intercept, err := diagQuery(pg, `
		SELECT p.id::text AS id, COALESCE(p.task_id,'') AS task_id, COALESCE(p.tool_name,'') AS tool_name,
		       COALESCE(p.status,'') AS status, COALESCE(p.rule_id::text,'') AS rule_id,
		       COALESCE(r.name,'') AS rule_name, COALESCE(p.decision_source,'') AS decision_source,
		       left(COALESCE(p.reason,''),300) AS reason, p.created_at, p.decided_at
		  FROM intercept_pending p LEFT JOIN intercept_rules r ON r.id=p.rule_id
		 WHERE p.created_at >= $1 ORDER BY p.id DESC LIMIT $2`, opts.Since, 300)
	b.add("intercept_audit", intercept, len(intercept), err)
	return b
}

// handleDiagnosticsExport GET /api/diagnostics/export[?detail=1&since=24h] —— 下载诊断包 zip。
func (s *Server) handleDiagnosticsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, 405, "method not allowed")
		return
	}
	opts := diagnosticsOptionsFrom(r)
	b := s.collectDiagnostics(opts)

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="pojun-diagnostics-%s%s.zip"`, time.Now().Format("20060102-150405"),
			map[bool]string{true: "-detail", false: ""}[opts.Detail]))
	w.WriteHeader(200)

	zw := zip.NewWriter(w)
	manifest := map[string]any{
		"format_version": diagnosticsFormatVersion,
		"generated_at":   time.Now().Format(time.RFC3339),
		"detail":         opts.Detail,
		"since":          opts.Since.Format(time.RFC3339),
		"sections":       map[string]any{},
		"notes":          b.notes,
	}
	for _, key := range b.order {
		sec := b.sections[key]
		data, err := json.MarshalIndent(sec.Data, "", "  ")
		if err != nil {
			sec.Error = "marshal: " + err.Error()
			data = []byte("null")
		}
		f, err := zw.Create(key + ".json")
		if err != nil {
			continue
		}
		_, _ = f.Write(data)
		manifest["sections"].(map[string]any)[key] = map[string]any{
			"rows": sec.Rows, "bytes": len(data), "truncated": sec.Truncated, "error": sec.Error,
		}
	}
	// 说明文件放在最后写，manifest 里已含所有节的错误/截断标记。
	mf, err := zw.Create("manifest.json")
	if err == nil {
		if data, merr := json.MarshalIndent(manifest, "", "  "); merr == nil {
			_, _ = mf.Write(data)
		}
	}
	_ = zw.Close()
}

// ── 小工具：写进 zip 的缓冲与键排序（保留给测试/旧调用）──

type byteWriter struct{ b []byte }

func newByteWriter() *byteWriter { return &byteWriter{} }

func (w *byteWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func (w *byteWriter) Bytes() []byte { return w.b }

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
