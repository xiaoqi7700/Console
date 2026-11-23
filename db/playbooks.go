package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	neturl "net/url"
	"strings"
	"time"
)

// Playbook 武器库（v0.4.94 经验层，Voyager 范式落地）：validator PASS 的
// critical/high 漏洞上报时，自动把成功攻击链快照入库；同类目标（同技术栈/
// 同根域）派新意图时按 Top3 检索注入 planner 态势——「平台越用越强」。
//
// steps 是代码组装的快照（不用 LLM 提炼）：意图原文 + 假设/判据 + 关键事实
// + 机验标记，全部事实已在库。明确不做：LLM 提炼、管理 UI（v0.4.95）。

// PlaybookStep 是一条成功攻击链的快照单元。
type PlaybookStep struct {
	Intent          string   `json:"intent"`                     // 产出该漏洞的意图原文
	Hypothesis      string   `json:"hypothesis,omitempty"`       // 意图假设
	SuccessCriteria string   `json:"success_criteria,omitempty"` // 成功判据
	Facts           []string `json:"facts,omitempty"`            // 支撑该漏洞的关键 fact 文本
	EvidenceExcerpt string   `json:"evidence_excerpt,omitempty"` // 证据前 500 字
	ValidateMarker  string   `json:"validate_marker,omitempty"`  // validate:<token>:pass
}

// Playbook 是一条可复用的成功攻击链。
type Playbook struct {
	ID         int64          `json:"id"`
	Name       string         `json:"name"`
	VulnClass  string         `json:"vulnclass"`
	Severity   string         `json:"severity"`
	RootDomain string         `json:"root_domain,omitempty"`
	Techs      []string       `json:"techs,omitempty"`
	URLPattern string         `json:"url_pattern,omitempty"` // 归一化路径模式（数字/hex 归一）
	Steps      []PlaybookStep `json:"steps"`
	FindingID  int64          `json:"finding_id,omitempty"`
	TaskID     int64          `json:"task_id,omitempty"`
	UsedCount  int            `json:"used_count"`
	LastUsedAt *time.Time     `json:"last_used_at,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
}

// playbookFindingRow 是 CapturePlaybook 内部的 finding 快照。
type playbookFindingRow struct {
	VulnClass string
	Severity  string
	Name      string
	Summary   string
	Evidence  string
	NodeID    sql.NullInt64
	AssetIDs  []byte
}

// EnsurePlaybookSchema 建表/索引（幂等，测试与老库共用）。
func (d *DB) EnsurePlaybookSchema() error {
	_, err := d.Exec(`
CREATE TABLE IF NOT EXISTS playbooks (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    key         TEXT NOT NULL DEFAULT '',
    vulnclass   TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    root_domain TEXT NOT NULL DEFAULT '',
    techs       TEXT[] NOT NULL DEFAULT '{}',
    url_pattern TEXT NOT NULL DEFAULT '',
    steps       JSONB NOT NULL DEFAULT '[]',
    finding_id  BIGINT,
    task_id     BIGINT,
    used_count  INTEGER NOT NULL DEFAULT 1,
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_playbooks_key ON playbooks(key, root_domain);
CREATE INDEX IF NOT EXISTS idx_playbooks_tech ON playbooks USING gin(techs);
`)
	return err
}

// playbookKey 归一化去重键：vulnclass + 路径模式（数字段→N、hex 段→H）。
// 同类漏洞同路径模式 = 同一条经验，used_count++ 而不是堆行。
func playbookKey(vulnclass, url string) string {
	u, err := neturl.Parse(url)
	if err != nil {
		return strings.ToLower(vulnclass)
	}
	var segs []string
	for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if seg == "" {
			continue
		}
		switch {
		case simUUIDRE.MatchString(seg):
			segs = append(segs, "U")
		case simHexRE.MatchString(seg):
			segs = append(segs, "H")
		case simNumRE.MatchString(seg):
			segs = append(segs, "N")
		default:
			segs = append(segs, strings.ToLower(seg))
		}
	}
	return strings.ToLower(vulnclass) + "|" + strings.Join(segs, "/")
}

// playbookURLPattern 归一化 URL 路径模式（去 query）。
func playbookURLPattern(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return ""
	}
	var segs []string
	for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if seg == "" {
			continue
		}
		switch {
		case simUUIDRE.MatchString(seg):
			segs = append(segs, "U")
		case simHexRE.MatchString(seg):
			segs = append(segs, "H")
		case simNumRE.MatchString(seg):
			segs = append(segs, "N")
		default:
			segs = append(segs, strings.ToLower(seg))
		}
	}
	return strings.Join(segs, "/")
}

// CapturePlaybook 从一条已入库的 finding 组装并入库 playbook（agent 上报回调
// 调用）。同 key+root_domain 已存在 → used_count++ / 合并 techs / severity 取
// 更严重者 / steps 追加（上限 5 条防膨胀）。
// 组装内容全部来自库内事实：finding 本体 + 绑定资产（technologies/URL）+
// 源意图（derived_from 回溯的 hypothesis/success_criteria/原文）+ 机验标记。
func (d *DB) CapturePlaybook(taskID int64, findingID int64, validateMarker string) (int64, error) {
	if d == nil {
		return 0, fmt.Errorf("db nil")
	}
	var f playbookFindingRow
	err := d.QueryRow(`SELECT vulnclass, severity, name, summary, evidence, node_id, asset_ids FROM findings WHERE id=$1`, findingID).
		Scan(&f.VulnClass, &f.Severity, &f.Name, &f.Summary, &f.Evidence, &f.NodeID, &f.AssetIDs)
	if err != nil {
		return 0, fmt.Errorf("finding %d 不存在: %w", findingID, err)
	}
	// 绑定资产：URL 与技术栈（取第一个带 URL 的）
	var rootDomain, url string
	var techs []string
	if len(f.AssetIDs) > 0 {
		var ids []int64
		if json.Unmarshal(f.AssetIDs, &ids) == nil && len(ids) > 0 {
			row := d.QueryRow(`SELECT COALESCE(root_domain,''), COALESCE(url,''), COALESCE(technologies,'{}'::text[]) FROM assets WHERE id=$1`, ids[0])
			if err := row.Scan(&rootDomain, &url, &techs); err != nil {
				techs = nil
			}
		}
	}
	urlPattern := playbookURLPattern(url)
	step := PlaybookStep{EvidenceExcerpt: clipStrPlaybook(f.Evidence, 500), ValidateMarker: validateMarker}
	if f.NodeID.Valid {
		// 源意图快照：finding 节点沿 derived_from 回溯 intent 节点
		var text, payload string
		err := d.QueryRow(`
SELECT COALESCE(payload->>'text',''), COALESCE(payload->>'summary','')
FROM exploration_nodes WHERE id = (
    SELECT parent_id FROM exploration_edges WHERE child_id = $1 AND rel = 'derived_from' LIMIT 1
)`, f.NodeID.Int64).Scan(&text, &payload)
		if err == nil {
			step.Intent = text
			var ip struct {
				Hypothesis      string `json:"hypothesis"`
				SuccessCriteria string `json:"success_criteria"`
			}
			if json.Unmarshal([]byte(payload), &ip) == nil {
				step.Hypothesis = ip.Hypothesis
				step.SuccessCriteria = ip.SuccessCriteria
			}
		}
		// 关键 facts：与 finding 同父的前置 fact 节点（≤3 条）
		factRows, ferr := d.Query(`
SELECT COALESCE(payload->>'text','') FROM exploration_nodes
WHERE kind='fact' AND id IN (
    SELECT parent_id FROM exploration_edges WHERE child_id = $1 AND rel='derived_from'
) ORDER BY id LIMIT 3`, f.NodeID.Int64)
		if ferr == nil {
			defer factRows.Close()
			for factRows.Next() {
				var t string
				if factRows.Scan(&t) == nil && strings.TrimSpace(t) != "" {
					step.Facts = append(step.Facts, clipStrPlaybook(t, 200))
				}
			}
		}
	}
	stepsJSON, err := json.Marshal([]PlaybookStep{step})
	if err != nil {
		return 0, err
	}
	name := fmt.Sprintf("%s · %s", f.VulnClass, firstNonEmpty(f.Name, clipStrPlaybook(f.Summary, 60), urlPattern))
	key := playbookKey(f.VulnClass, url)

	// severity 取新旧更严重者（Go 侧定级，避免依赖自定义 SQL 函数）。
	sev := f.Severity
	var oldSev string
	_ = d.QueryRow(`SELECT severity FROM playbooks WHERE key=$1 AND root_domain=$2`, key, rootDomain).Scan(&oldSev)
	if severityRank(oldSev) < severityRank(sev) {
		sev = oldSev
	}
	var id int64
	err = d.QueryRow(`
INSERT INTO playbooks(name, key, vulnclass, severity, root_domain, techs, url_pattern, steps, finding_id, task_id)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9,$10)
ON CONFLICT (key, root_domain) DO UPDATE SET
    used_count = playbooks.used_count + 1,
    last_used_at = now(),
    techs = (SELECT ARRAY(SELECT DISTINCT unnest(playbooks.techs || EXCLUDED.techs))),
    severity = $11,
    steps = CASE WHEN jsonb_array_length(playbooks.steps) < 5
                 THEN playbooks.steps || EXCLUDED.steps ELSE playbooks.steps END
RETURNING id`,
		name, key, f.VulnClass, sev, rootDomain, techs, urlPattern, stepsJSON, findingID, taskID, sev,
	).Scan(&id)
	return id, err
}

// MatchPlaybooks 检索同类目标的历史成功先例：vulnclass 精确或技术栈交集，
// Top limit 按 used_count DESC；root_domain 相同的排前（同目标族可信度最高）。
func (d *DB) MatchPlaybooks(vulnclass string, techs []string, rootDomain string, limit int) []Playbook {
	if d == nil || limit <= 0 {
		return nil
	}
	rows, err := d.Query(`
SELECT id, name, vulnclass, severity, COALESCE(root_domain,''), techs, COALESCE(url_pattern,''),
       steps, used_count, last_used_at
FROM playbooks
WHERE vulnclass = $1
   OR techs && $2::text[]
ORDER BY (root_domain = $3) DESC, used_count DESC, last_used_at DESC NULLS LAST
LIMIT $4`, vulnclass, techs, rootDomain, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Playbook
	for rows.Next() {
		var p Playbook
		var stepsJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.VulnClass, &p.Severity, &p.RootDomain, &p.Techs,
			&p.URLPattern, &stepsJSON, &p.UsedCount, &p.LastUsedAt); err != nil {
			continue
		}
		_ = json.Unmarshal(stepsJSON, &p.Steps)
		out = append(out, p)
	}
	return out
}

// MarkPlaybookUsed 显式记录一次「先例被参考」。
func (d *DB) MarkPlaybookUsed(id int64) {
	if d == nil || id <= 0 {
		return
	}
	_, _ = d.Exec(`UPDATE playbooks SET used_count = used_count + 1, last_used_at = now() WHERE id=$1`, id)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func clipStrPlaybook(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// severityRank 越严重越大（critical=4）；用于 playbook severity 取更严重者。
func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}
