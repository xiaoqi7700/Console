package agent

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// 变体分析意图族（v0.4.94 经验层，方向调研批次三）：validator PASS 的 critical/high
// 漏洞上报时，用资产 SimHash 找同 root_domain 下「同模式」端点，自动派 1-2 条
// 「变体验证」意图——Naptime 变体分析 + 同族迁移（planner.go:397）的确定性下限。
// planner 的 prompt 纪律保留；代码派生保证哪怕模型不自觉，变体也会被扫到。

// validateMarkerRE 与 evidence_check 的机验项同一套标记格式。
var validateMarkerRE = regexp.MustCompile(`validate:[0-9a-f]{8}:pass`)

// host 注入的 db 通道（assembly.go 接线）。nil = 不介入（经验层整体关闭）。
var (
	// CapturePlaybookFn 校验通过的 critical/high 上报 → playbook 入库。
	CapturePlaybookFn func(taskID int64, findingID int64, marker string) (int64, error)
	// FindingAssetInfoFn 查 finding 绑定资产的分簇信息（root_domain/simhash/techs/URL/资产ID）。
	FindingAssetInfoFn func(findingID int64) (rootDomain string, simhash int64, techs []string, assetURL string, assetID int64, ok bool)
	// SimilarEndpointsFn 同簇端点查询（db.SimilarHTTPEndpoints）。
	SimilarEndpointsFn func(rootDomain string, simhash int64, excludeID int64, limit int) ([]db.Asset, error)
	// VariantIntentsEnabledFn settings 开关（默认开）。
	VariantIntentsEnabledFn func() bool
)

// ValidateMarkerFromEvidence 提取 evidence 里的机验标记（第一个）。
func ValidateMarkerFromEvidence(evidence string) string {
	if m := validateMarkerRE.FindString(evidence); m != "" {
		return m
	}
	return ""
}

// DispatchVariantIntests 派发变体验证意图族（报告回调调用）。
// 门禁：开关开 + severity≥high + evidence 含机验 PASS 标记 + 有绑定资产；
// 候选 = 同簇端点（排除源资产），取 2 个；防重派复用 FindSimilarOpenIntent
// （经 addOneIntent 的既有三闸）。返回派发数量与提示（进 finding 回执）。
func DispatchVariantIntents(ts *ToolSet, vulnClass, severity, evidence string, findingNodeID, intentID int64, assetIDs []int64) (int, string) {
	if VariantIntentsEnabledFn == nil || !VariantIntentsEnabledFn() {
		return 0, ""
	}
	if severity != "critical" && severity != "high" {
		return 0, ""
	}
	marker := ValidateMarkerFromEvidence(evidence)
	if marker == "" {
		return 0, "" // 没有机验证据不派变体——先做程序化验证
	}
	if FindingAssetInfoFn == nil || SimilarEndpointsFn == nil || ts == nil {
		return 0, ""
	}
	findingID := findingNodeID
	rootDomain, simhash, _, _, srcAssetID, ok := FindingAssetInfoFn(findingID)
	if !ok || rootDomain == "" || simhash == 0 {
		return 0, ""
	}
	cands, err := SimilarEndpointsFn(rootDomain, simhash, srcAssetID, 2)
	if err != nil || len(cands) == 0 {
		return 0, ""
	}
	dispatched, notes := 0, ""
	for _, cand := range cands {
		summary := "变体验证：在 " + cand.URL + " 复现 " + vulnClass + " 同模式（同簇端点，SimHash 汉明距离 ≤6）"
		hypothesis := "同 root_domain 下结构同模式的端点大概率复用同一实现，存在同漏洞变体"
		criteria := "validate_finding 在该端点输出 pass 标记（同漏洞类同探针），或确认该端点实现不同/已修复并写回 fact"
		item := intentItem{
			Summary:         summary,
			Dimension:       inferDimension(vulnClass + " " + summary),
			Priority:        6,
			AssetIDs:        []json.RawMessage{json.RawMessage(strconv.FormatInt(cand.ID, 10))},
			ParentIDs:       []json.RawMessage{json.RawMessage(strconv.FormatInt(findingNodeID, 10))},
			Hypothesis:      hypothesis,
			SuccessCriteria: criteria,
		}
		if nid, err := ts.addOneIntent(item); err == nil && nid > 0 {
			dispatched++
			notes += " 变体意图 #" + strconv.FormatInt(nid, 10) + " → " + cand.URL + "。"
		}
	}
	if dispatched > 0 {
		notes = "已自动派发 " + itoaVariant(dispatched) + " 条同模式变体验证意图（SimHash 同簇端点）。" + notes
	}
	return dispatched, notes
}

func itoaVariant(n int) string { return strconv.Itoa(n) }

// PlaybookInjectEnabledFn settings 开关（默认开）：planner 态势是否注入历史先例。
var PlaybookInjectEnabledFn func() bool

// MatchPlaybooksFn 检索先例（db.MatchPlaybooks）。nil = 经验层关闭。
var MatchPlaybooksFn func(vulnClass string, techs []string, rootDomain string, limit int) []db.Playbook

// TaskRootAndTechsFn 任务根域与资产技术栈快照（planner 注入的匹配键）。
var TaskRootAndTechsFn func(taskID int64) (rootDomain string, techs []string)

// renderPlaybookPriorities 组装「历史成功先例」态势块（planner 每轮注入）。
// 无匹配/开关关/钩子未接线 → 空串。
func renderPlaybookPriorities(taskID int64) string {
	if PlaybookInjectEnabledFn == nil || !PlaybookInjectEnabledFn() || MatchPlaybooksFn == nil || TaskRootAndTechsFn == nil || taskID <= 0 {
		return ""
	}
	rootDomain, techs := TaskRootAndTechsFn(taskID)
	pbs := MatchPlaybooksFn("", techs, rootDomain, 3) // 空 vulnclass → 走 techs 交集优先
	if len(pbs) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n【历史成功先例（playbook 武器库：同类目标已验证成功的攻击链，可直接参考复用）】：\n")
	for _, p := range pbs {
		fmt.Fprintf(&b, "- %s（%s/%s，同域=%v，复用 %d 次）：", p.Name, p.VulnClass, p.Severity, p.RootDomain == rootDomain, p.UsedCount)
		if len(p.Steps) > 0 {
			fmt.Fprintf(&b, "%s", clipStrVariant(p.Steps[0].Intent, 160))
		}
		if p.URLPattern != "" {
			fmt.Fprintf(&b, " · 路径模式 /%s", p.URLPattern)
		}
		b.WriteString("\n")
	}
	b.WriteString("（若当前资产结构与之同构，优先复用该打法；参考过的先例不必重复确认——直接按它派验证意图。）\n")
	return b.String()
}

// clipStrVariant 截断文案（经验层内部用，避免与 db 层重名）。
func clipStrVariant(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
