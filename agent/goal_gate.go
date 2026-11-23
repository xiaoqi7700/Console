package agent

import (
	"encoding/json"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// capabilityGoalTerms 是「目标要求拿到实际能力/高危结果」的关键词。命中这些
// 词的目标不能用「未发现入口」这类否定性事实或 low/medium 信息发现来证明，
// 否则 planner 可以借 prove_goal 把所有目标标 met，绕过 goal_met 的收官闸门，
// 让任务以 done 结束而实际没有拿到要求的能力。
//
// 只列结果性词，不列「管理员」这种会出现在侦察目标里的宽泛词。
var capabilityGoalTerms = []string{
	"rce", "远程代码执行", "命令执行", "代码执行",
	"getshell", "webshell", "反弹shell", "反弹 shell", "reverse shell",
	"控制权", "管理员权限", "管理员控制权", "管理员凭据", "domain admin",
	"root权限", "root 权限", "提权", "privilege escalation",
	"立足点", "foothold", "敏感数据", "数据泄露", "高危数据", "越权访问", "越权泄露", "敏感信息泄露",
}

// capabilityGoalNegativePhrases 表示目标是「确认是否存在/排查」，不是「拿到」。
// 这类目标用否定性 fact 证明是合法的，不能套用能力型门槛。
var capabilityGoalNegativePhrases = []string{
	"是否存在", "是否可", "确认是否", "排查", "探测", "评估是否存在",
	"有无", "whether", "check if", "test if", "probe for",
}

// goalRequiresCapabilityEvidence reports whether the goal text demands a
// capability/high-impact outcome rather than a yes/no existence check.
func goalRequiresCapabilityEvidence(text string) bool {
	t := strings.ToLower(strings.TrimSpace(text))
	if t == "" {
		return false
	}
	for _, neg := range capabilityGoalNegativePhrases {
		if strings.Contains(t, neg) {
			return false
		}
	}
	for _, term := range capabilityGoalTerms {
		if strings.Contains(t, term) {
			return true
		}
	}
	return false
}

// goalText extracts the human-readable text from a goal node payload.
func goalText(n *db.Node) string {
	if n == nil {
		return ""
	}
	var p struct {
		Text string `json:"text"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return p.Text
}

// findingSeverity extracts a finding node's severity from its payload. Finding
// nodes are created with {"severity": ...} alongside the report payload.
func findingSeverity(n *db.Node) string {
	if n == nil || n.Kind != db.KindFinding {
		return ""
	}
	var p struct {
		Severity string `json:"severity"`
	}
	_ = json.Unmarshal(n.Payload, &p)
	return strings.ToLower(strings.TrimSpace(p.Severity))
}

// capabilityEvidenceError returns a non-empty message when a capability goal is
// being proved by evidence that cannot demonstrate the claimed capability.
func capabilityEvidenceError(goal, evidence *db.Node) string {
	if !goalRequiresCapabilityEvidence(goalText(goal)) {
		return ""
	}
	if evidence == nil || evidence.Kind != db.KindFinding {
		return "该目标要求拿到实际能力/高危结果（如 RCE、命令执行、控制权、敏感数据），evidence_id 必须是 high/critical 的漏洞节点；普通 fact（包括「未发现入口」这类否定结论）不能证明此类目标。请先用 report_finding 记录可验证的 high/critical 漏洞，再用 prove_goal 关联。"
	}
	sev := findingSeverity(evidence)
	if sev != "high" && sev != "critical" {
		return "该目标要求拿到实际能力/高危结果，当前关联漏洞的 severity 是「" + sev + "」；必须用 high/critical 的漏洞节点证明，low/medium 信息发现不足以证明能力型目标。"
	}
	return ""
}
