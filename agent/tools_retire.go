package agent

// 退役排队意图（retire_intent，取自上游 Pojun v0.7.0）。
//
// 解决的核心问题是积压：现场实测出现过「71 条 open 意图、worker 只有 3 个、
// 生产:消费 ≈ 2.5:1、最老的排队 6 小时」。模型自己很难主动想到去清理它已经
// 无法成立的意图——尤其当新事实已经否定了某条排队意图的前提时。
//
// 退役不删除证据/血缘，只置为 deleted 并记录原因，之后不会再被 worker 领取。
// 护栏（全部是代码层硬约束，不靠提示词）：
//   - 每轮最多 6 条，避免一轮清空导致链式误伤；
//   - 因「重复」而退役必须给 superseded_by 指向存活意图（禁止指向已退役的
//     ——那会造成覆盖断链）；
//   - 声称「前提失效」时必须在 reason 里引用否定它的事实/finding 节点号。

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

func (t *ToolSet) retireIntent() actool.CoreTool {
	return t.writeExpTool("retire_intent",
		"退役【尚未开始】的排队意图（open）。当你的新事实已否定某条意图的前提时调用，例如目标被证实是死目标、"+
			"真实业务入口已在别处定位到、或该方向已被结论排除。退役不删除证据/血缘，只置为 deleted 并记录原因，"+
			"之后不会再被 worker 领取。正在执行的意图不能退役——先用 kill_work 终止。\n"+
			"护栏：每轮最多 6 条；因『重复』退役必须用 superseded_by 指明存活的替代意图（不能指向已退役的）；"+
			"声称『前提失效』时必须在 reason 里引用否定它的事实/finding 节点号。",
		obj(map[string]any{
			"ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "要退役的意图节点 id（必须是 open 状态，可多条；本轮累计最多 6 条）"},
			"reason": str("退役原因（必填）：写清哪条事实否定了它的前提，或为什么不再需要这条方向"),
			"superseded_by": map[string]any{"type": "array", "items": map[string]any{"type": "integer"},
				"description": "【因重复而退役时必填】替代它的存活意图 id（open/running/done）。禁止指向已 deleted 的意图——那会造成覆盖断链。前提失效类退役不需要填。"},
		}, "ids", "reason"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				IDs          []json.RawMessage `json:"ids"`
				Reason       string            `json:"reason"`
				SupersededBy []json.RawMessage `json:"superseded_by"`
			}
			_ = json.Unmarshal(in, &a)
			ids := pidList(a.IDs)
			reason := strings.TrimSpace(a.Reason)
			sup := pidList(a.SupersededBy)
			if len(ids) == 0 {
				return actool.Errorf("ids 不能为空"), nil
			}
			if reason == "" {
				return actool.Errorf("reason 必填：写清是哪条事实/结论否定了它的前提"), nil
			}
			if remaining := maxIntentRetirePerRun - t.retiredThisRun; remaining <= 0 {
				return actool.Errorf(fmt.Sprintf("本轮退役已达上限 %d 条：先让 worker 消化积压，下一轮再清理（避免一轮清空导致链式误伤）", maxIntentRetirePerRun)), nil
			} else if len(ids) > remaining {
				return actool.Errorf(fmt.Sprintf("本轮最多还能退役 %d 条，本次提交 %d 条：请分轮处理，优先保留证据更完整的替代方向", remaining, len(ids))), nil
			}
			if len(sup) > 0 {
				for _, sid := range sup {
					if sid <= 0 {
						continue
					}
					for _, id := range ids {
						if sid == id {
							return actool.Errorf(fmt.Sprintf("superseded_by 不能指向本次要退役的意图 #%d（自指替代等于没有覆盖）", sid)), nil
						}
					}
					sn, err := t.ts.GetNode(sid)
					if err != nil || sn == nil {
						return actool.Errorf(fmt.Sprintf("superseded_by #%d 不存在：替代必须是本任务已存在的意图", sid)), nil
					}
					if sn.Kind != db.KindIntent {
						return actool.Errorf(fmt.Sprintf("superseded_by #%d 是 %q 节点：只能是意图 id", sid, sn.Kind)), nil
					}
					switch sn.State {
					case "open", "running", "done":
						// 存活替代，可接受
					default:
						return actool.Errorf(fmt.Sprintf("superseded_by #%d 当前状态为 %s：替代已被退役/终止，禁止链式退役（请先确认该覆盖类仍有存活意图或事实兜底）", sid, sn.State)), nil
					}
				}
				reason += "；替代意图：" + joinNodeRefs(sup)
			}
			if reasonClaimsPremiseInvalid(reason) && !t.reasonCitesKnowledge(reason) {
				return actool.Errorf("reason 声称『前提失效/被否定』但没有引用任何现存 fact/finding 节点号：请写出否定它的事实 id，或改为 superseded_by 表达重复"), nil
			}
			retired := []int64{}
			errs := map[string]string{}
			for _, id := range ids {
				key := strconv.FormatInt(id, 10)
				n, err := t.ts.GetNode(id)
				if err != nil || n == nil {
					errs[key] = "意图不存在"
					continue
				}
				if n.Kind != db.KindIntent {
					errs[key] = "不是意图节点：" + n.Kind
					continue
				}
				switch n.State {
				case "open":
					// 可退役
				case "running", "paused":
					errs[key] = "正在执行：先用 kill_work 终止，再退役"
					continue
				default:
					errs[key] = "已是终态（" + n.State + "），无需退役"
					continue
				}
				if _, err := t.ts.SoftDeleteIntent(id, "planner 退役："+reason); err != nil {
					errs[key] = err.Error()
					continue
				}
				t.retiredThisRun++
				retired = append(retired, id)
			}
			out := map[string]any{"retired": retired, "retired_this_round": t.retiredThisRun, "round_limit": maxIntentRetirePerRun}
			if len(errs) > 0 {
				out["errors"] = errs
			}
			return jsonResult(out)
		})
}

const maxIntentRetirePerRun = 6

func reasonClaimsPremiseInvalid(reason string) bool {
	for _, w := range []string{"前提", "否定", "失效", "证伪", "已被回答", "死目标"} {
		if strings.Contains(reason, w) {
			return true
		}
	}
	return false
}

func (t *ToolSet) reasonCitesKnowledge(reason string) bool {
	for _, id := range nodeRefIDs(reason) {
		n, err := t.ts.GetNode(id)
		if err != nil || n == nil {
			continue
		}
		if n.Kind == db.KindFact || n.Kind == db.KindFinding {
			return true
		}
	}
	return false
}


// nodeRefIDs 从自由文本里抠出 #123 形式的节点引用（退役 reason 校验用）。
func nodeRefIDs(s string) []int64 {
	var out []int64
	for i := 0; i < len(s); i++ {
		if s[i] != '#' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j > i+1 {
			if n, err := strconv.ParseInt(s[i+1:j], 10, 64); err == nil && n > 0 && n < 1<<40 {
				out = append(out, n)
			}
		}
		i = j
	}
	return out
}

// joinNodeRefs 把节点 id 列表渲染成 #1/#2 形式（回执文案用）。
func joinNodeRefs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, "#"+strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, "/")
}
