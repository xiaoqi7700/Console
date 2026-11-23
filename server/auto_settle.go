package server

// 统一收尾入口（自动收尾批次）。
//
// 为什么需要「一个入口」：收尾此前散在三处——超时协调器、planner 判定 goal_met、
// 程序化自动收尾（idle/coverage/轮数）。三处各自实现 drain 等待、终局轮、终态
// 判定，行为逐版漂移。这里收敛成 settleTaskWithReason，所有触发源只传 reason。

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// taskGoalProgress 统计目标总数与已达成数（终态判定用）。
func taskGoalProgress(t *Task) (met, total int) {
	if t == nil || t.Store == nil {
		return 0, 0
	}
	goals, err := t.Store.ListByKind(db.KindGoal, 1000)
	if err != nil {
		return 0, 0
	}
	for _, g := range goals {
		total++
		if g.State == "met" {
			met++
		}
	}
	return met, total
}

// settleTerminalStatus 计算收尾终态。
//
// 有目标时以数据库达成情况为准，不看模型自述；无目标任务才参考终局轮判定。
// 「自动收尾统一 done」是「只做了一部分却显示完成」的来源，这里不允许。
func settleTerminalStatus(metGoals, totalGoals int, reason string, finalRoundMet bool) string {
	if totalGoals > 0 {
		if metGoals >= totalGoals {
			return "done"
		}
		return "timeout"
	}
	if reason == "timeout" && !finalRoundMet {
		return "timeout"
	}
	return "done"
}

// warnFindingsWithoutReport 在任务落终态前检查「已上报但详细报告为空」的漏洞。
// 终局之后不再派 worker，这些缺口只能提示人在漏洞页补齐——报告导出时一条
// 空报告漏洞会直接拉低交付质量。
func (e *Engine) warnFindingsWithoutReport(t *Task) {
	if e.m == nil || e.m.pg == nil {
		return
	}
	fs, _, err := e.m.pg.ListFindingsPage(db.FindingFilter{TaskID: t.ID}, 1, 500)
	if err != nil {
		return
	}
	var missing []string
	for _, f := range fs {
		if strings.TrimSpace(f.Report) == "" {
			title := strings.TrimSpace(f.Name)
			if title == "" {
				title = strings.TrimSpace(f.VulnClass)
			}
			if title == "" {
				title = "未分类"
			}
			missing = append(missing, fmt.Sprintf("#%d %s", f.ID, title))
			if len(missing) >= 5 {
				break
			}
		}
	}
	if len(missing) == 0 {
		return
	}
	e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
		Summary: fmt.Sprintf("收尾检查：%d 条漏洞缺少详细报告（%s…），可在漏洞页补齐后再导出", len(missing), strings.Join(missing, "、"))})
}

func (e *Engine) settleTaskWithReason(ctx context.Context, t *Task, reason, detail string) {
	if !e.markSettling(t.ID) {
		return
	}
	t.clearSettle()
	label := reason
	switch reason {
	case "timeout":
		label = "到达超时上限"
	case "goal_met":
		label = "planner 判定目标达成且无在跑意图"
	case "auto_idle", "auto_coverage", "auto_rounds":
		label = "自动收尾：" + detail
	}
	log.Printf("[settle] task %s 进入收尾（%s）", t.ID, label)
	if reason != "timeout" {
		e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("自动收尾：%s", detail)})
	}
	// ④ 等在跑 worker/planner drain(在跑 run 因夹逼的 MaxDuration 自行进收尾);
	// 超过 grace 仍未清空 → 硬 cancel 该任务 exec ctx(settling-aware 分支正确归类)。
	hardStop := time.Now().Add(settleDrainGrace)
	for e.inflightCount(t.ID) > 0 {
		if time.Now().After(hardStop) {
			log.Printf("[settle] task %s drain 超时(%s),硬取消在跑 run", t.ID, settleDrainGrace)
			e.cancelExec(t.ID, agent.AbortSettleDrainTimeout)
			_ = sleepCtx(ctx, 3*time.Second) // 给 worker 分支一点时间落库/归类
			break
		}
		if sleepCtx(ctx, 500*time.Millisecond) {
			return // 引擎整体关停
		}
	}

	// ⑤ 终局一轮 planner。goal_met 已经是 planner 的最终判定，不再多跑一轮；
	// timeout 用超时收尾词，自动收尾用“按策略收尾”词。
	met := reason == "goal_met"
	if reason != "goal_met" {
		met = e.runFinalPlannerRound(ctx, t)
	}
	if !e.beginTaskOperation(t.ID) {
		// 删除屏障/并发操作挡住了终态落库。settling 已经置位（planner/worker 都已停止），
		// 若不清掉，删除 abort 回滚后任务会永久卡在 settling：planner 每轮直接 return、
		// worker 空转、deadline 协调器已退出，只能重启进程。清掉后下一轮可重新收尾。
		e.settling.Delete(t.ID)
		t.requestSettle(reason, detail) // 删除回滚后下一轮继续收尾，不能把触发丢掉
		log.Printf("[settle] task %s 落终态时被删除屏障挡住，已清除 settling 等待重试", t.ID)
		return
	}
	defer e.decInflight(t.ID)

	// ⑤′ 落终态前点名缺报告的漏洞（终局后不再派 worker，只能提示人补齐）。
	e.warnFindingsWithoutReport(t)

	// ⑥ 定终态(带守卫)：有目标时以数据库的达成情况为准（见 settleTerminalStatus）。
	// 红队版 v0.6.31 下放：自动收尾（idle/coverage/轮数）与 goal_met 在目标未达成时
	// 一律落 timeout，由界面显示「未完成·已停止」——旧的「自动收尾统一 done」正是
	// 「只做了一部分却显示完成」的来源。
	metGoals, totalGoals := taskGoalProgress(t)
	status := settleTerminalStatus(metGoals, totalGoals, reason, met)
	if status == "timeout" && metGoals < totalGoals {
		log.Printf("[settle] task %s 目标未全部达成(%d/%d)，终态记 timeout（未完成）而非 done", t.ID, metGoals, totalGoals)
	}
	won, err := e.m.SetTaskStatusGuarded(t.ID, status)
	switch {
	case err != nil:
		// 终态写库失败：清掉 settling 并重新登记，避免任务永久卡在收尾中。
		e.settling.Delete(t.ID)
		t.requestSettle(reason, detail)
		log.Printf("[settle] task %s 落终态失败（已安排重试）: %v", t.ID, err)
	case won:
		log.Printf("[settle] task %s 收尾完成,终态=%s（%s）", t.ID, status, label)
		// 任务到终态后后台作业不应继续打目标（授权窗口结束）。
		if n := agent.KillJobsForTaskDir(filepath.Join(e.m.dir, "tasks", t.ID)); n > 0 {
			log.Printf("[settle] task %s 收尾时清理后台作业 %d 个", t.ID, n)
		}
		e.emitActivity(t, db.Activity{Worker: "system", Kind: "text",
			Summary: fmt.Sprintf("任务收尾完成：%s；终态 %s", label, status)})
	default:
		log.Printf("[settle] task %s 收尾时已是终态,保留原状态", t.ID)
	}
}
