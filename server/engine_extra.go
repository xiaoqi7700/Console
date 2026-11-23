package server

// 引擎内存态快照与自主推进看门狗状态（移植自上游 Pojun）。
// 诊断包需要一次拿到「哪些任务在跑、几个 worker、卡在哪一轮、是否在收尾」，
// 靠翻日志拼不出来。

import (
	"sort"
	"sync/atomic"
)

// EngineTaskSnapshot 是一个任务的引擎内存态。
type EngineTaskSnapshot struct {
	TaskID         string  `json:"task_id"`
	WorkersTarget  int64   `json:"workers_target"`
	Inflight       int64   `json:"inflight"`
	PlannerRound   int     `json:"planner_round"`
	RunningIntents []int64 `json:"running_intents"`
	Settling       bool    `json:"settling"`
	Paused         bool    `json:"paused"`
	Deleting       bool    `json:"deleting"`
	DeadlineUnix   int64   `json:"deadline_unix"`
}

// Snapshot 返回所有已启动任务的引擎内存态。锁顺序：先 runtimeMu 取任务集合，
// 再逐个读 sync.Map，避免与 kill/steer 长时间互斥。
func (e *Engine) Snapshot() []EngineTaskSnapshot {
	if e == nil {
		return nil
	}
	ids := make([]string, 0, 16)
	e.runtimeMu.Lock()
	for id := range e.runtimes {
		ids = append(ids, id)
	}
	e.runtimeMu.Unlock()
	sort.Strings(ids)
	out := make([]EngineTaskSnapshot, 0, len(ids))
	for _, id := range ids {
		s := EngineTaskSnapshot{TaskID: id}
		if v, ok := e.inflight.Load(id); ok {
			s.Inflight = atomic.LoadInt64(v.(*int64))
		}
		if v, ok := e.plannerRound.Load(id); ok {
			s.PlannerRound, _ = v.(int)
		}
		if v, ok := e.settling.Load(id); ok {
			s.Settling, _ = v.(bool)
		}
		if v, ok := e.paused.Load(id); ok {
			s.Paused, _ = v.(bool)
		}
		if v, ok := e.deleting.Load(id); ok {
			s.Deleting, _ = v.(bool)
		}
		if v, ok := e.deadline.Load(id); ok {
			s.DeadlineUnix, _ = v.(int64)
		}
		out = append(out, s)
	}
	return out
}
