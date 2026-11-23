package agent

import (
	"context"
	"iter"
	"sync"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// 流空闲看门狗（v0.4.96，对照内部版 v0.9.50）：LLM 网关偶发「连接活着但不再发
// 字节」的断流——SDK 的读循环纯阻塞，Pojun 侧既有的同 provider 重试又只在「未提交
// 输出」时生效，卡死的流会一直挂着直到任务超时。装饰器监视频道产出间隔：超过
// idle 未有任何事件 → cancel 派生 context 断开底层流 → 错误冒泡为可重试瞬时故障，
// 由 task_llm 的重试层承接（norma fork 零改动）。
//
// Complete 不需要装饰——它有整体超时与同步返回，不存在「挂着不给字节」的窗口。

const defaultStreamIdleTimeout = 180 * time.Second

// WithStreamIdleWatchdog 给 provider 的 Stream 路径包一层空闲看门狗。
// idle<=0 用默认 180s。装饰在 provider 构建链内层（Retry 之下），断流错误
// 由重试层按瞬时故障重放。
func WithStreamIdleWatchdog(prov llm.Provider, idle time.Duration) llm.Provider {
	if idle <= 0 {
		idle = defaultStreamIdleTimeout
	}
	return &idleWatchdogProvider{inner: prov, idle: idle}
}

type idleWatchdogProvider struct {
	inner llm.Provider
	idle  time.Duration
}

func (w *idleWatchdogProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		// 看门狗 ctx：cancel 后底层流读取立即报错退出。
		wctx, wcancel := context.WithCancel(ctx)
		defer wcancel()

		var last activityStamp
		last.store(time.Now())
		done := make(chan struct{})
		var closeOnce sync.Once
		defer closeOnce.Do(func() { close(done) })

		go func() {
			ticker := time.NewTicker(w.idle / 4)
			defer ticker.Stop()
			for {
				select {
				case <-done:
					return
				case <-wctx.Done():
					return
				case <-ticker.C:
					if time.Since(last.load()) >= w.idle {
						wcancel() // 断开底层流 → inner 返回超时错误
						return
					}
				}
			}
		}()

		inner := w.inner.Stream(wctx, req)
		for ev, err := range inner {
			last.store(time.Now())
			if !yield(ev, err) {
				return
			}
			if err != nil {
				return
			}
		}
	}
}

func (w *idleWatchdogProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	return w.inner.Complete(ctx, req)
}

// activityStamp 是并发安全的最近活动时间戳（watchdog goroutine 与流消费方各持一端）。
type activityStamp struct {
	mu sync.Mutex
	t  time.Time
}

func (a *activityStamp) store(t time.Time) {
	a.mu.Lock()
	a.t = t
	a.mu.Unlock()
}

func (a *activityStamp) load() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.t
}
