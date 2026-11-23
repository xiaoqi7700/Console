package validators

// 浏览器执行断言（XSS 执行级证据）的降级实现。
//
// 上游 Pojun 用 chromedp 驱动无头浏览器加载探针页、断言 alert() 真实触发。
// 本地暂未引入 chromedp（会带来一串浏览器驱动的传递依赖），因此这里保留
// **完全相同的对外契约**：探针照常构造，只是永远返回 Skipped=true，让
// XSS 验证退化为「反射确认」（warn 级别），不会误判成已执行。
//
// 要恢复完整的执行级证据：引入 github.com/chromedp/chromedp，把本文件换成
// 上游 .refs/pojun/agent/validators/validators_browser.go 即可，调用方无感。

import (
	"context"
	"os/exec"
)

// BrowserExecResult 与上游同构。
type BrowserExecResult struct {
	Executed bool   `json:"executed"` // alert() 弹窗真实触发 = payload 执行级证据
	Skipped  bool   `json:"skipped"`  // 本机无浏览器（或启动失败）= 断言跳过
	Detail   string `json:"detail"`
}

// chromeCandidates 是无头浏览器的常见可执行名（Kali chromium / Debian
// chromium-browser / 官方 chrome）。
var chromeCandidates = []string{
	"chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
	"/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome-stable",
}

// ChromeAvailable 报告本机是否有可用的无头浏览器。
func ChromeAvailable() bool {
	for _, c := range chromeCandidates {
		if _, err := exec.LookPath(c); err == nil {
			return true
		}
	}
	return false
}

// ProbeBrowserExec 在未接入驱动时恒定跳过：反射证据维持 warn，不会被误判为
// 已执行。proxyURL 参数保留与上游同签名（OPSEC：接入后浏览器探针走同一出口）。
func ProbeBrowserExec(ctx context.Context, probeURL, proxyURL string) BrowserExecResult {
	if !ChromeAvailable() {
		return BrowserExecResult{Skipped: true, Detail: "本机无 chromium/chrome，执行断言跳过（反射证据维持 warn）"}
	}
	return BrowserExecResult{Skipped: true, Detail: "浏览器驱动未接入（validators_browser_stub），执行断言跳过；反射证据维持 warn"}
}
