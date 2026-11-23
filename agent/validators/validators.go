// Package validators 实现按漏洞类别的程序化验证（v0.4.92 验证层冲刺，方向调研
// 共识①：渗透 agent 可信度取决于 harness——XBOW validators / AIxCC PoV 范式）。
//
// 与 evidence_check（人工可读的 13 项静态检查）互补：这里跑真实探针并对响应做
// 机械断言，输出机器可判定的 verdict 与证据标记（validate:<token>:pass），
// agent 把标记引用进 report_finding 的 evidence 即完成「机验闭环」。
//
// v1 覆盖三类：RCE/命令注入（回显 token + 时延）、XSS（反射+上下文+CSP 核查）、
// SSRF（OOB 回连 + 响应特征）。全部非阻断——validator 是加分证据，不替代
// evidence_check 的必过项，也不拦截任何上报路径。
package validators

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Verdict 是一次验证的机器判定：pass=探针断言命中；warn=有部分信号但缺执行级
// 证据（如 XSS 仅确认反射、未确认执行）；fail=探针未命中（不代表漏洞不存在，
// 只代表本组探针没打出来）。
type Verdict string

const (
	VerdictPass Verdict = "pass"
	VerdictWarn Verdict = "warn"
	VerdictFail Verdict = "fail"
)

// ProbeResult 是单个探针的断言结果。
type ProbeResult struct {
	Name     string `json:"name"`     // 探针名（echo_token / sleep_timing / reflection_raw ...）
	Injected string `json:"injected"` // 实际注入的参数值
	Detail   string `json:"detail"`   // 断言结论（人读）
	Hit      bool   `json:"hit"`      // 机械断言是否命中
}

// Result 是一次 validate 的完整结果。Marker 只在 Verdict==VerdictPass 时非空：
// 形如 `validate:<token>:pass`，agent 把它引用进 report_finding 的 evidence，
// evidence_check 的机验检查项据此判定。
type Result struct {
	Class   string        `json:"class"`
	Verdict Verdict       `json:"verdict"`
	Token   string        `json:"token"`
	Probes  []ProbeResult `json:"probes"`
	Marker  string        `json:"marker,omitempty"`
	Note    string        `json:"note,omitempty"`
	// Credentials 是云元数据深取提取到的凭据（目标侧泄露物，明文保真）。
	Credentials []CloudCredentials `json:"credentials,omitempty"`
}

// NewToken 生成 8 字节 hex 探针标记（64bit 熵足够区分并发验证）。
func NewToken() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// MarkerOf 组装 evidence 里的机验标记（pass 时才写入 evidence）。
func MarkerOf(token string) string { return "validate:" + token + ":pass" }

// inject 把 probeValue 注入 targetURL 的 param 参数（已有则替换，没有则追加）。
// 其余参数原样保留；返回注入后的完整 URL。
func inject(targetURL, param, probeValue string) (string, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return "", fmt.Errorf("目标 URL 解析失败: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("仅支持 http/https 目标: %s", targetURL)
	}
	q := u.Query()
	q.Set(param, probeValue)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// probeGet 发一次探针 GET，返回 (body, 响应头, elapsed, err)。失败不 panic、
// 不重试——探针失败本身就是 fail 信号的一种。
func probeGet(ctx context.Context, client *http.Client, probeURL string) (string, http.Header, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, time.Since(start), err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, limitBody))
	return string(body), resp.Header, time.Since(start), nil
}

// joinProbes 汇总探针结果为 verdict：任一 hit → pass；全部未命中但有部分信号 → fail。
func joinProbes(class string, token string, probes []ProbeResult, note string) *Result {
	r := &Result{Class: class, Token: token, Probes: probes, Note: note}
	for _, p := range probes {
		if p.Hit {
			r.Verdict = VerdictPass
			r.Marker = MarkerOf(token)
			return r
		}
	}
	r.Verdict = VerdictFail
	return r
}

// baselineElapsed 先用原始参数值打一发，量基线时延（时延型探针的对照）。
func baselineElapsed(ctx context.Context, client *http.Client, targetURL string) time.Duration {
	_, _, el, err := probeGet(ctx, client, targetURL)
	if err != nil {
		return 0
	}
	return el
}

// probeValuesFor 把注入值做成探针 URL。失败返回空切片（调用方报 fail）。
func probeURLs(targetURL, param string, values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if u, err := inject(targetURL, param, v); err == nil {
			out = append(out, u)
		}
	}
	return out
}

// limitBody 常量：探针响应最多读 1MB（见 probeGet）。
const limitBody = 1 << 20
