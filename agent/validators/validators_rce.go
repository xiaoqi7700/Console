package validators

import (
	"context"
	"net/http"
	"time"
)

// RunRCE 验证命令注入/ RCE 类：两组探针。
//  1. 回显型——注入 echo <token> 的常见连接符变体，断言响应包含 token；
//  2. 时延型——注入 sleep 7，与基线时延差 ≥5s 判命中（盲注型 RCE 的机械信号）。
//
// verdict：回显命中 → pass；仅时延命中 → pass（带「盲注」note）；全未命中 → fail。
//
// sleep 秒数与时延阈值是包内变量（测试用短值覆盖，生产走默认）。
var (
	rceSleepSeconds    = 7
	rceTimingThreshold = 5 * time.Second
)

func RunRCE(ctx context.Context, client *http.Client, targetURL, param, token string) *Result {
	echoProbes := []string{
		";echo " + token,
		"|echo " + token,
		"$(echo " + token + ")",
		"&&echo " + token,
		"\necho " + token,
	}
	var probes []ProbeResult
	base := baselineElapsed(ctx, client, targetURL)

	for _, v := range echoProbes {
		for _, u := range probeURLs(targetURL, param, []string{v}) {
			body, _, _, err := probeGet(ctx, client, u)
			name := "echo_token"
			if err != nil {
				probes = append(probes, ProbeResult{Name: name, Injected: v, Detail: "请求失败: " + err.Error()})
				continue
			}
			hit := containsToken(body, token)
			probes = append(probes, ProbeResult{
				Name: name, Injected: v, Hit: hit,
				Detail: verdictText(hit, "响应回显了探针 token（命令拼接生效）", "响应未包含探针 token"),
			})
			if hit {
				return joinProbes("rce", token, probes, "")
			}
		}
	}

	// 时延型：sleep N（拼接变体取两种最常见），与基线差 ≥阈值判命中。
	sleepCmd := ";sleep " + itoa(rceSleepSeconds)
	altCmd := "|sleep " + itoa(rceSleepSeconds)
	for _, v := range []string{sleepCmd, altCmd} {
		for _, u := range probeURLs(targetURL, param, []string{v}) {
			_, _, el, err := probeGet(ctx, client, u)
			diff := el - base
			hit := err == nil && diff >= rceTimingThreshold
			probes = append(probes, ProbeResult{
				Name: "sleep_timing", Injected: v, Hit: hit,
				Detail: verdictText(hit,
					"时延差异 "+diff.Truncate(time.Millisecond).String()+"（基线 "+base.Truncate(time.Millisecond).String()+"），盲注型执行信号",
					"时延差异不足（"+diff.Truncate(time.Millisecond).String()+"）",
				),
			})
			if hit {
				return joinProbes("rce", token, probes, "盲注型命中：无回显，按时延判定；建议再用带外（OOB）探针补强证据。")
			}
		}
	}
	return joinProbes("rce", token, probes, "")
}
