package validators

import (
	"strconv"
	"strings"
)

// stringsContains 是 strings.Contains 的包内别名（各 runner 共用）。
func stringsContains(body, sub string) bool { return strings.Contains(body, sub) }

// containsToken 判断响应是否包含探针 token（大小写敏感，token 本身即随机串）。
func containsToken(body, token string) bool { return strings.Contains(body, token) }

// verdictText 按 Hit 选择成对结论（hit=命中文案 / miss=未命中文案）。
func verdictText(hit bool, hitText, missText string) string {
	if hit {
		return hitText
	}
	return missText
}

// strictCSP 判断 CSP 响应头是否属于「会阻断内联脚本执行」的严格策略——
// 反射确认但 CSP 严格时，XSS verdict 降为 warn（执行被拦截的可能性高）。
func strictCSP(csp string) bool {
	if csp == "" {
		return false
	}
	l := strings.ToLower(csp)
	if strings.Contains(l, "script-src") || strings.Contains(l, "default-src") {
		// 允许 unsafe-inline / 通配源的策略不算严格
		if strings.Contains(l, "unsafe-inline") || strings.Contains(l, "'*'") {
			return false
		}
		return true
	}
	return false
}

// itoa 是 strconv.Itoa 的包内别名（rce runner 时延命令拼装用）。
func itoa(n int) string { return strconv.Itoa(n) }
