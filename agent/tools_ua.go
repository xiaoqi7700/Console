package agent

import (
	"fmt"
	"strings"
)

// toolUserAgentMaxBytes 是可选的 user_agent 参数上限。
//
// 真实移动端 webview UA 可达约 540 字节；1024 仍远低于常见 HTTP 头的 8KB
// 上限，也给 http_probe 最多 40 个 URL 的命令留出余量。
const toolUserAgentMaxBytes = 1024

// normalizeToolUserAgent 归一化并校验 curl 系工具的可选 user_agent。
//
// 两态语义：
//   - 省略 / 空串 / 纯空白 → 返回 ("", nil)，调用方不得注入任何参数；
//   - 非空 → 去掉首尾空白后必须全部是可打印 ASCII（0x20-0x7E），且不超过
//     toolUserAgentMaxBytes 字节。
//
// 为什么只允许可打印 ASCII：
//   - curl -A 会把 CR/LF 当成新的请求头（CWE-113）；Go net/http 会在发送期
//     拒绝非法头值，但这四个工具是 shell-out，拿不到那层保护，必须自己拒绝。
//   - js_audit 的 Python urllib 按 latin-1 编码请求头：非 ASCII 只会报
//     UnicodeEncodeError 或把字节改写成另一个值，四个工具无法保持同一语义。
//   - ASCII-only 同时挡住 ESC(0x1B) 等控制字符进入日志与 transcript。
//
// 唯一的归一化是去掉首尾空白；其余字节原样保留。错误信息只给位置与字节值，
// 不回显 UA 原文，避免把恶意内容写进日志。
func normalizeToolUserAgent(raw string) (string, error) {
	ua := strings.TrimSpace(raw)
	if ua == "" {
		return "", nil
	}
	if len(ua) > toolUserAgentMaxBytes {
		return "", fmt.Errorf("user_agent 过长：%d 字节，上限 %d 字节", len(ua), toolUserAgentMaxBytes)
	}
	for i := 0; i < len(ua); i++ {
		if b := ua[i]; b < 0x20 || b > 0x7e {
			return "", fmt.Errorf(
				"user_agent 第 %d 字节为 0x%02X（0-based）：只允许可打印 ASCII（0x20-0x7E），禁止 CR/LF/NUL 等控制字符与非 ASCII",
				i, b)
		}
	}
	return ua, nil
}

// normalizeHeaderValue 校验 curl -H 的附加值（v0.4.97，issue #52）：
// 与 normalizeToolUserAgent 同字符集规则（可打印 ASCII，≤1024 字节），额外拒绝
// 以 @ 开头的值——curl -H @file 会把本地文件的行当成请求头发给目标（本地文件
// 读取外泄）。
func normalizeHeaderValue(raw string) (string, error) {
	ua := strings.TrimSpace(raw)
	if ua == "" {
		return "", nil
	}
	if strings.HasPrefix(ua, "@") {
		return "", fmt.Errorf("header 值以 @ 开头：curl 会把本地文件的行当成请求头发给目标（本地文件读取外泄）；请直接传键值对")
	}
	return normalizeToolUserAgent(ua)
}
