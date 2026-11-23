package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/llmpresets"
)

// LLM 配置的厂商知识层端点（v0.4.91 配置重构）：全部只读、纯增量，
// 不改动既有 9 个 LLM 端点的行为。

// GET /api/llm/presets — 内置厂商预设清单（新建向导第一步的卡片数据）。
func (s *Server) llmPresets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"presets": llmpresets.All()})
}

// GET /api/llm/model-meta?model=xxx — 按模型名推断元数据（context window /
// 是否支持推理）。来源 meta（元数据表）> preset（厂商预设条目）> none（前端
// 让用户手填）。配置保存时用推断值预填 context_window_k，用户可覆盖。
func (s *Server) llmModelMeta(w http.ResponseWriter, r *http.Request) {
	model := strings.TrimSpace(r.URL.Query().Get("model"))
	e, source := llmpresets.LookupMeta(model)
	resp := map[string]any{
		"model":     model,
		"context_k": e.ContextK,
		"reasoning": e.Reasoning,
		"source":    source,
	}
	if e.MaxOutput > 0 {
		resp["max_output_k"] = e.MaxOutput
	}
	writeJSON(w, 200, resp)
}

// POST /api/llm/check — 连通测试第一步（快速分诊）：按协议格式拉模型列表，
// 把失败分类成人话。第二步验收用既有 POST /api/llm/test（1-token 真实推理）。
// 请求体与 /api/llm/models 相同（key/UA 支持 profile_id 兜底）。
func (s *Server) llmCheck(w http.ResponseWriter, r *http.Request) {
	req, apiKey, userAgent, ok := s.decodeModelsReq(w, r)
	if !ok {
		return
	}
	if apiKey == "" {
		writeJSON(w, 200, map[string]any{
			"ok": false, "status_class": "missing_key",
			"error_human": "还没有填写 API Key：在第 2 步粘贴厂商给你的 Key 后重试。",
		})
		return
	}
	start := time.Now()
	models, lastCode, lastErr := fetchProviderModels(r.Context(), req.Provider, req.BaseURL, apiKey, req.Proxy, userAgent)
	latency := time.Since(start).Milliseconds()
	if len(models) > 0 {
		writeJSON(w, 200, map[string]any{
			"ok": true, "status_class": "ok", "models": models, "latency_ms": latency,
		})
		return
	}
	class, human := classifyModelListFailure(lastCode, lastErr)
	resp := map[string]any{
		"ok": false, "status_class": class, "error_human": human, "latency_ms": latency,
	}
	if lastErr != "" && lastErr != errAllEmpty {
		resp["error"] = lastErr // 原始错误保留给排障，UI 主展示 error_human
	}
	writeJSON(w, 200, resp)
}

// classifyModelListFailure 把模型列表拉取失败翻译成分类 + 人话 + 修复指引。
func classifyModelListFailure(lastCode int, lastErr string) (class, human string) {
	switch {
	case lastCode == 401 || lastCode == 403:
		return "key_invalid", "Key 无效或权限不足（HTTP " + strconv.Itoa(lastCode) + "）：确认 Key 是否复制完整、是否属于这个平台、账号是否还有额度。"
	case lastCode == 404 || lastCode == 405:
		return "path_or_format", "端点路径或协议不匹配（HTTP " + strconv.Itoa(lastCode) + "）：确认 Base URL 是否正确（一般以 /v1 结尾），以及厂商是否用 OpenAI 协议——Anthropic 协议的网关（如 DeepSeek 官方 Anthropic 端点、OpenCode Zen）要选对应预设。"
	case lastCode == 402:
		return "key_invalid", "账户余额不足（HTTP 402）：先去厂商控制台充值或换免费通道。"
	case lastCode == 429:
		return "server_error", "被限流（HTTP 429）：Key 有效但当前请求过快或额度受限，稍后重试。"
	case lastCode >= 500:
		return "server_error", "厂商服务端错误（HTTP " + strconv.Itoa(lastCode) + "）：服务暂不可用，稍后重试。"
	case lastCode == 200:
		return "empty_list", "端点连通但没返回任何模型（HTTP 200 空列表）：这个网关可能不开放模型列表接口——直接手填模型名即可。"
	case lastErr != "":
		return "network", "网络不通：" + netHint(lastErr) + "（若配置了代理，检查代理地址；若目标是外网厂商，检查本机出网。）"
	}
	return "unknown", "未知错误：请查看服务端日志。"
}

func netHint(lastErr string) string {
	if strings.Contains(lastErr, "timeout") || strings.Contains(lastErr, "deadline") {
		return "连接超时"
	}
	if strings.Contains(lastErr, "connection refused") || strings.Contains(lastErr, "connectex") {
		return "连接被拒绝（地址或端口不对）"
	}
	if strings.Contains(lastErr, "no such host") || strings.Contains(lastErr, "DNS") {
		return "域名无法解析"
	}
	if strings.Contains(lastErr, "certificate") || strings.Contains(lastErr, "x509") {
		return "TLS 证书校验失败"
	}
	return "底层网络错误"
}
