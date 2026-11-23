package server

// LLM 端点模型列表探测与失败分诊（移植自上游 Pojun）。
//
// 为什么单独一层：配置 LLM 时最常卡住的是「Key 填对了但模型列表拉不到」，
// 可能是网关不支持 /v1/models、Key 没权限、协议格式选错、代理不通。把失败
// 分类成人话（status_class + error_human + 修复指引），用户才能自己走出去。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const errAllEmpty = "all candidates returned empty lists"

// llmModelsReq 是 /llm/models 与 /llm/check 共用的请求体。
type llmModelsReq struct {
	Provider  string `json:"provider"` // "openai" | "anthropic"
	BaseURL   string `json:"base_url"`
	APIKey    string `json:"api_key"`
	Proxy     string `json:"proxy"`
	UserAgent string `json:"user_agent"` // 非空=与模型请求一致的 UA；空=profile 存的值
	ProfileID *int64 `json:"profile_id"` // fallback: use stored key from this profile
}

// decodeModelsReq 是 /llm/models 与 /llm/check 共用的请求解码与 key/UA 兜底。
// 返回 ok=false 时已写响应。
func (s *Server) decodeModelsReq(w http.ResponseWriter, r *http.Request) (req llmModelsReq, apiKey, userAgent string, ok bool) {
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return req, "", "", false
	}
	// Resolve API key: form input > profile stored key. UA 同样从 profile 兜底：
	// 网关拦默认 UA 时，「加载模型」也应该和真实请求走同一套特征。
	apiKey = strings.TrimSpace(req.APIKey)
	userAgent = strings.TrimSpace(req.UserAgent)
	if req.ProfileID != nil {
		if p, err := s.m.pg.ProfileByID(*req.ProfileID); err == nil && p != nil {
			if apiKey == "" {
				apiKey = p.APIKey
			}
			if userAgent == "" {
				userAgent = p.UserAgent
			}
		}
	}
	return req, apiKey, userAgent, true
}

// fetchProviderModels 按协议格式试候选端点，返回首个非空模型列表。
// lastCode/lastErr 供 /llm/check 做失败分类：lastCode 是最后一次拿到 HTTP 响应
// 的状态码（网络错误时为 0）；lastErr==errAllEmpty 表示全 200 但列表空。
func fetchProviderModels(ctx context.Context, provider, baseURL, apiKey, proxy, userAgent string) (models []string, lastCode int, lastErr string) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	provider = strings.TrimSpace(provider)

	// Candidate endpoints to try in order. Some Anthropic-compatible providers
	// (e.g. DeepSeek) implement /v1/messages under an /anthropic path but expose
	// the model list only on their OpenAI-format path — so for anthropic we fall
	// back to the OpenAI endpoint at the stripped root.
	type candidate struct {
		url string
		hdr http.Header
	}
	bearerHdr := func() http.Header {
		h := http.Header{}
		h.Set("Authorization", "Bearer "+apiKey)
		return h
	}
	anthropicHdr := func() http.Header {
		h := http.Header{}
		h.Set("x-api-key", apiKey)
		h.Set("anthropic-version", "2023-06-01")
		return h
	}

	var candidates []candidate
	switch provider {
	case "openai", "openai-responses":
		// Responses API shares the OpenAI model list at /v1/models; tolerate a full
		// endpoint URL of either format.
		if baseURL == "" {
			baseURL = "https://api.openai.com/v1"
		}
		b := strings.TrimRight(strings.TrimSuffix(strings.TrimSuffix(baseURL, "/chat/completions"), "/responses"), "/")
		candidates = append(candidates, candidate{b + "/models", bearerHdr()})
	default: // anthropic
		if baseURL == "" {
			baseURL = "https://api.anthropic.com"
		}
		b := strings.TrimRight(strings.TrimSuffix(baseURL, "/v1/messages"), "/")
		candidates = append(candidates, candidate{b + "/v1/models", anthropicHdr()})
		// Fallback for Anthropic-compatible third parties whose model list lives on
		// the OpenAI path: strip a trailing /anthropic and try the OpenAI endpoint.
		if root := strings.TrimRight(strings.TrimSuffix(b, "/anthropic"), "/"); root != b {
			candidates = append(candidates,
				candidate{root + "/models", bearerHdr()},
				candidate{root + "/v1/models", bearerHdr()},
			)
		}
	}

	// Build HTTP client with optional proxy.
	transport := &http.Transport{}
	if p := strings.TrimSpace(proxy); p != "" {
		if pu, err := url.Parse(p); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}

	// Try each candidate; return the first that yields a non-empty model list.
	emptyOK := false
	for _, c := range candidates {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
		if err != nil {
			lastErr = "构建请求失败: " + err.Error()
			continue
		}
		httpReq.Header = c.hdr
		if userAgent != "" {
			httpReq.Header.Set("User-Agent", userAgent)
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			lastErr = "请求失败: " + err.Error()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		lastCode = resp.StatusCode
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Sprintf("API 返回 %d: %s", resp.StatusCode, string(body[:min(len(body), 512)]))
			continue
		}
		// Both OpenAI and Anthropic return {"data": [{"id": "..."},...]}.
		var parsed struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &parsed); err != nil {
			lastErr = "解析响应失败: " + err.Error()
			continue
		}
		models = make([]string, 0, len(parsed.Data))
		for _, m := range parsed.Data {
			if m.ID != "" {
				models = append(models, m.ID)
			}
		}
		if len(models) > 0 {
			return models, lastCode, ""
		}
		emptyOK = true // 200 but no model ids — keep trying other candidates
	}
	if emptyOK {
		return nil, lastCode, errAllEmpty
	}
	return nil, lastCode, lastErr
}
