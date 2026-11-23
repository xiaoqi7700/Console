package llmpresets

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// models.dev 的 api.json：顶层 provider id → { models: { model id → entry } }。
// entry 里我们只关心 limit.context / limit.output / reasoning 三个字段，
// 其余（价格/模态/作者）忽略。
type modelsDevFile struct {
	Providers map[string]struct {
		Models map[string]struct {
			Limit struct {
				Context int `json:"context"`
				Output  int `json:"output"`
			} `json:"limit"`
			Reasoning bool `json:"reasoning"`
		} `json:"models"`
	} `json:"providers"`
}

var fetchClient = &http.Client{Timeout: 60 * time.Second}

// fetchModelsDev 拉全量 api.json（约几 MB），失败返回 error 由调用方静默兜底。
func fetchModelsDev() ([]byte, error) {
	resp, err := fetchClient.Get("https://models.dev/api.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errHTTPStatus(resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20))
}

func parseModelsDev(body []byte) map[string]MetaEntry {
	var file modelsDevFile
	if err := json.Unmarshal(body, &file); err != nil {
		return nil
	}
	out := make(map[string]MetaEntry, 512)
	for _, prov := range file.Providers {
		for id, m := range prov.Models {
			if id == "" || m.Limit.Context <= 0 {
				continue
			}
			e := MetaEntry{
				ContextK:  m.Limit.Context / 1000,
				MaxOutput: m.Limit.Output / 1000,
				Reasoning: m.Reasoning,
			}
			if e.ContextK <= 0 {
				e.ContextK = 1 // 极小窗口（<1000）也标记为已知，避免当未知处理
			}
			lid := strings.ToLower(id)
			if _, exists := out[lid]; !exists || e.ContextK > out[lid].ContextK {
				out[lid] = e
			}
		}
	}
	return out
}

type httpStatusError struct{ code int }

func (e *httpStatusError) Error() string { return "models.dev 返回 HTTP " + strconv.Itoa(e.code) }

func errHTTPStatus(code int) error { return &httpStatusError{code: code} }
