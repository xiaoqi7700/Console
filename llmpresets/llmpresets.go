// Package llmpresets 是 LLM 配置的「厂商知识层」：内置厂商预设 + 模型元数据
// （context window / 是否支持推理）的推断来源。预设与代码分离（JSON 内嵌编译，
// 运行时可被 data 缓存覆盖），模型清单只是拉取失败时的回退候选，不是硬依赖。
package llmpresets

import (
	_ "embed"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed presets.json
var presetsJSON []byte

//go:embed meta.json
var metaJSON []byte

// ModelEntry 是预设里的推荐模型条目。
type ModelEntry struct {
	ID        string `json:"id"`
	ContextK  int    `json:"context_k"`
	Reasoning bool   `json:"reasoning,omitempty"`
	// 模型级参数覆盖（v0.4.96，对照内部版 v0.9.64）：选中模型时优先于预设级。
	MaxTokens       int    `json:"max_tokens,omitempty"`
	MaxTokensField  string `json:"max_tokens_field,omitempty"`
	ThinkingType    string `json:"thinking_type,omitempty"`
	ReasoningEffort string `json:"reasoning_effort,omitempty"`
	UserAgent       string `json:"user_agent,omitempty"`
}

// Preset 是一条厂商预设：新建向导第一步选中的卡片。
type Preset struct {
	ID       string       `json:"id"`
	Name     string       `json:"name"`
	Category string       `json:"category"` // official | aggregate | relay | local | custom
	Format   string       `json:"format"`   // openai | anthropic | openai-responses
	BaseURL  string       `json:"base_url"` // 空=用户自填（自定义中转）
	AuthNote string       `json:"auth_note"`
	Note     string       `json:"note"`
	Models   []ModelEntry `json:"models"`
	// 差异化 profile 参数预置（v0.4.93）：选预设即带入，用户「填 Key 即可用」
	// 不必再进高级设置。空串=无预置（用户自填）。
	SessionHeaderKey string `json:"session_header_key,omitempty"` // 如 opencode-go 的 x-opencode-session
	UserAgent        string `json:"user_agent,omitempty"`         // 按客户端放行的网关用
	MaxTokensField   string `json:"max_tokens_field,omitempty"`   // openai 格式的上限字段名预置
	MaxTokens        int    `json:"max_tokens,omitempty"`         // 输出上限预填（Anthropic 协议必填）
	ThinkingType     string `json:"thinking_type,omitempty"`      // 思考开关预填（GLM 等强制思考的模型）
	ReasoningEffort  string `json:"reasoning_effort,omitempty"`   // 思考强度预填
}

// MetaEntry 是一个模型的推断元数据。
type MetaEntry struct {
	ContextK  int  `json:"context_k"`
	MaxOutput int  `json:"max_output,omitempty"` // 单位 K；0=未知
	Reasoning bool `json:"reasoning,omitempty"`
}

// MetaSource 说明推断结果的出处：meta=元数据表命中；preset=厂商预设模型条目
// 命中；none=没命中（前端应让用户手填 context）。
const (
	SourceMeta   = "meta"
	SourcePreset = "preset"
	SourceNone   = "none"
)

func All() []Preset {
	var out []Preset
	if err := json.Unmarshal(presetsJSON, &out); err != nil {
		log.Printf("[llmpresets] 内置预设解析失败（编译产物异常）: %v", err)
		return nil
	}
	return out
}

func Get(id string) (Preset, bool) {
	for _, p := range All() {
		if p.ID == id {
			return p, true
		}
	}
	return Preset{}, false
}

// runtimeMeta 是在线刷新缓存的内存视图：model id（小写）→ 条目。
// 刷新失败静默沿用内嵌快照——元数据只影响 context 推断的准确度，不影响功能。
var (
	metaMu       sync.RWMutex
	runtimeMeta  map[string]MetaEntry
	metaCacheTTL = 7 * 24 * time.Hour
)

// InitCache 在服务启动时调用：加载 data 缓存（未过期则用），过期则后台拉
// models.dev/api.json 刷新并落盘。dataDir 为空跳过缓存（纯内嵌快照）。
func InitCache(dataDir string) {
	if dataDir == "" {
		return
	}
	path := filepath.Join(dataDir, "llm-meta-cache.json")
	if b, err := os.ReadFile(path); err == nil {
		var snap struct {
			UpdatedAt time.Time            `json:"updated_at"`
			Models    map[string]MetaEntry `json:"models"`
		}
		if json.Unmarshal(b, &snap) == nil && len(snap.Models) > 0 &&
			time.Since(snap.UpdatedAt) < metaCacheTTL {
			metaMu.Lock()
			runtimeMeta = snap.Models
			metaMu.Unlock()
			return // 缓存仍新鲜，不发起刷新
		}
	}
	go refreshCache(dataDir, path)
}

// refreshCache 拉取 models.dev 全量模型数据，压平成 id→条目 落盘。
// 任何失败都静默返回（内嵌快照兜底），不打扰服务。
func refreshCache(dataDir, path string) {
	body, err := fetchModelsDev()
	if err != nil {
		return
	}
	models := parseModelsDev(body)
	if len(models) == 0 {
		return
	}
	metaMu.Lock()
	runtimeMeta = models
	metaMu.Unlock()
	snap := struct {
		UpdatedAt time.Time            `json:"updated_at"`
		Models    map[string]MetaEntry `json:"models"`
	}{UpdatedAt: time.Now().UTC(), Models: models}
	if b, err := json.Marshal(snap); err == nil {
		_ = os.WriteFile(path, b, 0o600)
	}
}

// LookupMeta 推断模型元数据：精确命中（大小写不敏感）→ 最长前缀命中
// （"claude-opus-4-8-20261101" 命中 "claude-opus-4-8"；带厂商前缀
// "anthropic/claude-opus-4-5" 命中裸 id）→ 预设模型条目 → 未命中。
func LookupMeta(model string) (MetaEntry, string) {
	id := strings.ToLower(strings.TrimSpace(model))
	if id == "" {
		return MetaEntry{}, SourceNone
	}
	metaMu.RLock()
	if runtimeMeta != nil {
		if e, ok := lookupIn(runtimeMeta, id); ok {
			metaMu.RUnlock()
			return e, SourceMeta
		}
	}
	metaMu.RUnlock()
	if e, ok := lookupIn(embeddedMeta(), id); ok {
		return e, SourceMeta
	}
	// 预设模型条目兜底（最长前缀优先，与 lookupIn 同判定）
	bestID, bestLen := "", 0
	for _, p := range All() {
		for _, m := range p.Models {
			mid := strings.ToLower(m.ID)
			if id == mid || (strings.HasPrefix(id, mid) && boundaryOK(id, len(mid)) && len(mid) > bestLen) {
				bestID, bestLen = mid, len(mid)
			}
		}
	}
	if bestID != "" {
		for _, p := range All() {
			for _, m := range p.Models {
				if strings.ToLower(m.ID) == bestID {
					return MetaEntry{ContextK: m.ContextK, Reasoning: m.Reasoning}, SourcePreset
				}
			}
		}
	}
	return MetaEntry{}, SourceNone
}

// lookupIn 在一张元数据表里查 id：精确 → 剥厂商前缀再查 → 最长前缀命中。
func lookupIn(m map[string]MetaEntry, id string) (MetaEntry, bool) {
	if m == nil {
		return MetaEntry{}, false
	}
	if e, ok := m[id]; ok {
		return e, true
	}
	// id 里带厂商前缀而表里是裸 id：取 "/" 后半段再查一次
	if i := strings.LastIndex(id, "/"); i >= 0 && i+1 < len(id) {
		if e, ok := m[id[i+1:]]; ok {
			return e, true
		}
		if e, ok := lookupPrefix(m, id[i+1:]); ok {
			return e, true
		}
	}
	return lookupPrefix(m, id)
}

// lookupPrefix 最长前缀命中：用户填了带日期后缀/版本尾巴的完整 id 时命中短键。
// 边界要求：前缀后的第一个字符是 - : / 或数字（防止 "gpt-4o" 误吃 "gpt-4omni"），
// 同长度时以 map 命中为准（最长优先已保证语义上最具体的条目胜出）。
func lookupPrefix(m map[string]MetaEntry, id string) (MetaEntry, bool) {
	bestKey := ""
	for k := range m {
		if len(k) <= len(bestKey) || !strings.HasPrefix(id, k) || !boundaryOK(id, len(k)) {
			continue
		}
		bestKey = k
	}
	if bestKey == "" {
		return MetaEntry{}, false
	}
	return m[bestKey], true
}

func boundaryOK(id string, at int) bool {
	if at >= len(id) {
		return false // 纯前缀相等走精确分支，不该到这里
	}
	switch c := id[at]; {
	case c == '-' || c == ':' || c == '/':
		return true
	case c >= '0' && c <= '9':
		return true
	}
	return false
}

func embeddedMeta() map[string]MetaEntry {
	var snap struct {
		Models map[string]MetaEntry `json:"models"`
	}
	if err := json.Unmarshal(metaJSON, &snap); err != nil {
		log.Printf("[llmpresets] 内嵌元数据解析失败（编译产物异常）: %v", err)
		return nil
	}
	return snap.Models
}
