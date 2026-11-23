// 代理池 API:CRUD + 批量导入 + 连通性验证 + 主动健康检查。
//
// 持久化仍在 settings(proxy_pool_entries JSONB + proxy_pool_strategy),内存态经
// Traffic.SetProxyPool 原子推送。批量导入与验证解决原页面「只能一行行加、坏没坏
// 看不出、筛不掉」的问题;健康检查是后台协程,把「连败 5 次才熔断」升级成「主动
// 发现不通就立刻熔断」。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	pgdb "github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/traffic"
	"golang.org/x/net/proxy"
)

const (
	settingProxyPoolEntries    = "proxy_pool_entries"
	settingProxyPoolStrategy   = "proxy_pool_strategy"
	settingProxyPoolEnabled    = "proxy_pool_enabled"
	settingProxyBreaks         = "proxy_pool_break_state" // 跨重启保留的熔断状态(URL→解禁 unix)
	settingProxyCheckTarget    = "proxypool_check_target"
	settingProxyHealthMinutes  = "proxypool_health_minutes"
	settingProxyHealthCooldown = "proxypool_health_cooldown_minutes"
	// settingProxyAllowSocks5：是否允许 socks5 上游入池。历史上 go-mitmproxy 在
	// socks5 拨号失败时会对 nil conn 调 Close() 触发 panic（v1.9.4 已修）。v0.8.0
	// 起默认允许——SOCKS5 是 Clash/mihomo 混合端的常见出口，默认拒绝会让「导入
	// Clash 节点」看起来完全不可用。显式设置为 false/0 时才关闭。
	settingProxyAllowSocks5 = "proxypool_allow_socks5"
)

const (
	defaultProxyCheckTarget    = "https://api.ipify.org?format=json"
	defaultProxyHealthMinutes  = 10 // 0 = 关闭主动健康检查
	defaultProxyHealthCooldown = 30 // 主动熔断的冷却时长(分钟)
	defaultProxyCheckTimeout   = 8 * time.Second
	proxyCheckConcurrency      = 8
	// 导入验活：并发更高、单条超时更短——导入是同步请求，240 条也要在 ~1 分钟内出结果。
	importVerifyConcurrency = 32
	importVerifyTimeout     = 6 * time.Second
)

// proxyPoolState 是持久化的池配置。URL 明文入库(与 LLM 配置密码同级别,
// settings 表不对外),对外输出掩码。
type proxyPoolState struct {
	Entries  []traffic.PoolEntry `json:"entries"`
	Strategy string              `json:"strategy"`
	Enabled  bool                `json:"enabled"` // 总开关：false 时池不参与出口选择
}

func (s *Server) loadProxyPool() *proxyPoolState {
	return loadProxyPoolState(s.m.pg)
}
func loadProxyPoolState(pg *pgdb.DB) *proxyPoolState {
	st := proxyPoolState{Strategy: "round_robin", Enabled: true}
	if raw, ok, _ := pg.GetSetting(settingProxyPoolEntries); ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), &st)
	}
	if v, ok, _ := pg.GetSetting(settingProxyPoolStrategy); ok && v != "" {
		st.Strategy = v
	}
	// 总开关独立成键：老数据没有它时默认开启（升级前池是「有条目即生效」的语义）。
	if v, ok, err := pg.GetSetting(settingProxyPoolEnabled); err == nil && ok {
		st.Enabled = !(v == "false" || v == "0")
	}
	if st.Entries == nil {
		st.Entries = []traffic.PoolEntry{}
	}
	return &st
}

// socks5Allowed 读取「允许 socks5 上游」开关（v0.8.0 起默认 true；
// 只有显式写入 false/0 才关闭）。socks5 拨号 panic 在 v1.9.4 已修复。
func (s *Server) socks5Allowed() bool {
	if s == nil || s.m == nil || s.m.pg == nil {
		return true
	}
	v, ok, err := s.m.pg.GetSetting(settingProxyAllowSocks5)
	if err != nil || !ok {
		return true
	}
	v = strings.TrimSpace(strings.ToLower(v))
	return !(v == "0" || v == "false" || v == "off" || v == "no")
}

// validateProxyScheme 在 URL 校验之后再做 scheme 策略校验。
func (s *Server) validateProxyScheme(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if (strings.EqualFold(u.Scheme, "socks5") || strings.EqualFold(u.Scheme, "socks5h")) && !s.socks5Allowed() {
		return fmt.Errorf("当前版本默认不启用 socks5 上游（历史版本在 socks5 拨号失败时会 panic，且握手无超时）。请改用 http(s):// 代理；确需 socks5 请在系统设置开启 proxypool_allow_socks5")
	}
	return nil
}

// effectivePoolEntries 返回真正推给 MITM 的条目，并统计被 scheme 策略挡下的条数。
func (s *Server) effectivePoolEntries(st *proxyPoolState) ([]traffic.PoolEntry, int) {
	if st == nil {
		return nil, 0
	}
	if s.socks5Allowed() {
		return st.Entries, 0
	}
	kept := make([]traffic.PoolEntry, 0, len(st.Entries))
	blocked := 0
	for _, e := range st.Entries {
		if u, err := url.Parse(e.URL); err == nil && (strings.EqualFold(u.Scheme, "socks5") || strings.EqualFold(u.Scheme, "socks5h")) {
			blocked++
			continue
		}
		kept = append(kept, e)
	}
	return kept, blocked
}

func (s *Server) saveProxyPool(st proxyPoolState) error {
	return saveProxyPoolState(s.m.pg, st)
}

// saveProxyPoolState 是 saveProxyPool 的包级版本，供 Manager 启动期自动探测使用。
func saveProxyPoolState(pg *pgdb.DB, st proxyPoolState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := pg.SetSetting(settingProxyPoolEntries, string(raw)); err != nil {
		return err
	}
	if err := pg.SetSetting(settingProxyPoolStrategy, st.Strategy); err != nil {
		return err
	}
	enabled := "true"
	if !st.Enabled {
		enabled = "false"
	}
	return pg.SetSetting(settingProxyPoolEnabled, enabled)
}

// applyProxyPool 把配置推到运行态：总开关关闭时与「池为空」同义（回退全局代理/直连）。
func (s *Server) applyProxyPool(st proxyPoolState) error {
	t := s.m.traffic
	if t == nil {
		return nil
	}
	entries, blocked := s.effectivePoolEntries(&st)
	if blocked > 0 {
		log.Printf("[proxypool] 已跳过 %d 条 socks5 上游（默认禁用；如需启用请开启 proxypool_allow_socks5）", blocked)
	}
	var err error
	if !st.Enabled {
		err = t.SetProxyPool(nil, st.Strategy)
	} else {
		err = t.SetProxyPool(entries, st.Strategy)
	}
	if err != nil {
		return err
	}
	s.refreshAgentsForEgressChange()
	return nil
}

// refreshAgentsForEgressChange 在「流量捕获关闭」时重建 Agent：出口地址是在建
// Agent 时烤进 worker 的 HTTP_PROXY 的，池一改就得重新装配才能生效。
// 捕获开启时代理地址是常量（MITM 本地端口），池在 MITM 钩子里按请求选，无需重建。
func (s *Server) refreshAgentsForEgressChange() {
	if s.m == nil || s.m.TrafficEnabled() {
		return
	}
	s.cfgMu.Lock()
	cfg, on := s.llmCfg, s.llmOn
	s.cfgMu.Unlock()
	if !on {
		return
	}
	if err := s.applyLLM(cfg); err != nil {
		log.Printf("[proxypool] 出口变更后重建 Agent 失败: %v", err)
	}
}

// proxyPoolGet 返回当前配置(含运行状态:熔断计数/掩码/最近一次验证)。
func (s *Server) proxyPoolGet(w http.ResponseWriter, r *http.Request) {
	st := s.loadProxyPool()
	running := []traffic.PoolEntry{}
	if t := s.m.traffic; t != nil {
		running = t.ProxyPoolStatus()
	}
	s.m.proxyCheckMu.Lock()
	last := s.m.proxyCheckLast
	s.m.proxyCheckMu.Unlock()
	eff, socks5Blocked := s.effectivePoolEntries(st)
	writeJSON(w, 200, map[string]any{
		"entries":                st.Entries,
		"strategy":               st.Strategy,
		"enabled":                st.Enabled,
		"total":                  len(st.Entries),
		"effective_total":        len(eff),
		"socks5_blocked":         socks5Blocked,
		"socks5_allowed":         s.socks5Allowed(),
		"running":                running,
		"usable":                 s.usableProxyCount(running),
		"capturing":              s.m.TrafficEnabled(),
		"check_target":           settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget),
		"health_minutes":         intSetting(s.m.pg, settingProxyHealthMinutes, defaultProxyHealthMinutes),
		"health_cooldown":        intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown),
		"last_check":             last,
		"strict":                 s.m.traffic != nil && s.m.traffic.StrictEgress(),
		"direct_record_fallback": s.m.traffic != nil && s.m.traffic.DirectRecordFallback(),
		// effective_proxy 是 Agent/Bash/WebFetch 当前真正拿到的出口（掩码凭据），
		// 便于确认「配置了代理后没有回退直连」；空串 = 直连。
		"effective_proxy": maskProxyURL(s.m.ProxyAddr()),
	})
}

// maskProxyURL 掩码代理地址里的账号密码，供状态接口回显。
func maskProxyURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("***")
	return u.String()
}

// usableProxyCount 数「未被熔断」的条目（running 里的 break_remaining==0）。
func (s *Server) usableProxyCount(running []traffic.PoolEntry) int {
	n := 0
	for _, e := range running {
		if e.BreakRemaining == 0 {
			n++
		}
	}
	return n
}

// settingOr 读字符串设置,缺失/空时用默认值。
func settingOr(pg *pgdb.DB, key, def string) string {
	v, ok, err := pg.GetSetting(key)
	if err != nil || !ok || strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

// proxyPoolPut 全量替换配置并热应用。
func (s *Server) proxyPoolPut(w http.ResponseWriter, r *http.Request) {
	// Enabled 用指针区分「没传」和「显式 false」：老客户端不传时保持原值。
	var in struct {
		Entries  []traffic.PoolEntry `json:"entries"`
		Strategy string              `json:"strategy"`
		Enabled  *bool               `json:"enabled"`
		Strict   *bool               `json:"strict"`
		// ConfirmClear 显式确认「把非空池清空」。页面状态过期（GET 失败 / 旧标签页）
		// 时 entries=[] 的误保存会静默清掉整池，必须由调用方明确确认。
		ConfirmClear bool `json:"confirm_clear"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if in.Entries == nil {
		in.Entries = []traffic.PoolEntry{}
	}
	st := proxyPoolState{Entries: in.Entries, Strategy: in.Strategy, Enabled: true}
	prev := s.loadProxyPool()
	if len(st.Entries) == 0 && len(prev.Entries) > 0 && !in.ConfirmClear {
		writeErr(w, 400, "清空代理池需要 confirm_clear=true（防止页面状态过期误清空）；只想停用请传 enabled=false")
		return
	}
	if st.Strategy == "" {
		st.Strategy = prev.Strategy
	}
	if in.Enabled != nil {
		st.Enabled = *in.Enabled
	} else {
		st.Enabled = prev.Enabled
	}
	// 校验:URL 可解析、权重下限、名称去重留白
	seen := map[string]bool{}
	for i := range st.Entries {
		e := &st.Entries[i]
		if _, err := traffic.ValidateProxyURL(e.URL); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if err := s.validateProxyScheme(e.URL); err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if e.Weight < 1 {
			e.Weight = 1
		}
		if seen[e.URL] {
			writeErr(w, 400, "重复的代理地址: "+e.URL)
			return
		}
		seen[e.URL] = true
	}
	if err := s.applyProxyPool(st); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if err := s.saveProxyPool(st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	// 严格出口开关独立于池条目：显式传了就持久化并立即生效（页面「保存并热应用」）。
	if in.Strict != nil && s.m.traffic != nil {
		val := "true"
		if !*in.Strict {
			val = "false"
		}
		if err := s.m.pg.SetSetting(settingEgressStrict, val); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
		s.m.traffic.SetStrictEgress(*in.Strict)
		// 严格开关会改变 ProxyAddr（可能变成哨兵地址），Agent 的 HTTP_PROXY 是
		// 建 Agent 时固定的，必须重建才能立刻生效。
		s.refreshAgentsForEgressChange()
	}
	s.proxyPoolGet(w, r)
}

// --- 批量导入 ---

type proxyBulkInvalid struct {
	Line   int    `json:"line"`
	Raw    string `json:"raw"`
	Reason string `json:"reason"`
}

// parseProxyLine 解析一行代理。支持的形态(用户从付费站导出的常见格式):
//
//	1.2.3.4:8080
//	http://1.2.3.4:8080  /  socks5://user:pass@1.2.3.4:1080
//	1.2.3.4:8080:user:pass
//	名字 | 1.2.3.4:8080     (名字用竖线,避免与 URL 里的冒号混淆)
//	以 # 开头或空行 = 注释
//
// 省略 scheme 一律按 http 补——socks5 必须显式写出来,否则会被当 http 代理连失败。
func parseProxyLine(raw string) (name, u string, comment bool, err error) {
	line := strings.TrimSpace(raw)
	if line == "" {
		return "", "", true, nil
	}
	if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
		return "", "", true, nil
	}
	if i := strings.Index(line, "|"); i >= 0 {
		name = strings.TrimSpace(line[:i])
		line = strings.TrimSpace(line[i+1:])
	}
	// host:port:user:pass(最常见的付费商导出格式)
	if strings.Count(line, ":") == 3 && !strings.Contains(line, "://") {
		parts := strings.SplitN(line, ":", 4)
		if strings.Contains(parts[0], ".") && parts[1] != "" {
			u = fmt.Sprintf("http://%s:%s@%s:%s", parts[2], parts[3], parts[0], parts[1])
			return name, u, false, nil
		}
	}
	if strings.HasPrefix(strings.ToLower(line), "socks://") {
		line = "socks5://" + line[len("socks://"):]
	}
	if !strings.Contains(line, "://") {
		line = "http://" + line
	}
	if _, err := url.Parse(line); err != nil {
		return name, line, false, err
	}
	return name, line, false, nil
}

// proxyPoolBulk 批量导入。mode=append 追加(默认),replace 整体替换。
// verify 默认开启：逐条经该代理请求 check_target，连不通的行**不导入**并逐行说明原因
// （用户诉求：「导入的时候不通的这一部分就不会被导入进去了」）。若 check_target 本身
// 直连不可达（内网/被墙），自动跳过验证并在响应里警告，绝不因为验活环境坏了把整包丢弃。
// 返回逐行结果,让前端能明确指出哪一行错在哪。
func (s *Server) proxyPoolBulk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text             string `json:"text"`
		Mode             string `json:"mode"`
		Strategy         string `json:"strategy"`
		Weight           int    `json:"weight"`
		Verify           *bool  `json:"verify"`
		VerifyTimeoutSec int    `json:"verify_timeout_seconds"`
		Enabled          *bool  `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	req.Mode = strings.TrimSpace(req.Mode)
	if req.Mode == "" {
		req.Mode = "append"
	}
	if req.Mode != "append" && req.Mode != "replace" {
		writeErr(w, 400, "mode 只能是 append 或 replace")
		return
	}
	weight := req.Weight
	if weight < 1 {
		weight = 1
	}

	st := s.loadProxyPool()
	if req.Mode == "replace" {
		st.Entries = []traffic.PoolEntry{}
	}
	if req.Enabled != nil {
		st.Enabled = *req.Enabled
	}
	byURL := map[string]int{}
	for i, e := range st.Entries {
		byURL[e.URL] = i
	}

	var invalid []proxyBulkInvalid
	added, updated := 0, 0
	// incoming 记录本次文本里解析出的全部条目（新增 + 已存在）。两条路径都验活：
	// 新增的连不通就丢弃；已存在的连不通就停用（不删用户数据，但也不再参与出口选择）。
	type incomingEntry struct {
		line  int
		entry traffic.PoolEntry
		isNew bool
	}
	var incoming []incomingEntry
	lines := strings.Split(req.Text, "\n")
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		name, raw, isComment, _ := parseProxyLine(ln)
		if isComment {
			continue
		}
		norm, verr := traffic.ValidateProxyURL(raw)
		if verr != nil {
			invalid = append(invalid, proxyBulkInvalid{Line: i + 1, Raw: strings.TrimSpace(ln), Reason: verr.Error()})
			continue
		}
		if serr := s.validateProxyScheme(norm.String()); serr != nil {
			invalid = append(invalid, proxyBulkInvalid{Line: i + 1, Raw: strings.TrimSpace(ln), Reason: serr.Error()})
			continue
		}
		if name == "" {
			name = norm.Host
		}
		key := norm.String()
		if idx, ok := byURL[key]; ok {
			st.Entries[idx].Name = name
			st.Entries[idx].Enabled = true
			if st.Entries[idx].Weight < 1 {
				st.Entries[idx].Weight = weight
			}
			updated++
			incoming = append(incoming, incomingEntry{line: i + 1, entry: st.Entries[idx], isNew: false})
			continue
		}
		e := traffic.PoolEntry{URL: key, Name: name, Enabled: true, Weight: weight}
		st.Entries = append(st.Entries, e)
		byURL[key] = len(st.Entries) - 1
		added++
		incoming = append(incoming, incomingEntry{line: i + 1, entry: e, isNew: true})
	}

	if req.Mode == "replace" && strings.TrimSpace(req.Text) == "" {
		// 替换模式 + 空文本：绝不能把现有池清空。全是无效行时仍走正常流程返回
		// 逐行原因（此时也没新增条目，不会误清空）。
		writeErr(w, 400, "替换导入的文本为空，已拒绝（不会清空现有池）")
		return
	}

	// --- 导入验活 ---
	verify := true
	if req.Verify != nil {
		verify = *req.Verify
	}
	var rejected []proxyBulkInvalid
	var verifiedOK []string
	verifySkipped, verifyNote := false, ""
	disabled := 0
	if verify && len(incoming) > 0 {
		target := settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget)
		timeout := time.Duration(req.VerifyTimeoutSec) * time.Second
		if timeout <= 0 || timeout > 30*time.Second {
			timeout = importVerifyTimeout
		}
		if !targetReachableDirect(target, 4*time.Second) {
			// 验活环境本身不可用：宁可全导入也不能把整包误杀。
			verifySkipped = true
			verifyNote = "验证目标 " + target + " 直连不可达，本次跳过连通性验证（可在设置页改 proxypool_check_target）"
		} else {
			entries := make([]traffic.PoolEntry, len(incoming))
			for i, f := range incoming {
				entries[i] = f.entry
			}
			results := probeProxies(context.Background(), entries, target, timeout, importVerifyConcurrency)
			dropNew := map[string]bool{}
			disableExisting := map[string]bool{}
			for i, res := range results {
				if res.OK {
					verifiedOK = append(verifiedOK, incoming[i].entry.URL)
					continue
				}
				if incoming[i].isNew {
					dropNew[incoming[i].entry.URL] = true
				} else {
					disableExisting[incoming[i].entry.URL] = true
				}
				reason := res.Error
				if !incoming[i].isNew {
					reason = "已停用（连不通）: " + reason
					disabled++
				}
				rejected = append(rejected, proxyBulkInvalid{
					Line:   incoming[i].line,
					Raw:    maskProxy(incoming[i].entry.URL),
					Reason: reason,
				})
			}
			if len(dropNew) > 0 || len(disableExisting) > 0 {
				kept := st.Entries[:0]
				for _, e := range st.Entries {
					if dropNew[e.URL] {
						continue
					}
					if disableExisting[e.URL] {
						e.Enabled = false
					}
					kept = append(kept, e)
				}
				st.Entries = kept
				added -= len(dropNew)
				if added < 0 {
					added = 0
				}
			}
		}
	}

	if req.Strategy != "" {
		st.Strategy = req.Strategy
	}
	if err := s.applyProxyPool(*st); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	// 验活通过的条目必须解除旧熔断：applyProxyPool 会按 URL 继承旧条目的
	// breakOpen，如果不在这里清掉，页面会显示「验活成功但可用 0」。
	if len(verifiedOK) > 0 && s.m != nil && s.m.traffic != nil {
		for _, u := range verifiedOK {
			s.m.traffic.ProxyPoolClearBreak(u)
		}
		s.m.persistProxyBreaks()
	}
	if err := s.saveProxyPool(*st); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := map[string]any{
		"ok": true, "added": added, "updated": updated, "invalid": invalid,
		"rejected": rejected, "disabled": disabled, "total": len(st.Entries),
		"verified": verify && !verifySkipped,
	}
	if verifySkipped {
		out["verify_skipped"] = verifyNote
	}
	writeJSON(w, 200, out)
}

// targetReachableDirect 判断验活目标「本机直连」是否可达——不可达时验活没有意义
// （所有代理都会报错），必须跳过而不是把整包代理判死。
func targetReachableDirect(target string, timeout time.Duration) bool {
	if strings.TrimSpace(target) == "" {
		return false
	}
	hc := &http.Client{Timeout: timeout}
	resp, err := hc.Get(target)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return true
}

// probeProxies 用指定并发/超时验证一批代理（导入验活专用：比手动验证并发更高）。
func probeProxies(ctx context.Context, entries []traffic.PoolEntry, target string, timeout time.Duration, concurrency int) []proxyCheckResult {
	if concurrency < 1 {
		concurrency = importVerifyConcurrency
	}
	results := make([]proxyCheckResult, len(entries))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, e := range entries {
		masked := maskProxy(e.URL)
		wg.Add(1)
		go func(idx int, entry traffic.PoolEntry, echo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkOneProxy(ctx, idx, echo, entry.URL, target, timeout)
		}(i, e, masked)
	}
	wg.Wait()
	return results
}

// --- 连通性验证 ---

type proxyCheckResult struct {
	Index     int    `json:"index"`
	URL       string `json:"url"` // 掩码
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Error     string `json:"error,omitempty"`
	CheckedAt string `json:"checked_at"`
}

// proxyPoolCheck 验证给定（或全部）代理的真实可用性。结果写回内存态的
// last_ok/last_fail,失败直接熔断——「一键筛选可用」正是建立在这些结果上。
func (s *Server) proxyPoolCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URLs        []string `json:"urls"` // 空 = 全部已启用条目
		Target      string   `json:"target"`
		TimeoutSec  int      `json:"timeout_seconds"`
		BreakOnFail bool     `json:"break_on_fail"`
	}
	_ = decode(r, &req)
	st := s.loadProxyPool()
	target := strings.TrimSpace(req.Target)
	if target == "" {
		target = settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget)
	}
	timeout := time.Duration(req.TimeoutSec) * time.Second
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = defaultProxyCheckTimeout
	}

	want := map[string]bool{}
	for _, u := range req.URLs {
		want[u] = true
	}
	type pick struct {
		index int // 全量 entries 里的下标：前端勾选/删除失效依赖它，不能是子集下标
		entry traffic.PoolEntry
	}
	selected := make([]pick, 0, len(st.Entries))
	for i, e := range st.Entries {
		if len(want) > 0 && !want[e.URL] {
			continue
		}
		selected = append(selected, pick{index: i, entry: e})
	}
	results := make([]proxyCheckResult, len(selected))
	sem := make(chan struct{}, proxyCheckConcurrency)
	var wg sync.WaitGroup
	for i, sel := range selected {
		// 掩码 URL 用于回显;真实凭据只在请求时用。
		masked := maskProxy(sel.entry.URL)
		wg.Add(1)
		go func(slot int, fullIndex int, entry traffic.PoolEntry, echo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[slot] = checkOneProxy(context.Background(), fullIndex, echo, entry.URL, target, timeout)
		}(i, sel.index, sel.entry, masked)
	}
	wg.Wait()

	// 把验证结果写回池状态(成功清零连败、失败按需熔断),让下一次 Pick
	// 立刻避开坏出口,同时刷新页面上的 last_ok/last_fail。
	t := s.m.traffic
	cooldown := time.Duration(intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown)) * time.Minute
	for i, res := range results {
		if t == nil {
			continue
		}
		raw := selected[i].entry.URL
		if res.OK {
			t.ProxyPoolReportOK(raw)
		} else if req.BreakOnFail {
			t.ProxyPoolMarkBad(raw, cooldown)
		} else {
			t.ProxyPoolReportFail(raw)
		}
	}

	// 记录一次「最近检查」供 UI 展示时间戳。
	s.m.proxyCheckMu.Lock()
	s.m.proxyCheckLast = map[string]any{
		"at":       time.Now().Format(time.RFC3339),
		"target":   target,
		"count":    len(results),
		"ok_count": countOK(results),
	}
	s.m.proxyCheckMu.Unlock()
	s.m.persistProxyBreaks() // 手动验证同样落盘，重启后仍然跳过死代理

	writeJSON(w, 200, map[string]any{
		"target":        target,
		"entries_total": len(st.Entries),
		"results":       results,
	})
}

func countOK(list []proxyCheckResult) int {
	n := 0
	for _, r := range list {
		if r.OK {
			n++
		}
	}
	return n
}

// s_probeAll 并发验证一批上游。手动验证与后台健康检查共用同一套探测逻辑——
// 两条路径对「什么叫可用」的理解必须一致,否则页面显示可用但实际不通。
func s_probeAll(ctx context.Context, m *Manager, entries []traffic.PoolEntry, target string) []proxyCheckResult {
	results := make([]proxyCheckResult, len(entries))
	sem := make(chan struct{}, proxyCheckConcurrency)
	var wg sync.WaitGroup
	for i, e := range entries {
		masked := maskProxy(e.URL)
		wg.Add(1)
		go func(idx int, entry traffic.PoolEntry, echo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = checkOneProxy(ctx, idx, echo, entry.URL, target, defaultProxyCheckTimeout)
		}(i, e, masked)
	}
	wg.Wait()
	return results
}

// checkOneProxy 经由该代理请求 target,记录耗时与出口 IP。
func checkOneProxy(ctx context.Context, idx int, masked, raw, target string, timeout time.Duration) proxyCheckResult {
	res := proxyCheckResult{Index: idx, URL: masked, CheckedAt: time.Now().Format(time.RFC3339)}
	proxyURL, err := traffic.ValidateProxyURL(raw)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	transport := &http.Transport{}
	switch proxyURL.Scheme {
	case "socks5", "socks5h":
		// SOCKS5 交给 x/net/proxy 拨号:http.Transport 只认 HTTP 代理。
		transport.Proxy = nil
		transport.DialContext = func(c context.Context, network, addr string) (net.Conn, error) {
			return socksDial(c, proxyURL, addr)
		}
	default:
		transport.Proxy = http.ProxyURL(proxyURL)
	}
	hc := &http.Client{Timeout: timeout, Transport: transport}
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(qctx, http.MethodGet, target, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	start := time.Now()
	resp, err := hc.Do(req)
	res.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	res.OK = resp.StatusCode >= 200 && resp.StatusCode < 400
	if !res.OK {
		res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return res
	}
	res.ExitIP = extractIP(string(body))
	return res
}

// socksDial 通过 SOCKS5 代理建立到 addr 的连接。
func socksDial(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	var auth *proxy.Auth
	if proxyURL.User != nil {
		pass, _ := proxyURL.User.Password()
		auth = &proxy.Auth{User: proxyURL.User.Username(), Password: pass}
	}
	dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}
	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", addr)
	}
	return dialer.Dial("tcp", addr)
}

// extractIP 从探测响应里抓出口 IP(抓不到就留空,不影响可用性判定)。
func extractIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, key := range []string{`"ip"`, `"origin"`, `"query"`} {
		if i := strings.Index(s, key); i >= 0 {
			rest := s[i+len(key):]
			if j := strings.IndexAny(rest, "\"'"); j >= 0 {
				rest = rest[j+1:]
			}
			if k := strings.IndexAny(rest, "\"'} \n"); k >= 0 {
				rest = rest[:k]
			}
			if looksLikeIP(rest) {
				return rest
			}
		}
	}
	if looksLikeIP(s) {
		return s
	}
	return ""
}

func looksLikeIP(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

// maskProxy 隐藏凭据,只用于回显（用户名保留、密码替换为 ****）。
func maskProxy(raw string) string {
	u, err := traffic.ValidateProxyURL(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		if _, has := u.User.Password(); has {
			u.User = url.UserPassword(u.User.Username(), "****")
		}
	}
	return u.String()
}
