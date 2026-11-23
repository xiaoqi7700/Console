package server

// 本机 Clash / mihomo 端口探测。
//
// 背景：用户把机场订阅导进来后，最常见的实际用法不是「把订阅里的每个节点
// 都塞进代理池」，而是「本机已经跑着 Clash，让平台复用它的 mixed-port」。
// 旧实现只接受用户手填的代理 URL，池里一旦是死条目（例如 127.0.0.1:12500），
// 页面就会显示 usable=0，而真正可用的 127.0.0.1:7897 不会被自动发现。
//
// 这里做三件事：
//  1. 扫描常见 mixed-port（7890/7891/7897/1080/…）并经代理真实请求验活；
//  2. 把 global_proxy 若是回环地址也纳入候选；
//  3. 启动时若池为空或全部熔断，自动把第一个可用本机端口加入池（可关）。

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/traffic"
)

const (
	settingProxyLocalPorts = "proxypool_local_ports" // 逗号分隔，覆盖默认探测端口
	settingProxyAutoLocal  = "proxypool_auto_local"  // 默认 true：池不可用时自动接管本机 Clash
)

var defaultLocalProxyPorts = []int{7890, 7891, 7897, 7898, 7899, 1080, 10808, 10809, 12500, 2080, 8889, 9090}

type localProxyCandidate struct {
	URL       string `json:"url"`
	Port      int    `json:"port"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Error     string `json:"error,omitempty"`
	Source    string `json:"source"` // clash-port / global-proxy / subscription-port
}

// parseLocalPorts 解析设置里的端口列表；空/非法时回退默认列表。
func parseLocalPorts(raw string) []int {
	seen := map[int]bool{}
	out := make([]int, 0, len(defaultLocalProxyPorts))
	for _, part := range strings.Split(raw, ",") {
		p, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || p <= 0 || p > 65535 || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	if len(out) == 0 {
		return append([]int(nil), defaultLocalProxyPorts...)
	}
	return out
}

// localProxyPorts 读取设置里的端口列表；额外传入的端口（例如订阅 YAML 的
// mixed-port）会合并到前面。
func localProxyPorts(pg interface {
	GetSetting(string) (string, bool, error)
}, extra ...int) []int {
	raw := ""
	if pg != nil {
		if v, ok, err := pg.GetSetting(settingProxyLocalPorts); err == nil && ok {
			raw = v
		}
	}
	base := parseLocalPorts(raw)
	seen := map[int]bool{}
	out := make([]int, 0, len(base)+len(extra))
	for _, p := range append(append([]int{}, extra...), base...) {
		if p > 0 && p <= 65535 && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// detectLocalProxyCandidates 并发探测一组本地端口。target 为空时读默认验活地址。
// 只把「真的能经该端口出网」的候选标为 OK；端口关闭/代理不通都给错误原因。
func detectLocalProxyCandidates(ctx context.Context, pg interface {
	GetSetting(string) (string, bool, error)
}, extraPorts []int, target string) []localProxyCandidate {
	if strings.TrimSpace(target) == "" {
		target = defaultProxyCheckTarget
	}
	ports := localProxyPorts(pg, extraPorts...)

	// 去重：同一个端口只测一次。
	cands := make([]localProxyCandidate, len(ports))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, p := range ports {
		wg.Add(1)
		go func(idx, port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			url := fmt.Sprintf("http://127.0.0.1:%d", port)
			c := localProxyCandidate{URL: url, Port: port, Source: "clash-port"}
			// 先做 TCP 预检，避免对关闭端口跑完整 HTTP 超时。
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
			if err != nil {
				c.Error = "端口未监听: " + err.Error()
				cands[idx] = c
				return
			}
			_ = conn.Close()
			// 主验活目标失败时用 generate_204 兜底：部分 Clash 规则会拦截 ipify，
			// 但 204 探测仍能证明「这个端口能出网」。
			probes := []string{target, "http://www.gstatic.com/generate_204"}
			var last proxyCheckResult
			for _, probe := range probes {
				last = checkOneProxy(ctx, idx, maskProxy(url), url, probe, 5*time.Second)
				if last.OK {
					break
				}
			}
			c.OK = last.OK
			c.LatencyMS = last.LatencyMS
			c.ExitIP = last.ExitIP
			c.Error = last.Error
			cands[idx] = c
		}(i, p)
	}
	wg.Wait()
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].OK != cands[j].OK {
			return cands[i].OK
		}
		return cands[i].LatencyMS < cands[j].LatencyMS
	})
	return cands
}

// addLocalCandidates 把可用候选合并进池（已存在则启用，不覆盖用户命名/权重）。
// 返回新增/启用的 URL 数。
func addLocalCandidates(st *proxyPoolState, cands []localProxyCandidate, source string) int {
	if st == nil {
		return 0
	}
	byURL := map[string]int{}
	for i, e := range st.Entries {
		byURL[e.URL] = i
	}
	added := 0
	for _, c := range cands {
		if !c.OK || strings.TrimSpace(c.URL) == "" {
			continue
		}
		if idx, ok := byURL[c.URL]; ok {
			if !st.Entries[idx].Enabled {
				st.Entries[idx].Enabled = true
				added++
			}
			continue
		}
		name := fmt.Sprintf("local-clash-%d", c.Port)
		if c.Source == "global-proxy" {
			name = "global-proxy"
		}
		if source != "" {
			name = source
		}
		st.Entries = append(st.Entries, traffic.PoolEntry{URL: c.URL, Name: name, Enabled: true, Weight: 1})
		byURL[c.URL] = len(st.Entries) - 1
		added++
	}
	return added
}

// applyDetectedLocalProxies 是 detect + add + save + apply 的组合，API 与自动接管共用。
func (s *Server) applyDetectedLocalProxies(ctx context.Context, cands []localProxyCandidate) (int, error) {
	st := s.loadProxyPool()
	added := addLocalCandidates(st, cands, "")
	if added == 0 {
		return 0, nil
	}
	if err := s.applyProxyPool(*st); err != nil {
		return 0, err
	}
	if err := s.saveProxyPool(*st); err != nil {
		return added, err
	}
	// 只清除本次验活通过的条目，避免把用户池里其他死条目的熔断状态一起复活。
	if s.m != nil && s.m.traffic != nil {
		for _, c := range cands {
			if c.OK {
				s.m.traffic.ProxyPoolClearBreak(c.URL)
			}
		}
		s.m.persistProxyBreaks()
	}
	return added, nil
}

// autoDetectLocalProxyForManager 在启动时调用：池为空或全部熔断时，自动把
// 第一个可用本机 Clash 端口加入池。可在设置里用 proxypool_auto_local=false 关闭。
func autoDetectLocalProxyForManager(ctx context.Context, m *Manager) {
	if m == nil || m.pg == nil || m.traffic == nil {
		return
	}
	if v, ok, err := m.pg.GetSetting(settingProxyAutoLocal); err == nil && ok {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "false" || v == "0" || v == "off" || v == "no" {
			return
		}
	}
	st := loadProxyPoolState(m.pg)
	if !st.Enabled {
		return
	}
	if m.traffic.ProxyPoolAvailable() > 0 {
		return
	}
	// 把 global_proxy 如果是回环端口也纳入候选。
	extra := []int{}
	if gp, ok, _ := m.pg.GetSetting(settingGlobalProxy); ok {
		if u, err := traffic.ValidateProxyURL(gp); err == nil && isLoopbackHost(u.Hostname()) {
			if p, err := strconv.Atoi(u.Port()); err == nil {
				extra = append(extra, p)
			}
		}
	}
	cands := detectLocalProxyCandidates(ctx, m.pg, extra, "")
	added := addLocalCandidates(st, cands, "")
	if added == 0 {
		return
	}
	if err := m.traffic.SetProxyPool(st.Entries, st.Strategy); err != nil {
		return
	}
	if err := saveProxyPoolState(m.pg, *st); err != nil {
		return
	}
	for _, c := range cands {
		if c.OK {
			m.traffic.ProxyPoolClearBreak(c.URL)
		}
	}
	m.persistProxyBreaks()
	// 日志只写端口/数量，不写 URL（URL 可能带凭据）。
	ports := make([]string, 0, len(cands))
	for _, c := range cands {
		if c.OK {
			ports = append(ports, strconv.Itoa(c.Port))
		}
	}
	if len(ports) > 0 {
		log.Printf("[proxypool] 本机 Clash 自动接管：可用端口 %s，池加入 %d 条", strings.Join(ports, ","), added)
	}
}

// isLoopbackHost 判断 host 是否是回环地址（含 localhost）。
func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// proxyPoolDetectLocal 是 UI 的「检测本机 Clash」入口。
func (s *Server) proxyPoolDetectLocal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Ports  []int  `json:"ports"`
		Target string `json:"target"`
		Use    bool   `json:"use"`
	}
	_ = decode(r, &req)
	if strings.TrimSpace(req.Target) == "" {
		req.Target = settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget)
	}
	cands := detectLocalProxyCandidates(r.Context(), s.m.pg, req.Ports, req.Target)
	added := 0
	if req.Use {
		var err error
		added, err = s.applyDetectedLocalProxies(r.Context(), cands)
		if err != nil {
			writeErr(w, 500, "已检测但写入代理池失败: "+err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{
		"ok":         true,
		"target":     req.Target,
		"candidates": cands,
		"added":      added,
	})
}
