// 代理池的主动健康检查与 Agent 侧工具。
//
// 被动熔断要等「连败 5 次」,而一个已经挂掉的代理再试 5 次只是白白拖慢请求。
// 这里加一条后台巡检:每隔 N 分钟并发验证所有已启用上游,不通的立刻熔断。
//
// Agent 侧给两个工具:proxy_status(看池状态)与 proxy_report(上报「这个目标被限速/
// 不通」,平台据此换出口)。Agent 不需要知道每条命令走了哪个代理——出口选择
// 始终由平台按策略做,Agent 只负责反馈「这个出口对我不好使」。
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"

	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/artex/traffic"
)

// StartProxyPoolHealthCheck launches the background probe loop. It is a no-op
// when the interval is 0 (health check disabled).
func (m *Manager) StartProxyPoolHealthCheck() {
	if m == nil || m.pg == nil {
		return
	}
	interval := time.Duration(intSetting(m.pg, settingProxyHealthMinutes, defaultProxyHealthMinutes)) * time.Minute
	if interval <= 0 {
		log.Printf("[proxypool] 主动健康检查已关闭（proxypool_health_minutes=0）")
		return
	}
	go func() {
		// 启动延迟：避开进程刚起来的流量高峰，也给 hostd/traffic 代理留出时间。
		time.Sleep(90 * time.Second)
		for {
			m.RunProxyPoolHealthCheck()
			time.Sleep(interval)
		}
	}()
}

// RunProxyPoolHealthCheck probes every enabled upstream once and melts down the
// dead ones. Safe to call from the API (manual "check all") as well.
func (m *Manager) RunProxyPoolHealthCheck() {
	if m == nil || m.traffic == nil || m.pg == nil {
		return
	}
	if !m.proxyCheckInFlight.CompareAndSwap(false, true) {
		return // 已有一轮在跑
	}
	defer m.proxyCheckInFlight.Store(false)

	st := loadProxyPoolState(m.pg)
	if !st.Enabled {
		return // 总开关关闭：不做无意义的探测
	}
	enabled := make([]traffic.PoolEntry, 0, len(st.Entries))
	for _, e := range st.Entries {
		if e.Enabled {
			enabled = append(enabled, e)
		}
	}
	if len(enabled) == 0 {
		return
	}
	target := settingOr(m.pg, settingProxyCheckTarget, defaultProxyCheckTarget)
	cooldown := time.Duration(intSetting(m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown)) * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	results := s_probeAll(ctx, m, enabled, target)
	dead := 0
	for i, res := range results {
		raw := enabled[i].URL
		if res.OK {
			m.traffic.ProxyPoolReportOK(raw)
			continue
		}
		dead++
		m.traffic.ProxyPoolMarkBad(raw, cooldown)
	}
	if dead > 0 {
		log.Printf("[proxypool] 健康检查：%d/%d 个上游不可用，已熔断", dead, len(enabled))
		// 本机 mihomo 进程死亡后自动拉起（仅当失败的出口是 loopback）：mihomo 是
		// 平台自己管理的本地内核，没有 systemd 守护；不自动恢复会让录制代理整条
		// 出口长期失效（任务 21 实测 6 小时无流量）。
		if dead == len(enabled) && m.mihomo != nil {
			for _, e := range enabled {
				u, err := url.Parse(e.URL)
				if err != nil || u.Hostname() != "127.0.0.1" {
					continue
				}
				port, _ := strconv.Atoi(u.Port())
				if st, rerr := m.mihomo.RestartFromConfig(ctx, port); rerr != nil {
					log.Printf("[proxypool] 自动拉起 mihomo 失败: %v", rerr)
				} else if st.Running {
					log.Printf("[proxypool] 已自动拉起 mihomo（端口 %d），下一轮健康检查复验", st.Port)
				}
				break
			}
		}
	}
	// 池非空但 0 可用：必须显式告警。严格出口下请求会快速失败（不外泄真实 IP），
	// 非严格模式才会回退直连/全局代理——文案必须区分，否则会误导 worker。
	if n := m.traffic.ProxyPoolAvailable(); n == 0 && len(enabled) > 0 {
		if m.traffic.StrictEgress() && m.traffic.ProxyPoolConfigured() {
			log.Printf("[proxypool] 警告：池内 %d 个上游全部不可用，且严格出口已阻止直连——目标请求会快速失败（真实 IP 未暴露），需恢复上游或临时关闭严格出口", len(enabled))
		} else {
			log.Printf("[proxypool] 警告：池内 %d 个上游全部不可用，任务出口已回退直连/全局代理（真实 IP 暴露）", len(enabled))
		}
	}
	// 页面上的「最近检查」时间戳与手动验证共用同一份快照。
	m.proxyCheckMu.Lock()
	m.proxyCheckLast = map[string]any{
		"at":       time.Now().Format(time.RFC3339),
		"target":   target,
		"count":    len(results),
		"ok_count": countOK(results),
		"auto":     true,
	}
	m.proxyCheckMu.Unlock()
	// 把熔断结果落盘：下一次重启仍然跳过这些死代理。
	m.persistProxyBreaks()
}

// restoreProxyBreaks 恢复上次进程保存的熔断状态：不恢复的话，重启后所有已判定
// 不通的出口都会重新变「可用」，任务要白等一轮超时（现网 240 条里 231 条死代理）。
func (m *Manager) restoreProxyBreaks() {
	if m == nil || m.traffic == nil || m.pg == nil {
		return
	}
	raw, ok, err := m.pg.GetSetting(settingProxyBreaks)
	if err != nil || !ok || strings.TrimSpace(raw) == "" {
		return
	}
	state := map[string]int64{}
	if json.Unmarshal([]byte(raw), &state) != nil {
		return
	}
	if n := m.traffic.RestoreProxyBreaks(state); n > 0 {
		log.Printf("[proxypool] 已恢复 %d 个出口的熔断状态（重启不复活死代理）", n)
	}
}

// persistProxyBreaks 把当前未到期的熔断状态写回 settings，跨重启保留。
func (m *Manager) persistProxyBreaks() {
	if m == nil || m.traffic == nil || m.pg == nil {
		return
	}
	state := m.traffic.SnapshotProxyBreaks()
	raw, err := json.Marshal(state)
	if err != nil {
		return
	}
	if err := m.pg.SetSetting(settingProxyBreaks, string(raw)); err != nil {
		log.Printf("[proxypool] 熔断状态持久化失败: %v", err)
	}
}

// proxyTools 返回给 agent 的代理池工具。采集中关闭时池不生效,工具会明确说明
// 这一点而不是报错——agent 需要知道「现在走的是直连/全局代理」。
func (s *Server) proxyTools() []actool.CoreTool {
	proxyStatus := actool.Build(actool.Spec{
		Name:        "proxy_status",
		Description: "查当前出口代理池的状态：策略、每个上游的可用性/熔断剩余/最近一次成功失败时间、当前是否在生效。判断「目标连不通」是不是出口的问题时先看这里。",
		Schema: map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return s.proxyStatusResult()
		},
	})
	proxyReport := actool.Build(actool.Spec{
		Name: "proxy_report",
		Description: "上报「当前出口对这个目标不好使」（被限速 / 连不通 / 被封），平台会立即熔断该出口并换一个。" +
			"target 填你刚才访问的目标 host（可带端口）。只有确认是出口问题才调——目标本身拒绝服务不算。",
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"target": map[string]any{"type": "string", "description": "刚才访问的目标 host（可带端口，如 10.10.0.5:8080）"},
				"reason": map[string]any{"type": "string", "description": "原因（限速/超时/拒绝连接等），便于审计"},
			},
			"required": []any{"target"},
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return s.proxyReportResult(in)
		},
	})
	return []actool.CoreTool{proxyStatus, proxyReport}
}

func (s *Server) proxyStatusResult() (actool.Result, error) {
	if s.m == nil || s.m.traffic == nil {
		return actool.Errorf("代理池未初始化"), nil
	}
	st := s.loadProxyPool()
	available := 0
	if s.m.traffic != nil {
		available = s.m.traffic.ProxyPoolAvailable()
	}
	eff, socks5Blocked := s.effectivePoolEntries(st)
	out := map[string]any{
		"enabled":        st.Enabled,
		"strategy":       st.Strategy,
		"total":          len(st.Entries),
		"usable":         available,
		"effective":      len(eff),
		"socks5_blocked": socks5Blocked,
		"capturing":      s.m.TrafficEnabled(),
		"global_proxy":   s.m.GlobalProxy() != "",
		"upstreams":      s.m.traffic.ProxyPoolStatus(),
		"health_check":   settingOr(s.m.pg, settingProxyCheckTarget, defaultProxyCheckTarget),
	}
	if socks5Blocked > 0 {
		out["socks5_note"] = fmt.Sprintf("有 %d 条 socks5 上游因默认策略未生效（历史版本 socks5 拨号失败会 panic）。如需启用请在设置开启 proxypool_allow_socks5。", socks5Blocked)
	}
	switch {
	case len(st.Entries) == 0:
		out["note"] = "代理池为空：流量直接出本机（或走「全局出口代理」）。要轮换出口请在 系统 → 代理池 配置。"
	case !st.Enabled:
		out["note"] = "代理池已被总开关停用：出口回退全局代理/直连。"
	case available == 0:
		if s.m.traffic != nil && s.m.traffic.StrictEgress() && s.m.traffic.ProxyPoolConfigured() {
			out["note"] = "池内全部上游当前熔断，且严格出口已阻止直连：目标请求会快速失败（真实 IP 未暴露）。先恢复上游或临时关闭严格出口再继续。"
		} else {
			out["note"] = "池内全部上游当前熔断：出口已回退直连/全局代理（真实 IP 暴露）。先验证连通性再继续。"
		}
	case !s.m.TrafficEnabled():
		out["note"] = "代理池已启用（流量捕获关闭）：Agent 的 Bash/WebFetch 直接注入池内出口，每个 worker 固定一个上游，无流量留痕。"
	}
	return jsonResult(out)
}

func (s *Server) proxyReportResult(in json.RawMessage) (actool.Result, error) {
	var a struct {
		Target string `json:"target"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(in, &a)
	target := strings.TrimSpace(a.Target)
	if target == "" {
		return actool.Errorf("target 为必填"), nil
	}
	if s.m == nil || s.m.traffic == nil {
		return actool.Errorf("代理池未初始化"), nil
	}
	cooldown := time.Duration(intSetting(s.m.pg, settingProxyHealthCooldown, defaultProxyHealthCooldown)) * time.Minute
	broken := s.m.traffic.ProxyPoolReportBad(target, cooldown)
	if broken == "" {
		return jsonResult(map[string]any{
			"ok":   false,
			"note": "该目标没有走代理池（直连或走全局出口代理），没有可切换的出口。",
		})
	}
	return jsonResult(map[string]any{
		"ok":              true,
		"broken_upstream": broken,
		"cooldown_min":    int(cooldown / time.Minute),
		"note":            "已熔断该出口，后续请求会自动换用其它上游；若仍不通说明是目标侧问题。",
	})
}
