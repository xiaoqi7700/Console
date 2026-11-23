package server

// 代理池 → mihomo 内核 API：状态、安装、启动、停止。
//
// 前端从 /api/proxypool/subscription/fetch 拿到 Clash YAML 后，可直接把 YAML
// POST 到 /api/proxypool/mihomo/start；服务端启动 mihomo 并把 mixed-port 作为
// 普通 HTTP 上游加入代理池。停止时只移除本内核对应的条目，不动用户手工条目。

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Autumn-27/artex/mihomo"
	"github.com/Autumn-27/artex/traffic"
)

const settingProxyMihomoPath = "proxypool_mihomo_path"

// settingMihomoMirrors 是安装加速镜像前缀列表（逗号/换行分隔，{url} 占位符可选）。
// 默认走 mihomo.DefaultMirrors；镜像下载必须与 GitHub API 的 digest 对上。
const settingMihomoMirrors = "proxypool_mihomo_mirrors"

func (s *Server) proxyPoolMihomoStatus(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.mihomo == nil {
		writeErr(w, 503, "mihomo 管理器未初始化")
		return
	}
	st := s.m.mihomo.Status()
	configured := settingOr(s.m.pg, settingProxyMihomoPath, "")
	if configured != "" {
		if info, err := os.Stat(configured); err == nil && info.Mode().IsRegular() {
			st.Installed = true
			st.Binary = configured
		}
	}
	writeJSON(w, 200, map[string]any{
		"ok":     true,
		"status": st,
		"path":   configured,
	})
}

func (s *Server) proxyPoolMihomoInstall(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.mihomo == nil {
		writeErr(w, 503, "mihomo 管理器未初始化")
		return
	}
	var req struct {
		Proxy  string `json:"proxy"`
		URL    string `json:"url"`    // 可选：自定义安装包 URL（内网镜像/文件服务）
		SHA256 string `json:"sha256"` // 可选：自定义来源的强校验
		Path   string `json:"path"`   // 可选：服务器本地安装包路径（离线安装）
		Source string `json:"source"` // 保留字段（默认已是官方+镜像链路）
	}
	_ = decode(r, &req)
	proxy := strings.TrimSpace(req.Proxy)
	if proxy == "" {
		proxy = settingOr(s.m.pg, settingGlobalProxy, "")
	}
	var res mihomo.InstallResult
	var err error
	// 安装可能持续几十分钟（慢链路续传）：不要绑在请求 ctx 上，页面刷新/代理超时
	// 不应该把下载打断。超时由 mihomo 包内部的整体预算控制。
	installCtx, cancelInstall := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Minute)
	defer cancelInstall()
	switch {
	case strings.TrimSpace(req.Path) != "":
		// 离线：运维把安装包拷到服务器后，从本地文件安装（不依赖外网）。
		res, err = s.m.mihomo.InstallFromFile(req.Path)
	case strings.TrimSpace(req.URL) != "":
		// 镜像：任意 http(s) 地址（.gz/.zip/裸二进制），可带 sha256 强校验。
		res, err = s.m.mihomo.InstallFromURL(installCtx, req.URL, req.SHA256, proxy)
	default:
		// 官方 GitHub + 加速镜像（镜像下载必须与 GitHub API 给出的 SHA-256 对上）。
		mirrors := mihomo.ParseMirrors(settingOr(s.m.pg, settingMihomoMirrors, strings.Join(mihomo.DefaultMirrors, ",")))
		res, err = s.m.mihomo.Install(installCtx, proxy, mirrors)
	}
	if err != nil {
		writeErr(w, 502, "安装 mihomo 失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "install": res})
}

func (s *Server) proxyPoolMihomoStart(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.mihomo == nil {
		writeErr(w, 503, "mihomo 管理器未初始化")
		return
	}
	var req struct {
		YAML     string   `json:"yaml"`
		URL      string   `json:"url"`
		Port     int      `json:"port"`
		Binary   string   `json:"binary"`
		Outbound string   `json:"outbound"` // 可选：MATCH 到哪个出口组/节点（订阅里的组名）
		Mode     string   `json:"mode"`     // 可选：group/node/load-balance/url-test/fallback
		Nodes    []string `json:"nodes"`    // 可选：轮询/测速/故障转移用的节点名
		Use      *bool    `json:"use"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	yamlText := strings.TrimSpace(req.YAML)
	if yamlText == "" && strings.TrimSpace(req.URL) != "" {
		body, _, err := fetchSubscriptionBody(r.Context(), req.URL)
		if err != nil {
			writeErr(w, 502, err.Error())
			return
		}
		yamlText = string(body)
	}
	if yamlText == "" {
		writeErr(w, 400, "yaml 或 url 至少提供一个")
		return
	}
	binary := strings.TrimSpace(req.Binary)
	if binary == "" {
		binary = settingOr(s.m.pg, settingProxyMihomoPath, "")
	}
	st, err := s.m.mihomo.Start(r.Context(), yamlText, binary, req.Port, mihomo.StartOptions{
		Preferred: req.Outbound,
		Mode:      req.Mode,
		Nodes:     req.Nodes,
	})
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	use := true
	if req.Use != nil {
		use = *req.Use
	}
	proxyURL := fmt.Sprintf("http://127.0.0.1:%d", st.Port)
	added := false
	if use && st.Port > 0 {
		ps := s.loadProxyPool()
		if ps.Entries == nil {
			ps.Entries = []traffic.PoolEntry{}
		}
		found := false
		for i := range ps.Entries {
			if ps.Entries[i].Name == "mihomo-local" || ps.Entries[i].URL == proxyURL {
				ps.Entries[i].URL = proxyURL
				ps.Entries[i].Name = "mihomo-local"
				ps.Entries[i].Enabled = true
				found = true
				added = true
				break
			}
		}
		if !found {
			ps.Entries = append(ps.Entries, traffic.PoolEntry{URL: proxyURL, Name: "mihomo-local", Enabled: true, Weight: 1})
			added = true
		}
		// 「接入」语义 = 启用代理池：否则条目加进去了、总开关还关着，流量仍走
		// 全局代理/直连，用户会以为启动失败（实测反馈）。严格出口下代理挂了会
		// 失败而不是漏真实 IP，符合「配置了代理就不回退直连」的约定。
		ps.Enabled = true
		if err := s.applyProxyPool(*ps); err != nil {
			writeErr(w, 500, "mihomo 已启动但写入代理池失败: "+err.Error())
			return
		}
		if err := s.saveProxyPool(*ps); err != nil {
			writeErr(w, 500, "mihomo 已启动但保存代理池失败: "+err.Error())
			return
		}
		if s.m.traffic != nil {
			s.m.traffic.ProxyPoolClearBreak(proxyURL)
			s.m.persistProxyBreaks()
		}
	}
	writeJSON(w, 200, map[string]any{
		"ok":     true,
		"status": st,
		"proxy":  proxyURL,
		"added":  added,
		"note":   "mihomo 已启动；如出口探测失败，请检查订阅节点/规则是否可用",
	})
}

// proxyPoolMihomoDelays 对订阅节点做真实延迟测试（经 mihomo external-controller
// 的 /proxies/{name}/delay）。需要内核已启动；names 为空时测全部真实节点。
func (s *Server) proxyPoolMihomoDelays(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.mihomo == nil {
		writeErr(w, 503, "mihomo 管理器未初始化")
		return
	}
	var req struct {
		Names      []string `json:"names"`
		Target     string   `json:"target"`
		TimeoutSec int      `json:"timeout_seconds"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if len(req.Names) > mihomo.MaxDelayNodes {
		writeErr(w, 400, fmt.Sprintf("一次最多测速 %d 个节点（当前 %d），请缩小范围", mihomo.MaxDelayNodes, len(req.Names)))
		return
	}
	timeout := mihomo.NormalizeDelayTimeout(time.Duration(req.TimeoutSec) * time.Second)
	// 预算按「节点数/并发 × 单节点超时」算：固定 90s 会让大订阅（200+ 节点）
	// 在中途被 ctx 截断，剩下没轮到的节点全被记成假超时。
	budget := 10 * time.Minute
	if n := len(req.Names); n > 0 {
		rounds := (n + mihomo.DelayConcurrency - 1) / mihomo.DelayConcurrency
		// 每个节点的实际上限是 timeout+3s（delayOne 的 client.Timeout），按它算预算，
		// 否则全线超时的大订阅会在最后一轮被 ctx 截断成假超时。
		budget = time.Duration(rounds)*(timeout+3*time.Second) + 30*time.Second
		if budget > 10*time.Minute {
			budget = 10 * time.Minute
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), budget)
	defer cancel()
	results, err := s.m.mihomo.Delay(ctx, req.Names, req.Target, timeout)
	if err != nil {
		writeErr(w, 409, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"target":  req.Target,
		"results": results,
	})
}

func (s *Server) proxyPoolMihomoStop(w http.ResponseWriter, r *http.Request) {
	if s.m == nil || s.m.mihomo == nil {
		writeErr(w, 503, "mihomo 管理器未初始化")
		return
	}
	st := s.m.mihomo.Status()
	if err := s.m.mihomo.Stop(); err != nil {
		writeErr(w, 500, "停止 mihomo 失败: "+err.Error())
		return
	}
	removed := 0
	ps := s.loadProxyPool()
	proxyURL := ""
	if st.Port > 0 {
		proxyURL = fmt.Sprintf("http://127.0.0.1:%d", st.Port)
	}
	kept := ps.Entries[:0]
	for _, e := range ps.Entries {
		// v0.8：mihomo 进程可能已经自行退出，Status().Port 会是 0；
		// 此时仍要按名字清掉残留的 mihomo-local 池条目。
		if e.Name == "mihomo-local" || (proxyURL != "" && e.URL == proxyURL) {
			removed++
			continue
		}
		kept = append(kept, e)
	}
	if removed > 0 {
		ps.Entries = kept
		if err := s.applyProxyPool(*ps); err != nil {
			writeErr(w, 500, "mihomo 已停止但热更新代理池失败: "+err.Error())
			return
		}
		if err := s.saveProxyPool(*ps); err != nil {
			writeErr(w, 500, "mihomo 已停止但保存代理池失败: "+err.Error())
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "removed": removed})
}
