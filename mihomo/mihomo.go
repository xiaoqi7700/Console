// Package mihomo 管理本机 mihomo（Clash.Meta）内核。
//
// 为什么需要它：机场订阅的绝大多数节点是 vmess/ss/trojan/vless，平台自己的
// HTTP 代理池无法直接消费；正确做法是让 mihomo 读整份 Clash YAML，在本机开一个
// mixed-port，平台把这个端口当作普通 HTTP 上游加入代理池。
//
// 本包只负责「找到/安装二进制、改配置、起停进程、等端口」；不解析业务代理池，
// 也不做流量捕获。配置里的节点凭据只落在本机 data 目录，不写日志。
package mihomo

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/proxyprobe"
	"gopkg.in/yaml.v3"
)

const (
	defaultStartTimeout = 20 * time.Second
	downloadLimit       = 200 << 20 // 200MB，防止异常响应写满磁盘
)

type Status struct {
	Running    bool   `json:"running"`
	Installed  bool   `json:"installed"`
	Port       int    `json:"port"`
	PID        int    `json:"pid"`
	Binary     string `json:"binary"`
	ConfigPath string `json:"config_path"`
	LogPath    string `json:"log_path"`
	StartedAt  string `json:"started_at,omitempty"`
	Version    string `json:"version,omitempty"`
	LastError  string `json:"last_error,omitempty"`
	// Outbound/Mode/Nodes 是当前配置文件里的实际出口（从 rules MATCH 反推），
	// 供节点管理页展示「现在到底用的什么策略」；配置文件被删/未启动时为空。
	Outbound string   `json:"outbound,omitempty"`
	Mode     string   `json:"mode,omitempty"`
	Nodes    []string `json:"nodes,omitempty"`
	// ControllerPort 是本次启动的 external-controller 端口（只绑回环；secret 不回显）。
	ControllerPort int `json:"controller_port,omitempty"`
}

type InstallResult struct {
	Path      string `json:"path"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	SourceURL string `json:"source_url"`
	// ChecksumVerified 表示 release 提供了 .sha256 且校验通过；没有校验文件时为 false。
	ChecksumVerified bool `json:"checksum_verified"`
}

// releaseAsset 是 GitHub Release 里的一项资产；命名类型便于测试 pickAsset。
type releaseAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"` // 形如 sha256:<hex>；GitHub 新版 API 提供
}

type Manager struct {
	mu sync.Mutex
	// startMu 串行化 Start：并发启动（测速自动启动 + 手动「启动并应用策略」）会互相
	// Stop，把对方刚起来的内核杀掉。
	startMu    sync.Mutex
	dir        string
	binary     string
	port       int
	configPath string
	logPath    string
	startedAt  time.Time
	version    string
	lastErr    string
	cmd        *exec.Cmd
	// external-controller（只绑 127.0.0.1 + 随机 secret）：节点延迟测速走它的
	// /proxies/{name}/delay。只在本次进程生命周期内有效。
	ctrlAddr   string
	ctrlSecret string
}

func New(dataDir string) *Manager {
	dir := filepath.Join(dataDir, "mihomo")
	return &Manager{
		dir:        dir,
		configPath: filepath.Join(dir, "config.yaml"),
		logPath:    filepath.Join(dir, "mihomo.log"),
	}
}

func (m *Manager) Dir() string { return m.dir }

// FindBinary 按「显式配置 → 环境变量 → data/tools → PATH」顺序找 mihomo。
func (m *Manager) FindBinary(configured string) (string, error) {
	var candidates []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p != "" {
			candidates = append(candidates, p)
		}
	}
	add(configured)
	add(os.Getenv("POJUN_MIHOMO_PATH"))
	add(filepath.Join(m.dir, "mihomo"))
	add(filepath.Join(m.dir, "mihomo.exe"))
	add(filepath.Join(filepath.Dir(m.dir), "tools", "mihomo"))
	add(filepath.Join(filepath.Dir(m.dir), "tools", "mihomo.exe"))
	for _, name := range []string{"mihomo", "mihomo.exe", "clash-meta", "clash-meta.exe", "Clash.Meta", "clash"} {
		if p, err := exec.LookPath(name); err == nil {
			candidates = append(candidates, p)
		}
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			abs, _ := filepath.Abs(p)
			m.mu.Lock()
			m.binary = abs
			m.mu.Unlock()
			return abs, nil
		}
	}
	if configured != "" {
		return "", fmt.Errorf("配置的 mihomo 路径不存在: %s", configured)
	}
	return "", fmt.Errorf("未找到 mihomo 内核：可点「安装 mihomo」自动下载，或把 mihomo 放到 %s，或设置 POJUN_MIHOMO_PATH", filepath.Join(m.dir, "mihomo"))
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{
		Installed:  m.binary != "",
		Port:       m.port,
		Binary:     m.binary,
		ConfigPath: m.configPath,
		LogPath:    m.logPath,
		Version:    m.version,
		LastError:  m.lastErr,
	}
	if m.cmd != nil && m.cmd.Process != nil {
		st.Running = true
		st.PID = m.cmd.Process.Pid
	}
	if !m.startedAt.IsZero() {
		st.StartedAt = m.startedAt.Format(time.RFC3339)
	}
	if m.ctrlAddr != "" {
		if _, portStr, err := net.SplitHostPort(m.ctrlAddr); err == nil {
			if p, err := strconv.Atoi(portStr); err == nil {
				st.ControllerPort = p
			}
		}
	}
	if m.configPath != "" {
		st.Outbound, st.Mode, st.Nodes = readActivePlan(m.configPath)
	}
	// 进程重启后 m.binary 为空，但之前安装的 <dir>/mihomo(.exe) 还在；
	// 状态页/订阅弹窗据此显示「已安装」，不必重新下载。
	if !st.Installed {
		for _, name := range []string{"mihomo", "mihomo.exe"} {
			p := filepath.Join(m.dir, name)
			if info, err := os.Stat(p); err == nil && info.Mode().IsRegular() {
				st.Installed = true
				st.Binary = p
				break
			}
		}
	}
	return st
}

// StartOptions 描述「整份订阅怎么变成一个出口」：
//
//	Mode="" / "group"  —— MATCH 到 Preferred（组或节点；空=第一个组，旧行为）
//	Mode="node"        —— MATCH 到 Preferred 指定的单个节点
//	Mode="load-balance"—— 在所选 Nodes 上建轮询组 POJUN-AUTO，MATCH 到它
//	Mode="url-test"    —— 所选 Nodes 自动测速选最快（url-test）
//	Mode="fallback"    —— 所选 Nodes 按顺序故障转移
//
// Nodes 只对 load-balance/url-test/fallback 生效；组名固定 POJUN-AUTO，
// 每次启动按最新选择重建，不与订阅自带组冲突（同名则覆盖）。
type StartOptions struct {
	Preferred string
	Mode      string
	Nodes     []string
	// ControllerAddr/ControllerSecret 由 Start 生成，只用于写 external-controller；
	// 外部调用方不需要/不应该设置。
	ControllerAddr   string
	ControllerSecret string
}

const autoGroupName = "POJUN-AUTO"

// Start 用整份 Clash YAML 启动 mihomo，并等 mixed-port 真正可连。
// requestedPort=0 时自动选一个空闲端口。
func (m *Manager) Start(ctx context.Context, yamlText, configuredBinary string, requestedPort int, opts StartOptions) (Status, error) {
	if strings.TrimSpace(yamlText) == "" {
		return m.Status(), fmt.Errorf("Clash 配置为空")
	}
	// 串行化启动：测速自动启动与「启动并应用策略」可能同时进来。
	m.startMu.Lock()
	defer m.startMu.Unlock()
	binary, err := m.FindBinary(configuredBinary)
	if err != nil {
		return m.Status(), err
	}
	_ = m.Stop()

	port := requestedPort
	if port <= 0 || !portFree(port) {
		port, err = freePort()
		if err != nil {
			return m.Status(), fmt.Errorf("选择 mixed-port 失败: %w", err)
		}
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return m.Status(), err
	}
	// 节点测速需要 mihomo 的 RESTful API：只绑回环 + 每次随机 secret。
	ctrlPort, err := freePort()
	if err != nil {
		return m.Status(), fmt.Errorf("分配 external-controller 端口失败: %w", err)
	}
	opts.ControllerAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(ctrlPort))
	opts.ControllerSecret = randomSecret()
	configPath, err := m.writeConfig(yamlText, port, opts)
	if err != nil {
		return m.Status(), err
	}

	logFile, err := os.OpenFile(m.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return m.Status(), fmt.Errorf("打开 mihomo 日志失败: %w", err)
	}
	cmd := exec.Command(binary, "-d", m.dir, "-f", configPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return m.Status(), fmt.Errorf("启动 mihomo 失败: %w", err)
	}
	_ = logFile.Close()

	m.mu.Lock()
	m.cmd = cmd
	m.port = port
	m.binary = binary
	m.configPath = configPath
	m.startedAt = time.Now()
	m.lastErr = ""
	m.ctrlAddr = opts.ControllerAddr
	m.ctrlSecret = opts.ControllerSecret
	m.mu.Unlock()

	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd {
			m.cmd = nil
			m.port = 0
			// 进程已退出：控制器句柄必须一起清掉，否则 Status 会继续对外报
			// controller_port，指向一个没人监听的端口。
			m.ctrlAddr = ""
			m.ctrlSecret = ""
			if err != nil {
				m.lastErr = "mihomo 已退出: " + err.Error()
			}
		}
		m.mu.Unlock()
		// 先清状态再通知：否则启动失败路径拿到的是「还在运行」的假状态。
		done <- err
	}()

	deadline := time.Now().Add(defaultStartTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			return m.Status(), fmt.Errorf("mihomo 启动后立即退出: %v；日志尾部: %s", err, tail(m.logPath, 2048))
		default:
		}
		if portOpen("127.0.0.1", port, 300*time.Millisecond) {
			// 端口开了还不算可用：经它请求一次，确认规则/节点至少有一条能出网。
			if probeErr := probeViaHTTPProxy(ctx, fmt.Sprintf("http://127.0.0.1:%d", port)); probeErr != nil {
				m.mu.Lock()
				m.lastErr = "mixed-port 已监听，但出口探测失败: " + probeErr.Error()
				m.mu.Unlock()
			}
			m.mu.Lock()
			m.version = detectVersion(binary)
			m.mu.Unlock()
			return m.Status(), nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	// 只停自己启动的进程：并发 Start（一个来自「测速」自动启动、一个来自「启动并
	// 应用策略」）时 m.cmd 可能已经是后来者刚起来的健康内核，无脑 Stop 会把它杀掉。
	m.mu.Lock()
	stillMine := m.cmd == cmd
	m.mu.Unlock()
	if stillMine {
		_ = m.Stop()
	}
	return m.Status(), fmt.Errorf("mihomo 端口 %d 在 %s 内未监听；日志尾部: %s", port, defaultStartTimeout, tail(m.logPath, 2048))
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	m.cmd = nil
	m.port = 0
	m.ctrlAddr = ""
	m.ctrlSecret = ""
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	if err := cmd.Process.Kill(); err != nil {
		return err
	}
	return nil
}

// writeConfig 在原始 YAML 上重写监听参数：mixed-port 用分配端口、只绑回环、
// 去掉会冲突的 port/socks-port/redir-port/tproxy-port，关闭外部控制器。
func (m *Manager) writeConfig(yamlText string, port int, opts StartOptions) (string, error) {
	var cfg map[string]any
	if err := yaml.Unmarshal([]byte(yamlText), &cfg); err != nil {
		return "", fmt.Errorf("解析 Clash YAML 失败: %w", err)
	}
	if cfg == nil {
		return "", fmt.Errorf("Clash 配置为空")
	}
	if _, ok := cfg["proxies"]; !ok {
		if _, ok := cfg["proxy-providers"]; !ok {
			return "", fmt.Errorf("不是 Clash 配置：缺少 proxies / proxy-providers")
		}
	}
	cfg["mixed-port"] = port
	cfg["allow-lan"] = false
	cfg["bind-address"] = "127.0.0.1"
	if opts.ControllerAddr != "" {
		cfg["external-controller"] = opts.ControllerAddr
		cfg["secret"] = opts.ControllerSecret
	} else {
		cfg["external-controller"] = ""
		cfg["secret"] = ""
	}
	delete(cfg, "port")
	delete(cfg, "socks-port")
	delete(cfg, "redir-port")
	delete(cfg, "tproxy-port")
	// 平台只需要 mihomo 把「整份订阅」变成一个本地 mixed-port 上游，不需要按域名
	// 分流。订阅自带的 GEOIP/GEOSITE/RULE-SET 会让 mihomo 启动时下载 MMDB/GeoSite，
	// 在受限网络里表现为「20s 内未监听；日志 Can't find MMDB, start download」。
	// 因此删掉 rule-providers/sub-rules、rules 收敛为一条 MATCH、关闭 geo 自动更新；
	// TUN 也关掉（容器/无特权环境本就用不了，只留 mixed-port）。
	delete(cfg, "rule-providers")
	delete(cfg, "sub-rules")
	delete(cfg, "tun")
	// listeners 是与 mixed-port 平行的独立监听数组（每项自带 listen/port）。
	// 不删掉的话，恶意订阅可注入 listen: 0.0.0.0 的 socks listener——
	// bind-address/allow-lan 只约束 mixed-port，管不到这里（审计 B4）。
	delete(cfg, "listeners")
	cfg["geodata-mode"] = false
	cfg["geo-auto-update"] = false

	// mihomo 专有语法:dns.nameserver-policy 里 "rule-set:<name>"/"geosite:<name>" 键
	// 引用 rule-providers/GEOSITE;上面已删 rule-providers 并收敛 rules,残留引用
	// 会让 mihomo 启动即 fatal(not found rule-set: X)。清理这些引用键。
	if d, ok := cfg["dns"].(map[string]any); ok {
		if np, ok := d["nameserver-policy"].(map[string]any); ok {
			for k := range np {
				if strings.HasPrefix(k, "rule-set:") || strings.HasPrefix(k, "geosite:") {
					delete(np, k)
				}
			}
			if len(np) == 0 {
				delete(d, "nameserver-policy")
			}
		}
	}

	cfg["mode"] = "rule"
	outbound, err := applyOutboundPlan(cfg, opts)
	if err != nil {
		return "", err
	}
	cfg["rules"] = []any{"MATCH," + outbound}
	cfg["log-level"] = "warning"

	out, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("生成 mihomo 配置失败: %w", err)
	}
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return "", fmt.Errorf("创建 mihomo 数据目录失败: %w", err)
	}
	if err := os.WriteFile(m.configPath, out, 0o600); err != nil {
		return "", fmt.Errorf("写 mihomo 配置失败: %w", err)
	}
	return m.configPath, nil
}

// applyOutboundPlan 按 StartOptions 决定 MATCH 出口，必要时注入 POJUN-AUTO 组。
func applyOutboundPlan(cfg map[string]any, opts StartOptions) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	switch mode {
	case "", "group":
		return defaultOutboundName(cfg, opts.Preferred), nil
	case "node":
		name := strings.TrimSpace(opts.Preferred)
		if name == "" {
			return "", fmt.Errorf("指定节点模式缺少节点名")
		}
		if !proxyNameSet(cfg)[name] {
			return "", fmt.Errorf("订阅里没有节点 %q（可能已改名，重新拉取订阅）", name)
		}
		return name, nil
	case "load-balance", "url-test", "fallback":
		valid := make([]string, 0, len(opts.Nodes))
		known := proxyNameSet(cfg)
		for _, n := range opts.Nodes {
			n = strings.TrimSpace(n)
			if n != "" && known[n] {
				valid = append(valid, n)
			}
		}
		if len(valid) == 0 {
			return "", fmt.Errorf("所选模式需要至少一个订阅节点（勾选后重试）")
		}
		g := map[string]any{"name": autoGroupName, "type": mode}
		if mode == "load-balance" {
			// 显式 round-robin：默认 consistent-hashing 会把同一目标固定到同一节点，
			// 用户要的「轮询」是每个请求换出口。
			g["strategy"] = "round-robin"
		} else {
			g["url"] = "https://www.gstatic.com/generate_204"
			g["interval"] = 300
		}
		anyNodes := make([]any, len(valid))
		for i, n := range valid {
			anyNodes[i] = n
		}
		g["proxies"] = anyNodes
		groups := make([]any, 0)
		if old, ok := cfg["proxy-groups"].([]any); ok {
			for _, item := range old {
				if m, ok := item.(map[string]any); ok {
					if name, _ := m["name"].(string); name == autoGroupName {
						continue // 覆盖旧的自建组
					}
				}
				groups = append(groups, item)
			}
		}
		cfg["proxy-groups"] = append(groups, g)
		return autoGroupName, nil
	default:
		return "", fmt.Errorf("未知出口模式 %q（可选 group/node/load-balance/url-test/fallback）", opts.Mode)
	}
}

// RestartFromConfig restarts the kernel from the persisted config file using the
// previously active outbound plan. Used by the proxy health check to recover a
// dead mihomo process (task 21 实测：mihomo 01:04 退出后无人拉起，录制代理整条
// 出口失效 6 小时）。
func (m *Manager) RestartFromConfig(ctx context.Context, port int) (Status, error) {
	if m == nil {
		return Status{}, fmt.Errorf("mihomo 管理器未初始化")
	}
	if st := m.Status(); st.Running {
		return st, nil
	}
	raw, err := os.ReadFile(m.configPath)
	if err != nil {
		return m.Status(), fmt.Errorf("读取 mihomo 配置失败: %w", err)
	}
	outbound, mode, nodes := readActivePlan(m.configPath)
	if port <= 0 {
		port = m.Status().Port
	}
	if port <= 0 {
		port = 1679
	}
	return m.Start(ctx, string(raw), "", port, StartOptions{Preferred: outbound, Mode: mode, Nodes: nodes})
}

// readActivePlan 从已写入的配置文件反推实际出口：rules 的第一条 MATCH,<名字>。
// 若名字是自建组 POJUN-AUTO，再取该组的 type 与 proxies 作为模式/节点。
func readActivePlan(configPath string) (outbound, mode string, nodes []string) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return "", "", nil
	}
	var cfg map[string]any
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return "", "", nil
	}
	rules, _ := cfg["rules"].([]any)
	if len(rules) == 0 {
		return "", "", nil
	}
	rule, _ := rules[0].(string)
	if !strings.HasPrefix(rule, "MATCH,") {
		return "", "", nil
	}
	outbound = strings.TrimSpace(strings.TrimPrefix(rule, "MATCH,"))
	proxySet := proxyNameSet(cfg)
	groups, _ := cfg["proxy-groups"].([]any)
	inGroup := false
	for _, g := range groups {
		if m, ok := g.(map[string]any); ok {
			if n, _ := m["name"].(string); n == outbound {
				inGroup = true
				if t, _ := m["type"].(string); t != "" {
					mode = "group"
					if t == "load-balance" || t == "url-test" || t == "fallback" {
						mode = t
					}
				}
				if ps, ok := m["proxies"].([]any); ok {
					for _, x := range ps {
						if n, ok := x.(string); ok && proxySet[n] && !isDisplayNoiseName(n) {
							nodes = append(nodes, n)
						}
					}
				}
			}
		}
	}
	if !inGroup {
		// 直接 MATCH 到一个节点。
		mode = "node"
		nodes = []string{outbound}
	}
	return outbound, mode, nodes
}

// isDisplayNoiseName 过滤订阅里夹带的「伪节点」（官网/剩余流量/到期）——它们
// 不是可用出口，只在状态页展示时排除。
func isDisplayNoiseName(name string) bool {
	for _, kw := range []string{"官网", "剩余流量", "到期时间", "下次重置", "订阅地址"} {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

// proxyNameSet 返回订阅 proxies 里的名字集合（只认 map 条目）。
func proxyNameSet(cfg map[string]any) map[string]bool {
	set := map[string]bool{}
	if proxies, ok := cfg["proxies"].([]any); ok {
		for _, p := range proxies {
			if m, ok := p.(map[string]any); ok {
				if name, _ := m["name"].(string); strings.TrimSpace(name) != "" {
					set[name] = true
				}
			}
		}
	}
	return set
}

// defaultOutboundName 选 MATCH 的出口：优先第一个 proxy-group，其次第一个 proxy，
// 都没有就 DIRECT（mihomo 仍能启动，只是没有可代理节点）。
func defaultOutboundName(cfg map[string]any, preferred string) string {
	preferred = strings.TrimSpace(preferred)
	if preferred != "" {
		// 用户选择的出口组/节点：存在才用（订阅换版后名字可能变，静默回落默认）。
		if groups, ok := cfg["proxy-groups"].([]any); ok {
			for _, g := range groups {
				if m, ok := g.(map[string]any); ok {
					if name, _ := m["name"].(string); name == preferred {
						return preferred
					}
				}
			}
		}
		if proxies, ok := cfg["proxies"].([]any); ok {
			for _, p := range proxies {
				if m, ok := p.(map[string]any); ok {
					if name, _ := m["name"].(string); name == preferred {
						return preferred
					}
				}
			}
		}
	}
	if groups, ok := cfg["proxy-groups"].([]any); ok {
		for _, g := range groups {
			if m, ok := g.(map[string]any); ok {
				if name, ok := m["name"].(string); ok && strings.TrimSpace(name) != "" {
					return name
				}
			}
		}
	}
	if proxies, ok := cfg["proxies"].([]any); ok {
		for _, p := range proxies {
			if m, ok := p.(map[string]any); ok {
				if name, ok := m["name"].(string); ok && strings.TrimSpace(name) != "" {
					return name
				}
			}
		}
	}
	return "DIRECT"
}

// Install 从 GitHub Releases 下载当前平台对应的 mihomo 二进制。
// 先尝试校验 .sha256；校验文件不可用时仍然安装，但在返回的错误里不静默——
// 调用方会把 SourceURL/SHA256 一起回显给用户。
func (m *Manager) Install(ctx context.Context, proxyURL string, mirrors []string) (InstallResult, error) {
	client, err := installClient(proxyURL)
	if err != nil {
		return InstallResult{}, err
	}
	if err := m.ensureWritable(); err != nil {
		return InstallResult{}, err
	}
	api := "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
	apiCtx, cancelAPI := context.WithTimeout(ctx, installAPITimeout)
	defer cancelAPI()
	req, _ := http.NewRequestWithContext(apiCtx, http.MethodGet, api, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "pojun-mihomo-installer")
	resp, err := client.Do(req)
	if err != nil {
		return InstallResult{}, fmt.Errorf("查询 mihomo 最新版本失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return InstallResult{}, fmt.Errorf("查询 mihomo 最新版本返回 %d", resp.StatusCode)
	}
	var rel struct {
		TagName string         `json:"tag_name"`
		Assets  []releaseAsset `json:"assets"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return InstallResult{}, fmt.Errorf("解析 mihomo release 失败: %w", err)
	}
	asset := pickAsset(rel.Assets)
	if asset.URL == "" {
		return InstallResult{}, fmt.Errorf("release %s 里没有适配 %s/%s 的 mihomo 包", rel.TagName, runtime.GOOS, runtime.GOARCH)
	}
	if asset.Size > downloadLimit {
		return InstallResult{}, fmt.Errorf("mihomo 包异常大（%d 字节）", asset.Size)
	}
	// GitHub API 的 asset.digest 是压缩包 SHA-256；有它就能安全地走第三方加速镜像
	// （镜像只搬运字节，哈希对不上直接换下一个源）。API 没给时退回 .sha256 资产。
	wantSHA := ""
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(asset.Digest)), "sha256:") {
		wantSHA = strings.ToLower(strings.TrimSpace(asset.Digest))[len("sha256:"):]
	}
	if wantSHA == "" {
		sumCtx, cancelSum := context.WithTimeout(ctx, installAPITimeout)
		rawSum, sumErr := downloadText(sumCtx, client, asset.URL+".sha256", 4096)
		cancelSum()
		if sumErr == nil {
			if fields := strings.Fields(rawSum); len(fields) > 0 {
				wantSHA = strings.ToLower(fields[0])
			}
		}
	}

	dlCtx, cancelDL := context.WithTimeout(ctx, installOverallBudget)
	defer cancelDL()
	// 加速：镜像优先、官方兜底。只有拿到官方哈希时才用镜像（镜像只搬字节，
	// 哈希不对就换源）。官方 CDN 在国内常被限速/黑洞，先试镜像能把安装从
	// 十几分钟降到几十秒；镜像全挂再回官方。
	sources := []string{}
	if wantSHA != "" {
		for _, prefix := range mirrors {
			if u := applyMirrorPrefix(prefix, asset.URL); u != "" {
				sources = append(sources, u)
			}
		}
	}
	sources = append(sources, asset.URL)
	// 并发测速，最快的源排第一：镜像间速度差可达 100 倍，顺序尝试会卡在慢源上。
	if best := pickFastestSource(dlCtx, client, sources); best != "" {
		reordered := []string{best}
		for _, u := range sources {
			if u != best {
				reordered = append(reordered, u)
			}
		}
		sources = reordered
	}
	dlFile := filepath.Join(m.dir, "mihomo.download")
	var data []byte
	var sourceURL string
	var lastErr error
	for _, src := range sources {
		_ = os.Remove(dlFile) // 换源必须从头下，避免把两个源的字节拼接
		d, err := downloadResumable(dlCtx, client, src, dlFile)
		if err != nil {
			lastErr = err
			continue
		}
		if asset.Size > 0 && int64(len(d)) != asset.Size {
			lastErr = fmt.Errorf("%s 下载大小不符：%d 字节，release 标注 %d 字节", src, len(d), asset.Size)
			continue
		}
		if wantSHA != "" {
			sum := sha256.Sum256(d)
			if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, wantSHA) {
				lastErr = fmt.Errorf("%s 校验失败：期望 %s，实际 %s", src, wantSHA, got)
				continue
			}
		}
		data, sourceURL = d, src
		break
	}
	if data == nil {
		if lastErr == nil {
			lastErr = errors.New("所有下载源均失败")
		}
		return InstallResult{}, fmt.Errorf("%w；可配置镜像加速（设置项 proxypool_mihomo_mirrors）或用「从服务器文件安装」", lastErr)
	}
	checksumVerified := wantSHA != ""

	payload, err := payloadFromArchive(asset.Name, data)
	if err != nil {
		return InstallResult{}, err
	}
	res, err := m.saveInstalledBinary(payload, rel.TagName, sourceURL, "", checksumVerified)
	if err != nil {
		return InstallResult{}, err
	}
	_ = os.Remove(dlFile)
	return res, nil
}

// applyMirrorPrefix 把 GitHub 资产 URL 套到镜像前缀上。支持两种写法：
//   - 前缀直接拼接：https://ghproxy.net/https://github.com/...
//   - 占位符：https://mirror.example/fetch?url={url}
func applyMirrorPrefix(prefix, raw string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return ""
	}
	if strings.Contains(prefix, "{url}") {
		return strings.ReplaceAll(prefix, "{url}", raw)
	}
	return strings.TrimRight(prefix, "/") + "/" + raw
}

// ParseMirrors 解析设置项里的镜像前缀（逗号/换行/空格分隔）。
func ParseMirrors(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func pickAsset(assets []releaseAsset) (out releaseAsset) {
	osName := runtime.GOOS
	arch := runtime.GOARCH
	// mihomo 的命名：mihomo-windows-amd64-v1.19.0.zip / mihomo-linux-amd64-v1.19.0.gz
	// 同一个版本还有 -v1/-v2/-v3、-go120、-compatible 等变体；优先选无后缀的
	// 通用包，其次才是 compatible/特定 Go 版本。
	want := fmt.Sprintf("mihomo-%s-%s-", osName, arch)
	generic := regexp.MustCompile(`^mihomo-` + regexp.QuoteMeta(osName) + `-` + regexp.QuoteMeta(arch) + `-v\d+\.\d+\.\d+\.(zip|gz)$`)
	bestScore := -1
	for _, a := range assets {
		name := strings.ToLower(a.Name)
		if !strings.HasPrefix(name, want) {
			continue
		}
		if !strings.HasSuffix(name, ".zip") && !strings.HasSuffix(name, ".gz") {
			continue
		}
		score := 50
		switch {
		case generic.MatchString(name):
			score = 100
		case strings.Contains(name, "compatible"):
			score = 10
		case strings.Contains(name, "-go1"):
			score = 30
		case strings.Contains(name, "-v1-"), strings.Contains(name, "-v2-"), strings.Contains(name, "-v3-"):
			score = 40
		}
		if score > bestScore {
			bestScore = score
			out = a
		}
	}
	return out
}

func downloadText(ctx context.Context, client *http.Client, url string, max int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func unzipBinary(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("解压 mihomo zip 失败: %w", err)
	}
	for _, f := range zr.File {
		base := strings.ToLower(filepath.Base(f.Name))
		// 官方 Windows 包内文件名是 mihomo-windows-amd64.exe；不要只认 mihomo.exe。
		if !strings.HasPrefix(base, "mihomo") || (!strings.HasSuffix(base, ".exe") && base != "mihomo") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, downloadLimit))
	}
	return nil, fmt.Errorf("mihomo zip 里没有 mihomo 可执行文件")
}

func gunzip(data []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("解压 mihomo gz 失败: %w", err)
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, downloadLimit))
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func portFree(port int) bool {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

func portOpen(host string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)), timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func probeViaHTTPProxy(ctx context.Context, proxy string) error {
	c, err := proxyprobe.ClientFor(proxy, 8*time.Second)
	if err != nil {
		return err
	}
	for _, target := range []string{
		"https://api.ipify.org?format=json",
		"http://www.gstatic.com/generate_204",
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			continue
		}
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 400 {
			return nil
		}
	}
	return fmt.Errorf("经 mixed-port 请求验活目标失败")
}

func detectVersion(binary string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary, "-v").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func tail(path string, max int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	start := st.Size() - int64(max)
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(f, int64(max)))
	// 日志可能含节点地址；只回最后一段，且由调用方决定是否展示。
	return strings.TrimSpace(string(b))
}

// Controller 返回本次运行的外部控制器地址与 secret（只在本进程生命周期有效）。
func (m *Manager) Controller() (addr, secret string, ok bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	running := m.cmd != nil && m.cmd.Process != nil
	if !running || m.ctrlAddr == "" || m.ctrlSecret == "" {
		return "", "", false
	}
	return m.ctrlAddr, m.ctrlSecret, true
}

func randomSecret() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(buf)
}

// DelayResult 是单个节点的延迟测试结果（错误时 DelayMS=0）。
type DelayResult struct {
	Name    string `json:"name"`
	DelayMS int64  `json:"delay_ms"`
	Error   string `json:"error,omitempty"`
}

// 节点测速上限：单次最多 MaxDelayNodes 个节点，最多 DelayConcurrency 个并发。
const (
	DelayConcurrency = 8
	MaxDelayNodes    = 500
)

// NormalizeDelayTimeout 把单节点测速超时收敛到 (0,15s]，缺省 5s。
func NormalizeDelayTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 || timeout > 15*time.Second {
		return 5 * time.Second
	}
	return timeout
}

// newControllerClient 构造只走回环、绕过环境代理的控制器 HTTP 客户端。
// 用完必须 CloseIdleConnections：零值 Transport 的 IdleConnTimeout 是 0（永不回收），
// 每次调用新建的 client 会让空闲连接一直占着 fd。
func newControllerClient(timeout time.Duration) *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: timeout}
}

// unknownNames 返回 requested 里不在 running 中的名字个数。
func unknownNames(requested, running []string) int {
	known := make(map[string]bool, len(running))
	for _, n := range running {
		known[n] = true
	}
	missing := 0
	for _, n := range requested {
		if !known[n] {
			missing++
		}
	}
	return missing
}

// Delay 通过 mihomo 的 /proxies/{name}/delay 对节点做真实延迟测试。
// names 为空时测全部「真实节点」；target 为空用 gstatic 204；并发 8。
func (m *Manager) Delay(ctx context.Context, names []string, target string, timeout time.Duration) ([]DelayResult, error) {
	addr, secret, ok := m.Controller()
	if !ok {
		return nil, fmt.Errorf("mihomo 未运行或控制器不可用：先启动内核再测速")
	}
	if strings.TrimSpace(target) == "" {
		target = "https://www.gstatic.com/generate_204"
	}
	timeout = NormalizeDelayTimeout(timeout)
	// 先取一次运行中内核的节点表：既用于 names 为空时枚举，也用于发现「订阅换了、
	// 内核还是旧配置」——否则每个节点都会 404 成「超时」，用户看到满屏假超时。
	running, err := m.proxyNames(addr, secret)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		names = running
	} else if unknownNames(names, running) == len(names) {
		return nil, fmt.Errorf("运行中的内核配置里没有这些节点：订阅更新后请先「启动并应用策略」再测速")
	}
	if len(names) > MaxDelayNodes {
		return nil, fmt.Errorf("一次最多测速 %d 个节点（当前 %d），请缩小范围", MaxDelayNodes, len(names))
	}
	known := make(map[string]bool, len(running))
	for _, n := range running {
		known[n] = true
	}
	client := newControllerClient(timeout + 3*time.Second)
	defer client.CloseIdleConnections()
	results := make([]DelayResult, len(names))
	var wg sync.WaitGroup
	sem := make(chan struct{}, DelayConcurrency)
	for i, name := range names {
		if !known[name] {
			// 订阅新增/改名的节点：直接给出原因，别发一次注定 404 的请求（会被当成超时）。
			results[i] = DelayResult{Name: name, Error: "节点不在当前内核配置中（订阅已更新？）"}
			continue
		}
		// 先占坑再起 goroutine：并发上限同时约束 goroutine 数量。
		sem <- struct{}{}
		wg.Add(1)
		go func(idx int, node string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[idx] = delayOne(ctx, client, addr, secret, node, target, timeout)
		}(i, name)
	}
	wg.Wait()
	return results, nil
}

// proxyNames 读取 mihomo /proxies，过滤掉组/内置策略/伪节点，返回真实节点名。
func (m *Manager) proxyNames(addr, secret string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+addr+"/proxies", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	client := newControllerClient(5 * time.Second)
	defer client.CloseIdleConnections()
	var resp *http.Response
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		// 刚启动时控制器可能比 mixed-port 晚几十毫秒就绪。
		if attempt < 2 {
			time.Sleep(200 * time.Millisecond)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("读取 mihomo 节点列表失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("读取 mihomo 节点列表失败: HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Proxies map[string]struct {
			Type string `json:"type"`
		} `json:"proxies"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("解析 mihomo 节点列表失败: %w", err)
	}
	skipTypes := map[string]bool{
		"selector": true, "urltest": true, "fallback": true, "loadbalance": true,
		"direct": true, "reject": true, "rejectdrop": true, "pass": true, "compatible": true,
	}
	out := make([]string, 0, len(payload.Proxies))
	for name, p := range payload.Proxies {
		t := strings.ToLower(strings.ReplaceAll(p.Type, "-", ""))
		if skipTypes[t] || isDisplayNoiseName(name) {
			continue
		}
		out = append(out, name)
	}
	return out, nil
}

func delayOne(ctx context.Context, client *http.Client, addr, secret, name, target string, timeout time.Duration) DelayResult {
	res := DelayResult{Name: name}
	u := "http://" + addr + "/proxies/" + url.PathEscape(name) + "/delay?timeout=" +
		strconv.FormatInt(timeout.Milliseconds(), 10) + "&url=" + url.QueryEscape(target)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := client.Do(req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		// mihomo 用 {"message":"..."} 描述失败原因。
		var m struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(body, &m)
		res.Error = strings.TrimSpace(m.Message)
		if res.Error == "" {
			res.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return res
	}
	var payload struct {
		Delay int64 `json:"delay"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		res.Error = "解析延迟结果失败"
		return res
	}
	res.DelayMS = payload.Delay
	return res
}
