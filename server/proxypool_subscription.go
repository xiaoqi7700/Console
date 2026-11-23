package server

// 代理订阅拉取：从机场订阅地址抓取节点列表。
//
// 现实里的机场订阅有两类返回：
//  1. URI 列表：http:// / https:// / socks5:// / vmess:// / ss:// ...
//  2. Clash / mihomo YAML：proxies + proxy-groups + rules + mixed-port。
//
// 旧实现只认第 1 类，碰到第 2 类会解析出 0 个节点（用户看到的“导不进去”）。
// 这里同时支持两类：
//   - YAML 里 type=http/https/socks5 的节点可直接作为本项目上游；
//   - vmess/ss/trojan/vless 等节点交给 mihomo 内核（由 /api/proxypool/mihomo/start
//     启动后用 mixed-port 接入代理池）；
//   - YAML 自带的 mixed-port/port/socks-port 作为“本机 Clash 端口”候选返回。
//
// 安全：订阅地址由管理员显式填写，但仍做 SSRF 防护——拒绝回环/私网/链路本地地址，
// 避免把平台当成内网探测跳板。

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/traffic"
	"gopkg.in/yaml.v3"
)

type subscriptionFetchResult struct {
	Format string `json:"format"` // clash / uri
	// Supported 永远是非 nil 数组：nil 会被编码成 null，前端 .length 直接崩
	//（2026-11-13 实测：全 vmess 的 Clash 订阅 → supported:null → 页面渲染异常）。
	Supported   []string `json:"supported"`
	Text        string   `json:"text"`
	Unsupported int      `json:"unsupported"`
	Invalid     int      `json:"invalid"`
	// Ignored 是订阅里混入的「非节点信息」条数：剩余流量/到期时间/官网地址等。
	// 这些不是代理，单独计数，不再计入 invalid（旧版会把它们报成无效节点）。
	Ignored int    `json:"ignored"`
	Note    string `json:"note,omitempty"`

	// Clash YAML 专有字段。ClashYAML 只回给已鉴权的管理端；它是完整配置，
	// 内含节点凭据，不写日志、不落诊断包。
	ClashYAML string `json:"clash_yaml,omitempty"`
	Proxies   int    `json:"proxies,omitempty"`
	// DirectNodes 0 是有意义的值（全部节点都需要内核），不能 omitempty，否则前端
	// 回退到 supported.length 时会踩到 null。
	DirectNodes int   `json:"direct_nodes"`
	LocalPorts  []int `json:"local_ports,omitempty"`
	ProxyGroups int   `json:"proxy_groups,omitempty"`
	// GroupNames 是 Clash proxy-groups 的名字，供前端选「MATCH 到哪个出口组」。
	GroupNames     []string `json:"group_names,omitempty"`
	ProxyProviders int      `json:"proxy_providers,omitempty"`
	// Nodes/Groups 供「Clash 节点管理」二级页面使用：只回名字与类型，
	// 不回 server/密码等节点凭据。
	Nodes  []subNodeInfo  `json:"nodes,omitempty"`
	Groups []subGroupInfo `json:"groups,omitempty"`
}

type subNodeInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type subGroupInfo struct {
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	Members []string `json:"members,omitempty"`
}

type clashProxy struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Server   string `yaml:"server"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	TLS      bool   `yaml:"tls"`
}

type clashConfig struct {
	MixedPort          int              `yaml:"mixed-port"`
	Port               int              `yaml:"port"`
	SocksPort          int              `yaml:"socks-port"`
	RedirPort          int              `yaml:"redir-port"`
	TProxyPort         int              `yaml:"tproxy-port"`
	ExternalController string           `yaml:"external-controller"`
	Secret             string           `yaml:"secret"`
	AllowLan           bool             `yaml:"allow-lan"`
	Proxies            []clashProxy     `yaml:"proxies"`
	ProxyGroups        []map[string]any `yaml:"proxy-groups"`
	ProxyProviders     map[string]any   `yaml:"proxy-providers"`
	Rules              []string         `yaml:"rules"`
}

// isBlockedIP 是 SSRF 的统一判定：回环 / 私网 / 链路本地 / 未指定 / 组播都拒绝。
func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

func privateHost(host string) bool {
	if host == "" {
		return true
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return false // 解析失败交给请求阶段报错
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return true
		}
	}
	return false
}

// envProxyAddr 返回环境里配置的 HTTP(S)/ALL 代理地址（host:port），没有则空。
// 订阅抓取走系统代理时，DialContext 的目标是代理而非订阅站，需要放行。
func envProxyAddr() string {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"} {
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			continue
		}
		host := u.Host
		if u.Port() == "" {
			port := "80"
			if u.Scheme == "https" {
				port = "443"
			}
			host = net.JoinHostPort(u.Hostname(), port)
		}
		return host
	}
	return ""
}

// ssrfSafeDialContext 在真正建连时重新解析并只拨公网 IP。
//
// 只做「请求前 LookupIP + 请求时用域名」会留下 DNS rebinding 窗口：校验时解析到公网，
// 建连时再解析到 127.0.0.1。这里把解析结果钉死在 dial 阶段，跳过任何被屏蔽的地址。
func ssrfSafeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	// 显式配置了出口代理时，连接目标是代理本身（常见 127.0.0.1:7897），
	// 不能被 SSRF 规则拦掉——代理是运维自己配置的可信出口。
	if p := envProxyAddr(); p != "" && strings.EqualFold(p, addr) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{}
	var lastErr error
	tried := false
	for _, ip := range ips {
		if isBlockedIP(ip.IP) {
			continue
		}
		tried = true
		conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if derr == nil {
			return conn, nil
		}
		lastErr = derr
	}
	if !tried {
		return nil, fmt.Errorf("订阅地址只解析到回环/私网/保留地址，已拒绝（防止 SSRF）")
	}
	return nil, lastErr
}

// decodeSubscriptionBase64 只在「文本里没有 scheme、也没有 YAML 结构」时尝试，
// 避免把一段普通文本误判成 base64。
func decodeSubscriptionBase64(raw string) string {
	if strings.Contains(raw, "://") || strings.Contains(raw, "proxies:") ||
		strings.Contains(raw, "proxy-groups:") || strings.Contains(raw, "mixed-port:") {
		return raw
	}
	// 机场订阅的 base64 有标准/无填充/URL-safe 多种写法（URL-safe 常见于缺省 token 的机场），
	// 只试 Standard 会解不开、最后按原始文本解析出 0 个节点。
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		dec, err := enc.DecodeString(raw)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(dec))
		if strings.Contains(s, "://") || strings.Contains(s, "proxies:") || strings.Contains(s, "mixed-port:") {
			return s
		}
	}
	return raw
}

// 订阅里常混入「剩余流量/到期时间/官网」等信息行或伪节点：它们不是代理。
// 判断必须保守——真实节点名里也可能带「流量」二字，所以对 Clash 节点名只认可
// 出现在开头的明确信息词；URI 列表里不含 "://" 的行则允许更宽的关键词。
var infoLineRE = regexp.MustCompile(`(?i)(剩余流量|剩余|距下次|下次重置|到期|过期|有效期|套餐|官网|订阅|重置|流量|已用|总量|traffic|expire|expiry|reset|website|official|\d+(\.\d+)?\s*(GB|TB|MB)|20\d{2}[-/年]\d{1,2})`)

var infoNodeNameRE = regexp.MustCompile(`(?i)^\s*(剩余|到期|过期|有效期|套餐|官网|订阅|重置|流量\s*[:：]|traffic|expire|expiry|reset|website|official)`)

// isSubscriptionInfoLine 判断 URI 列表里的一行是否「信息行」而不是节点。
func isSubscriptionInfoLine(line string) bool {
	return infoLineRE.MatchString(strings.TrimSpace(line))
}

// isInfoNodeName 判断 Clash proxies 里的名字是否是订阅附带的伪节点。
func isInfoNodeName(name string) bool {
	name = strings.TrimSpace(name)
	if infoNodeNameRE.MatchString(name) {
		return true
	}
	// 名字前可能带 emoji/装饰符号（如「🌐︎ 官网: ...」），开头锚点匹配不到；
	// 这些词在真实节点名里几乎不会出现，用包含判定兜底。
	for _, kw := range []string{"官网", "剩余流量", "到期时间", "下次重置", "订阅地址"} {
		if strings.Contains(name, kw) {
			return true
		}
	}
	return false
}

// parseClashSubscription 识别并解析 Clash / mihomo YAML。
// ok=false 表示这段文本不是 Clash 配置（交给 URI 列表解析器）。
func parseClashSubscription(body string) (subscriptionFetchResult, bool) {
	raw := strings.TrimSpace(body)
	var cfg clashConfig
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		return subscriptionFetchResult{}, false
	}
	// 只有出现 Clash 的结构化键才算 YAML 订阅；普通 YAML（比如 k8s 配置）
	// 不能被误当成代理。
	if len(cfg.Proxies) == 0 && len(cfg.ProxyGroups) == 0 && len(cfg.ProxyProviders) == 0 &&
		cfg.MixedPort == 0 && cfg.Port == 0 && cfg.SocksPort == 0 {
		return subscriptionFetchResult{}, false
	}

	res := subscriptionFetchResult{
		Format:         "clash",
		Supported:      []string{},
		ClashYAML:      raw,
		Proxies:        len(cfg.Proxies),
		ProxyGroups:    len(cfg.ProxyGroups),
		ProxyProviders: len(cfg.ProxyProviders),
	}
	for _, g := range cfg.ProxyGroups {
		name, _ := g["name"].(string)
		if strings.TrimSpace(name) == "" {
			continue
		}
		res.GroupNames = append(res.GroupNames, name)
		gi := subGroupInfo{Name: name, Type: strings.TrimSpace(fmt.Sprint(g["type"]))}
		if members, ok := g["proxies"].([]any); ok {
			for _, m := range members {
				if s, ok := m.(string); ok && strings.TrimSpace(s) != "" {
					gi.Members = append(gi.Members, s)
				}
			}
		}
		res.Groups = append(res.Groups, gi)
	}
	seenPort := map[int]bool{}
	addPort := func(p int) {
		if p > 0 && !seenPort[p] {
			seenPort[p] = true
			res.LocalPorts = append(res.LocalPorts, p)
		}
	}
	addPort(cfg.MixedPort)
	addPort(cfg.Port)
	addPort(cfg.SocksPort)
	addPort(cfg.RedirPort)
	addPort(cfg.TProxyPort)

	for _, p := range cfg.Proxies {
		if isInfoNodeName(p.Name) {
			res.Ignored++
			continue
		}
		res.Nodes = append(res.Nodes, subNodeInfo{Name: p.Name, Type: strings.ToLower(strings.TrimSpace(p.Type))})
		typ := strings.ToLower(strings.TrimSpace(p.Type))
		scheme := ""
		switch typ {
		case "http":
			scheme = "http"
			if p.TLS {
				scheme = "https"
			}
		case "https":
			scheme = "https"
		case "socks5", "socks":
			scheme = "socks5"
		default:
			res.Unsupported++
			continue
		}
		if strings.TrimSpace(p.Server) == "" || p.Port <= 0 || p.Port > 65535 {
			res.Invalid++
			continue
		}
		u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(p.Server, strconv.Itoa(p.Port))}
		if p.Username != "" || p.Password != "" {
			u.User = url.UserPassword(p.Username, p.Password)
		}
		norm, err := traffic.ValidateProxyURL(u.String())
		if err != nil {
			res.Invalid++
			continue
		}
		res.Supported = append(res.Supported, norm.String())
	}
	res.DirectNodes = len(res.Supported)
	res.Text = strings.Join(res.Supported, "\n")

	// 组成员里可能有「组引用」「伪节点」：节点管理页展示时只保留真实节点。
	real := make(map[string]bool, len(res.Nodes))
	for _, n := range res.Nodes {
		real[n.Name] = true
	}
	for i := range res.Groups {
		kept := res.Groups[i].Members[:0]
		for _, m := range res.Groups[i].Members {
			if real[m] {
				kept = append(kept, m)
			}
		}
		res.Groups[i].Members = kept
	}

	var notes []string
	if cfg.MixedPort > 0 {
		notes = append(notes, fmt.Sprintf("配置自带 mixed-port=%d，可直接作为本机 Clash 端口使用", cfg.MixedPort))
	}
	if res.Ignored > 0 {
		notes = append(notes, fmt.Sprintf("已忽略 %d 条非节点信息（剩余流量/到期时间/官网等）", res.Ignored))
	}
	if res.Unsupported > 0 {
		notes = append(notes, fmt.Sprintf("有 %d 个 vmess/ss/trojan/vless 等节点，需要 mihomo 内核启动后才能使用", res.Unsupported))
	}
	if res.ProxyProviders > 0 {
		notes = append(notes, fmt.Sprintf("配置含 %d 个 proxy-providers，节点由 mihomo 运行时拉取", res.ProxyProviders))
	}
	if res.Proxies == 0 && res.ProxyProviders == 0 {
		notes = append(notes, "Clash 配置里没有 proxies / proxy-providers：订阅可能已过期、需要特定 UA，或返回的是模板；请检查订阅状态")
	}
	if res.DirectNodes == 0 && res.Unsupported > 0 {
		notes = append(notes, "本订阅没有可直接作为 HTTP/SOCKS5 上游的节点；请用「mihomo 启动」或「检测本机 Clash」")
	}
	res.Note = strings.Join(notes, "；")
	return res, true
}

func parseSubscriptionText(body string) subscriptionFetchResult {
	raw := strings.TrimSpace(decodeSubscriptionBase64(strings.TrimSpace(body)))
	if res, ok := parseClashSubscription(raw); ok {
		return res
	}

	res := subscriptionFetchResult{Format: "uri", Supported: []string{}}
	for _, ln := range strings.Split(raw, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		low := strings.ToLower(ln)
		switch {
		case strings.HasPrefix(low, "vmess://"), strings.HasPrefix(low, "vless://"),
			strings.HasPrefix(low, "ss://"), strings.HasPrefix(low, "trojan://"),
			strings.HasPrefix(low, "hysteria"), strings.HasPrefix(low, "tuic://"),
			strings.HasPrefix(low, "wireguard://"):
			res.Unsupported++
		case strings.HasPrefix(low, "http://"), strings.HasPrefix(low, "https://"), strings.HasPrefix(low, "socks5://"), strings.HasPrefix(low, "socks5h://"):
			res.Supported = append(res.Supported, ln)
		case strings.HasPrefix(low, "socks://"):
			res.Supported = append(res.Supported, "socks5://"+ln[len("socks://"):])
		case isSubscriptionInfoLine(ln):
			// 「剩余流量：100GB」「到期时间：2026-12-01」「官网：…」等，不是节点。
			res.Ignored++
		default:
			// host:port 或 host:port:user:pass
			if strings.Count(ln, ":") >= 1 && !strings.ContainsAny(ln, " \t") {
				res.Supported = append(res.Supported, ln)
			} else {
				res.Invalid++
			}
		}
	}
	res.DirectNodes = len(res.Supported)
	res.Text = strings.Join(res.Supported, "\n")
	if res.Ignored > 0 {
		res.Note = fmt.Sprintf("已忽略 %d 条非节点信息（剩余流量/到期时间/官网等）。", res.Ignored)
	}
	if res.Unsupported > 0 {
		note := fmt.Sprintf("有 %d 个节点是 vmess/ss/trojan/vless 等协议，需要本地 mihomo 内核才能使用；可直接导入 http/https/socks5 节点，或用 mihomo 启动整份订阅。", res.Unsupported)
		if res.Note != "" {
			res.Note += " " + note
		} else {
			res.Note = note
		}
	}
	// 最常见的「导不进去」：订阅过期/需要特定 UA 时返回登录页或错误页（HTML），
	// 解析结果会是 0 节点且没有任何提示，用户只看到「没有可用节点」。
	lower := strings.ToLower(raw)
	switch {
	case strings.TrimSpace(raw) == "":
		res.Note = "订阅返回空内容：检查订阅是否过期、是否要求特定 UA，或地址是否被机场风控"
	case res.DirectNodes == 0 && res.Unsupported == 0 && (strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype html")):
		res.Note = "订阅返回的是网页而不是节点配置（常见于订阅过期、登录页或 UA 风控）；请检查订阅状态或更换 UA"
	}
	return res
}

// subscriptionUserAgents 是机场订阅的 UA 轮换表。
//
// 现场实测（2026-11-12，真实订阅）：同一个订阅 URL
//   - 浏览器 UA → HTTP 403（订阅站按 UA 风控）
//   - clash.meta → 200 + 完整 Clash YAML（29 proxies）
//   - mihomo/1.19.34 → 200 + 精简配置
//
// 旧实现写死浏览器 UA，所以「用户确认可用的订阅」在平台里导不进去。
// 按「返回节点最多」的顺序尝试；第一个 200 即采用。
var subscriptionUserAgents = []string{
	"clash.meta",
	"ClashMetaForAndroid/2.10.1",
	"mihomo/1.19.34",
	"ClashforWindows/0.20.39",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
}

// fetchSubscriptionBody 拉取订阅原文。所有调用方共用同一套 SSRF 规则：
// 首跳与每一跳重定向都拒绝回环/私网/链路本地地址。
//
// 按 subscriptionUserAgents 轮换 UA：订阅站常按 UA 返回 403 或不同格式的配置，
// 不能假设浏览器 UA 能拿到 Clash 节点。只有 200 才算成功；403/401 继续换 UA，
// 其他非 200 也换一次（有些站按 UA 返回不同状态码）。
func fetchSubscriptionBody(ctx context.Context, rawURL string) ([]byte, string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, "", fmt.Errorf("订阅地址必须是 http(s) 绝对地址")
	}
	if privateHost(u.Hostname()) {
		return nil, "", fmt.Errorf("订阅地址解析到回环/私网地址，已拒绝（防止 SSRF）")
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           ssrfSafeDialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("重定向次数过多")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("重定向到非 http(s) 地址")
			}
			if privateHost(req.URL.Hostname()) {
				return fmt.Errorf("重定向到回环/私网地址，已拒绝")
			}
			return nil
		},
	}

	var lastErr error
	for _, ua := range subscriptionUserAgents {
		hr, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, "", err
		}
		hr.Header.Set("User-Agent", ua)
		hr.Header.Set("Accept", "*/*")
		resp, err := client.Do(hr)
		if err != nil {
			lastErr = fmt.Errorf("拉取订阅失败（UA=%s）: %w", uaLabel(ua), err)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("订阅返回 %d（UA=%s；检查订阅是否过期、是否要求特定 UA，或被机场风控）",
				resp.StatusCode, uaLabel(ua))
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		contentType := resp.Header.Get("Content-Type")
		_ = resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("读取订阅失败（UA=%s）: %w", uaLabel(ua), err)
			continue
		}
		return body, contentType, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("订阅拉取失败：没有可用 UA")
	}
	return nil, "", lastErr
}

// uaLabel 只把 UA 的产品名放进错误（避免把完整 UA/订阅 URL 写进日志）。
func uaLabel(ua string) string {
	if i := strings.IndexByte(ua, '/'); i > 0 {
		return ua[:i]
	}
	if i := strings.IndexByte(ua, ' '); i > 0 {
		return ua[:i]
	}
	return ua
}

func (s *Server) proxyPoolSubscriptionFetch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL         string `json:"url"`
		IncludeYAML *bool  `json:"include_yaml"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	body, contentType, err := fetchSubscriptionBody(ctx, req.URL)
	if err != nil {
		writeErr(w, 502, err.Error())
		return
	}
	res := parseSubscriptionText(string(body))
	if res.Note == "" && strings.Contains(strings.ToLower(contentType), "yaml") && res.Format != "clash" {
		res.Note = "订阅返回 YAML，但未识别出 Clash 结构；已按 URI 列表解析"
	}
	if req.IncludeYAML != nil && !*req.IncludeYAML {
		res.ClashYAML = ""
	}
	writeJSON(w, 200, res)
}
