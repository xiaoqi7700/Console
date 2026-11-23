package db

// 存量自动范围审计（移植自上游 Pojun）：
// 按归属规则回放所有 source=auto 的范围行，给出「按新规则应当保留 / 应当清理」
// 的清单。只读，不删数据——删除必须备份后人工确认。供 a rtex-maint 维护工具调用。

import (
	"net"
	"strings"
)

var autoScopeInfra = []string{
	"min.io", "github.com", "githubusercontent.com", "githubassets.com",
	"cloudflare.com", "cdnjs.cloudflare.com", "jsdelivr.net", "unpkg.com",
	"googleapis.com", "gstatic.com", "google.com", "googletagmanager.com",
	"bootstrapcdn.com", "fontawesome.com", "jquery.com", "w3.org", "schema.org",
	"mozilla.org", "mozilla.net", "apache.org", "nginx.org", "openssl.org",
	"microsoft.com", "windows.net", "amazonaws.com", "cloudfront.net",
	"aliyuncs.com", "alicdn.com", "bdstatic.com", "qhimg.com", "gtimg.com",
	"byteimg.com", "volccdn.com", "tencent-cloud.com", "huaweicloud.com",
}

type scopeBaseline struct {
	domains    []string
	nets       []*net.IPNet
	hasCompany bool
}

// loadScopeBaseline 读取任务的「基线范围」：source 不是 auto 的行（人工/agent
// 显式登记的目标）。auto 行本身不参与，避免自动扩进来的资产自我合法化。
func (s *AssetStore) loadScopeBaseline(taskID int64) scopeBaseline {
	var b scopeBaseline
	rows, err := s.db.Query(`SELECT kind, COALESCE(domain,''), COALESCE(net::text,'') FROM task_scope
WHERE task_id=$1 AND (source <> 'auto' OR kind = 'company')`, taskID)
	if err != nil {
		return b
	}
	defer rows.Close()
	for rows.Next() {
		var kind, domain, netText string
		if err := rows.Scan(&kind, &domain, &netText); err != nil {
			continue
		}
		switch kind {
		case "company":
			b.hasCompany = true
		case "ip", "cidr":
			if _, n, err := net.ParseCIDR(netText); err == nil {
				b.nets = append(b.nets, n)
			}
		default:
			if domain != "" {
				b.domains = append(b.domains, domain)
			}
		}
	}
	return b
}

// allowsDomain：基线里没有任何域名类范围时放行（保持旧任务行为）；有基线时要求
// 同根域，或任务声明了 company 范围（公司资产归属由资产层判定，这里不误杀）。
func (b scopeBaseline) allowsDomain(host string) bool {
	if len(b.domains) == 0 {
		return true
	}
	root, _ := RootDomain(host)
	for _, d := range b.domains {
		if rd, _ := RootDomain(d); rd == root {
			return true
		}
	}
	return b.hasCompany
}

// allowsIP：基线里没有网段时放行；有网段时要求 IP 落在网段内。
func (b scopeBaseline) allowsIP(ipText string) bool {
	p := net.ParseIP(strings.TrimSpace(ipText))
	if p == nil || len(b.nets) == 0 {
		return true
	}
	for _, n := range b.nets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

// autoScopeAllowed 判断一个自动发现是否属于任务基线范围。
func (s *AssetStore) autoScopeAllowed(taskID int64, assetType, domain, rawURL, ipText string) bool {
	host := DomainKey(domain)
	if host == "" && rawURL != "" {
		host, _, _ = parseURL(normalizeURL(rawURL))
		host = DomainKey(host)
	}
	isIP := host != "" && net.ParseIP(host) != nil
	if assetType == "ip" || isIP {
		if isIP {
			ipText = host
		}
		if h := strings.TrimSpace(ipText); h != "" {
			return s.loadScopeBaseline(taskID).allowsIP(h)
		}
		// IP-only 的 service/endpoint（domain/url 都空）：无基线网段时按旧语义放行
		//（与 AddAutoScope 的 ipToHostCIDR 兜底一致），有网段则要求命中。
		return s.loadScopeBaseline(taskID).allowsIP(ipText)
	}
	if host == "" {
		// 域名/IP 都为空：有显式 IP 时仍走网段判定（service/endpoint 常见形态），
		// 否则拒绝（什么都不知道的资产不该进范围）。
		return s.loadScopeBaseline(taskID).allowsIP(ipText)
	}
	// 黑名单按可注册域匹配：play.min.io 命中 min.io。
	root, _ := RootDomain(host)
	for _, bad := range autoScopeInfra {
		if root == bad || strings.HasSuffix(root, "."+bad) || strings.HasSuffix(DomainKey(host), "."+bad) {
			return false
		}
	}
	return s.loadScopeBaseline(taskID).allowsDomain(host)
}

// AutoScopeAudit 是「存量自动范围审计」的一行结果（只读，不删数据）。
type AutoScopeAudit struct {
	TaskID  int64  `json:"task_id"`
	Kind    string `json:"kind"`
	Domain  string `json:"domain,omitempty"`
	Net     string `json:"net,omitempty"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"` // ok / infra-blacklist / outside-baseline / no-baseline
}

// AuditAutoScope 按 v0.9.14 的归属规则回放所有 source=auto 的范围行，给出
// 「按新规则应当保留 / 应当清理」的清单。只读；删除必须备份后人工确认。
func (s *AssetStore) AuditAutoScope() ([]AutoScopeAudit, error) {
	rows, err := s.db.Query(`SELECT task_id, kind, COALESCE(domain,''), COALESCE(net::text,'') FROM task_scope WHERE source='auto' ORDER BY task_id, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	baselines := map[int64]scopeBaseline{}
	out := make([]AutoScopeAudit, 0)
	for rows.Next() {
		var (
			item    AutoScopeAudit
			domain  string
			netText string
		)
		if err := rows.Scan(&item.TaskID, &item.Kind, &domain, &netText); err != nil {
			return nil, err
		}
		item.Domain = domain
		item.Net = netText
		b, ok := baselines[item.TaskID]
		if !ok {
			b = s.loadScopeBaseline(item.TaskID)
			baselines[item.TaskID] = b
		}
		noBaseline := len(b.domains) == 0 && len(b.nets) == 0 && !b.hasCompany
		if noBaseline {
			item.Allowed = true
			item.Reason = "no-baseline"
			out = append(out, item)
			continue
		}
		switch item.Kind {
		case "ip", "cidr", "company":
			host := netText
			if i := strings.IndexByte(host, '/'); i > 0 {
				host = host[:i]
			}
			if item.Kind == "company" || b.allowsIP(host) {
				item.Allowed = true
				item.Reason = "ok"
			} else {
				item.Reason = "outside-baseline"
			}
		default:
			root, _ := RootDomain(domain)
			bad := false
			for _, infra := range autoScopeInfra {
				if root == infra || strings.HasSuffix(root, "."+infra) {
					bad = true
					break
				}
			}
			if bad {
				item.Reason = "infra-blacklist"
			} else if b.allowsDomain(domain) {
				item.Allowed = true
				item.Reason = "ok"
			} else {
				item.Reason = "outside-baseline"
			}
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
