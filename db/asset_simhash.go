package db

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// 资产 URL 结构指纹（v0.4.94 经验层）：同 root_domain 下「同模式」的 endpoint
// 归为一簇，供变体分析意图族找同类端点。指纹是 64-bit simhash：
//   - 路径段归一（数字→N、长 hex→H、UUID→U——版本号/ID 差异不破坏相似性）
//   - 参数名集合（值不参与——同参数名即同语义入口）
//   - title 与 content_length 分桶（页面同构性弱信号）
//
// 归一策略来自 XBOW 资产分簇（SimHash）与 bbot 的 URL 类型化思想，实现自研。
// 明文偏好：只吃结构特征，不存内容。

var (
	simNumRE  = regexp.MustCompile(`^\d+$`)
	simHexRE  = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	simUUIDRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
)

// simFeatures 抽取 URL 的结构特征 token（加权语义：路径段 ×3、参数名 ×2、title ×1）。
func simFeatures(rawURL, title string, contentLength int64) map[string]int {
	feats := map[string]int{}
	add := func(tok string, w int) { feats[tok] += w }
	u, err := url.Parse(rawURL)
	if err != nil {
		return feats
	}
	add("scheme:"+u.Scheme, 1)
	add("host:"+u.Hostname(), 2)
	for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if seg == "" {
			continue
		}
		switch {
		case simUUIDRE.MatchString(seg):
			add("seg:U", 3)
		case simHexRE.MatchString(seg):
			add("seg:H", 3)
		case simNumRE.MatchString(seg):
			add("seg:N", 3)
		case strings.Contains(seg, "."):
			add("seg:file:"+strings.ToLower(filepathExt(seg)), 3)
		default:
			add("seg:"+strings.ToLower(seg), 3)
		}
	}
	q := u.Query()
	for k := range q {
		add("param:"+strings.ToLower(k), 2)
	}
	tt := strings.ToLower(strings.TrimSpace(title))
	if tt != "" {
		for _, w := range strings.Fields(tt) {
			if len(w) > 2 {
				add("title:"+w, 1)
			}
		}
	}
	switch {
	case contentLength <= 0:
		add("len:0", 1)
	case contentLength < 1024:
		add("len:S", 1)
	case contentLength < 10240:
		add("len:M", 1)
	default:
		add("len:L", 1)
	}
	return feats
}

func filepathExt(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return name
	}
	return name[i+1:]
}

// URLStructureSimhash 计算 64-bit simhash：每个特征 token 的哈希按符号加权累加，
// 最终按位取符号（>0 为 1）。
func URLStructureSimhash(rawURL, title string, contentLength int64) int64 {
	feats := simFeatures(rawURL, title, contentLength)
	if len(feats) == 0 {
		return 0
	}
	var v [64]int
	for tok, w := range feats {
		h := fnv64(tok)
		for bit := 0; bit < 64; bit++ {
			if h&(1<<uint(bit)) != 0 {
				v[bit] += w
			} else {
				v[bit] -= w
			}
		}
	}
	var out int64
	for bit := 0; bit < 64; bit++ {
		if v[bit] > 0 {
			out |= 1 << uint(bit)
		}
	}
	return out
}

// fnv64 是 FNV-1a 64bit（无依赖、分布足够用于 simhash 位折叠）。
func fnv64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// Hamming64 计算 64-bit 指纹的汉明距离。
func Hamming64(a, b int64) int {
	x := uint64(a ^ b)
	n := 0
	for x != 0 {
		x &= x - 1
		n++
	}
	return n
}

// SimhashHex 指纹的十六进制展示（调试/列表用）。
func SimhashHex(v int64) string {
	return "0x" + strconv.FormatUint(uint64(v), 16)
}

// SimilarHTTPEndpoints 在同 root_domain 下找与 simhash 汉明距离 ≤6 的同类端点
// （变体分析意图族的候选来源）。候选集为该域的全部 service 资产（有限集），
// Go 内存算距离；excludeID 用于排除源资产。
func (d *DB) SimilarHTTPEndpoints(rootDomain string, simhash int64, excludeID int64, limit int) ([]Asset, error) {
	if d == nil || rootDomain == "" || simhash == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 2
	}
	rows, err := d.Query(`
SELECT id, url, COALESCE(page_title,''), COALESCE(technologies,'{}'::text[]), simhash
FROM assets
WHERE root_domain = $1 AND type = 'service' AND simhash <> 0 AND id <> $2`,
		rootDomain, excludeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type cand struct {
		a    Asset
		dist int
	}
	var cands []cand
	for rows.Next() {
		var a Asset
		var sh int64
		if err := rows.Scan(&a.ID, &a.URL, &a.PageTitle, &a.Technologies, &sh); err != nil {
			return nil, err
		}
		dist := Hamming64(simhash, sh)
		if dist <= 6 {
			cands = append(cands, cand{a, dist})
		}
	}
	for i := 0; i < len(cands); i++ {
		for j := i + 1; j < len(cands); j++ {
			if cands[j].dist < cands[i].dist {
				cands[i], cands[j] = cands[j], cands[i]
			}
		}
	}
	out := make([]Asset, 0, limit)
	for _, c := range cands {
		if len(out) >= limit {
			break
		}
		out = append(out, c.a)
	}
	return out, nil
}

// derefI64 安全解引用 *int64（nil=0）。
func derefI64(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
