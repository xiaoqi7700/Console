package traffic

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// IdentityLexiconVersion identifies the built-in wordlist generation. Reports
// carry it so two baselines are only compared when the lexicon matches.
const IdentityLexiconVersion = "idscan-1"

// IdentityTerm is one literal pattern in an identity wordlist.
//
// Three lists mirror issue #40:
//   - A: platform brand / namespace strings (high confidence);
//   - B: platform capability, tool and skill names (medium confidence);
//   - C: generic framework / security-tool defaults (low confidence).
//
// Boundary=false makes the term a plain substring. Boundary=true rejects a hit
// whose neighbouring ASCII byte is a letter or digit, so "pojun" matches
// "pojun-hostd" and "POJUN_WORKER_CHAT" but not "pojunk" or "Pojunior".
// Underscore is deliberately not a boundary character: the platform's env
// prefixes are themselves brand evidence.
type IdentityTerm struct {
	ID       string `json:"id"`
	List     string `json:"list"`
	Pattern  string `json:"pattern"`
	Boundary bool   `json:"boundary"`
	CJK      bool   `json:"cjk"`
	Note     string `json:"note,omitempty"`

	// folded is the ASCII-lowercased pattern used by the matcher. It is built
	// by validate; unexported so wordlist JSON cannot inject a stale copy.
	folded []byte
}

// IdentityLexicon is the wordlist used by ScanIdentity. Terms are matched
// case-insensitively (ASCII fold); CJK terms are matched as byte substrings.
type IdentityLexicon struct {
	Version string         `json:"version"`
	Mode    string         `json:"mode,omitempty"`
	Terms   []IdentityTerm `json:"terms"`
}

// BuiltinLexicon returns a fresh copy of the compiled-in wordlist. Only strings
// present in the current tree are included: historical canary strings removed
// by #37 stay out of the binary and can only be loaded with --wordlist.
func BuiltinLexicon() *IdentityLexicon {
	terms := []IdentityTerm{
		// A. Brand and namespace. Overlapping substrings (pojun-hostd,
		// /opt/pojun, ghcr.io/chu0119/pojun) are intentionally not duplicated:
		// the base token already covers them, and one span must not count twice.
		{ID: "A-brand-pojun", List: "A", Pattern: "pojun", Boundary: true, Note: "产品名（大小写折叠后统一匹配）"},
		{ID: "A-brand-cjk", List: "A", Pattern: "破军", CJK: true, Note: "中文产品名"},
		{ID: "A-namespace-chu0119", List: "A", Pattern: "chu0119", Boundary: true, Note: "上游 GitHub 命名空间"},

		// B. Platform tool and skill names. A single B is only a notice; two
		// distinct B terms in one exchange promote to a finding.
		{ID: "B-tool-traffic-search", List: "B", Pattern: "traffic_search"},
		{ID: "B-tool-traffic-get", List: "B", Pattern: "traffic_get"},
		{ID: "B-tool-traffic-blob", List: "B", Pattern: "traffic_blob"},
		{ID: "B-tool-bind-finding-traffic", List: "B", Pattern: "bind_finding_traffic"},
		{ID: "B-tool-poc-scaffold", List: "B", Pattern: "poc_scaffold"},
		{ID: "B-tool-js-audit", List: "B", Pattern: "js_audit"},
		{ID: "B-tool-http-probe", List: "B", Pattern: "http_probe"},
		{ID: "B-tool-api-contract", List: "B", Pattern: "api_contract"},
		{ID: "B-tool-diff-responses", List: "B", Pattern: "diff_responses"},
		{ID: "B-tool-auth-request", List: "B", Pattern: "auth_request"},
		{ID: "B-tool-run-script", List: "B", Pattern: "run_script"},
		{ID: "B-tool-save-script", List: "B", Pattern: "save_script"},
		{ID: "B-tool-listener-start", List: "B", Pattern: "listener_start"},
		{ID: "B-tool-listener-stop", List: "B", Pattern: "listener_stop"},
		{ID: "B-tool-job-start", List: "B", Pattern: "job_start"},
		{ID: "B-tool-goal-met", List: "B", Pattern: "goal_met"},
		{ID: "B-tool-record-fact", List: "B", Pattern: "record_fact"},
		{ID: "B-tool-prove-goal", List: "B", Pattern: "prove_goal"},
		{ID: "B-tool-save-evidence", List: "B", Pattern: "save_evidence"},
		{ID: "B-tool-proxy-status", List: "B", Pattern: "proxy_status"},
		{ID: "B-tool-proxy-report", List: "B", Pattern: "proxy_report"},
		{ID: "B-tool-spawn-task", List: "B", Pattern: "spawn_task"},
		{ID: "B-tool-add-task-hint", List: "B", Pattern: "add_task_hint"},
		{ID: "B-script-probe", List: "B", Pattern: "probe.sh"},
		{ID: "B-script-js-audit", List: "B", Pattern: "js_audit.py"},
		{ID: "B-skill-ad", List: "B", Pattern: "active-directory-attack"},
		{ID: "B-skill-ai", List: "B", Pattern: "ai-llm-app-attack"},
		{ID: "B-skill-api-recon", List: "B", Pattern: "api-recon"},
		{ID: "B-skill-api-test", List: "B", Pattern: "api-security-testing"},
		{ID: "B-skill-apk", List: "B", Pattern: "apk-reverse"},
		{ID: "B-skill-surface", List: "B", Pattern: "attack-surface-recon"},
		{ID: "B-skill-mobile", List: "B", Pattern: "binary-mobile-reversing"},
		{ID: "B-skill-cloud", List: "B", Pattern: "cloud-attack-methods"},
		{ID: "B-skill-component", List: "B", Pattern: "component-vuln-intel"},
		{ID: "B-skill-output", List: "B", Pattern: "pentest-output-standards"},
		{ID: "B-skill-verification", List: "B", Pattern: "pentest-verification"},
		{ID: "B-skill-playwright", List: "B", Pattern: "playwright-cli"},
		{ID: "B-skill-redteam-ops", List: "B", Pattern: "redteam-ops"},
		{ID: "B-skill-redteam-opsec", List: "B", Pattern: "redteam-opsec"},
		{ID: "B-skill-scopesentry", List: "B", Pattern: "scopesentry-mcp"},
		{ID: "B-skill-contract", List: "B", Pattern: "smart-contract-audit"},
		{ID: "B-skill-source", List: "B", Pattern: "source-code-hunting"},
		{ID: "B-skill-src-acceptance", List: "B", Pattern: "src-acceptance"},
		{ID: "B-skill-src-hunting", List: "B", Pattern: "src-hunting"},
		{ID: "B-skill-vuln-hunting", List: "B", Pattern: "vuln-hunting"},
		{ID: "B-skill-web", List: "B", Pattern: "web-attack-methods"},
		{ID: "B-skill-wireless", List: "B", Pattern: "wireless-hardware-attack"},
		{ID: "B-skill-zero-day", List: "B", Pattern: "zero-day-research"},

		// C. Generic client and tool defaults. Disabled unless explicitly
		// requested; never promoted to a finding on their own.
		{ID: "C-ua-go-http-11", List: "C", Pattern: "Go-http-client/1.1"},
		{ID: "C-ua-go-http-20", List: "C", Pattern: "Go-http-client/2.0"},
		{ID: "C-ua-curl", List: "C", Pattern: "curl/"},
		{ID: "C-ua-python-requests", List: "C", Pattern: "python-requests/"},
		{ID: "C-ua-python-httpx", List: "C", Pattern: "python-httpx/"},
		{ID: "C-ua-python-urllib", List: "C", Pattern: "Python-urllib/"},
		{ID: "C-ua-okhttp", List: "C", Pattern: "okhttp/"},
		{ID: "C-ua-axios", List: "C", Pattern: "axios/"},
		{ID: "C-ua-aiohttp", List: "C", Pattern: "aiohttp/"},
		{ID: "C-ua-sqlmap", List: "C", Pattern: "sqlmap/"},
		{ID: "C-ua-ffuf", List: "C", Pattern: "Fuzz Faster U Fool", Boundary: true},
		{ID: "C-ua-nmap", List: "C", Pattern: "Nmap Scripting Engine", Boundary: true},
		{ID: "C-ua-zgrab", List: "C", Pattern: "zgrab/"},
		{ID: "C-ua-java", List: "C", Pattern: "Java/"},
		{ID: "C-ua-apache", List: "C", Pattern: "Apache-HttpClient/"},
	}
	l := &IdentityLexicon{Version: IdentityLexiconVersion, Terms: terms}
	_ = l.validate()
	return l
}

// LoadLexicon reads a JSON wordlist. With mode=merge (the default) terms are
// merged into the built-in list by ID; mode=replace uses the file alone.
func LoadLexicon(path string) (*IdentityLexicon, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取词表失败：%w", err)
	}
	return parseLexicon(raw)
}

func parseLexicon(raw []byte) (*IdentityLexicon, error) {
	var file IdentityLexicon
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("解析词表失败：%w", err)
	}
	mode := strings.ToLower(strings.TrimSpace(file.Mode))
	switch mode {
	case "", "merge":
		base := BuiltinLexicon()
		merged := map[string]IdentityTerm{}
		order := make([]string, 0, len(base.Terms)+len(file.Terms))
		for _, t := range base.Terms {
			merged[t.ID] = t
			order = append(order, t.ID)
		}
		for _, t := range file.Terms {
			if _, ok := merged[t.ID]; !ok {
				order = append(order, t.ID)
			}
			merged[t.ID] = t
		}
		out := &IdentityLexicon{Version: file.Version, Mode: "merge"}
		if out.Version == "" {
			out.Version = base.Version
		}
		for _, id := range order {
			out.Terms = append(out.Terms, merged[id])
		}
		if err := out.validate(); err != nil {
			return nil, err
		}
		return out, nil
	case "replace":
		file.Mode = "replace"
		if file.Version == "" {
			file.Version = IdentityLexiconVersion
		}
		if err := file.validate(); err != nil {
			return nil, err
		}
		return &file, nil
	default:
		return nil, fmt.Errorf("词表 mode 只支持 merge 或 replace，实际 %q", file.Mode)
	}
}

func (l *IdentityLexicon) validate() error {
	if l == nil {
		return fmt.Errorf("词表为空")
	}
	if strings.TrimSpace(l.Version) == "" {
		l.Version = IdentityLexiconVersion
	}
	ids := map[string]int{}
	patterns := map[string]string{}
	for i := range l.Terms {
		t := &l.Terms[i]
		t.ID = strings.TrimSpace(t.ID)
		t.List = strings.ToUpper(strings.TrimSpace(t.List))
		t.Pattern = strings.TrimSpace(t.Pattern)
		if t.ID == "" {
			return fmt.Errorf("词表第 %d 条缺少 id", i+1)
		}
		if prev, ok := ids[t.ID]; ok {
			return fmt.Errorf("词表 id 重复：%s（第 %d 条与第 %d 条）", t.ID, prev, i+1)
		}
		ids[t.ID] = i + 1
		switch t.List {
		case "A", "B", "C":
		default:
			return fmt.Errorf("词条 %s 的 list 必须是 A/B/C，实际 %q", t.ID, t.List)
		}
		if t.Pattern == "" {
			return fmt.Errorf("词条 %s 缺少 pattern", t.ID)
		}
		fold := foldASCII(t.Pattern)
		if t.CJK && t.Boundary {
			return fmt.Errorf("词条 %s 是 CJK，不能启用 boundary", t.ID)
		}
		if t.Boundary && len(fold) < 3 {
			return fmt.Errorf("词条 %s 启用 boundary 后折叠长度小于 3 字节", t.ID)
		}
		if !isASCII(t.Pattern) && !t.CJK {
			return fmt.Errorf("词条 %s 含非 ASCII 字符，必须标记 cjk", t.ID)
		}
		key := string(fold)
		if prev, ok := patterns[key]; ok {
			return fmt.Errorf("词条 %s 与 %s 折叠后 pattern 相同（%q）", t.ID, prev, t.Pattern)
		}
		patterns[key] = t.ID
		t.folded = fold
	}
	return nil
}

// IdentityAllowRule suppresses hits for one term, one host, or both. Reason is
// mandatory so every suppression is auditable.
type IdentityAllowRule struct {
	TermID string `json:"term_id,omitempty"`
	Host   string `json:"host,omitempty"`
	Reason string `json:"reason"`
}

// IdentityAllowlist is the false-positive control file accepted by --allowlist.
type IdentityAllowlist struct {
	Rules []IdentityAllowRule `json:"rules"`
}

func LoadAllowlist(path string) (*IdentityAllowlist, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取白名单失败：%w", err)
	}
	var a IdentityAllowlist
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("解析白名单失败：%w", err)
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return &a, nil
}

func (a *IdentityAllowlist) validate() error {
	if a == nil {
		return nil
	}
	for i := range a.Rules {
		r := &a.Rules[i]
		r.TermID = strings.TrimSpace(r.TermID)
		r.Host = normalizeIdentityHost(r.Host)
		r.Reason = strings.TrimSpace(r.Reason)
		if r.TermID == "" && r.Host == "" {
			return fmt.Errorf("白名单第 %d 条必须至少指定 term_id 或 host", i+1)
		}
		if r.Reason == "" {
			return fmt.Errorf("白名单第 %d 条缺少 reason（抑制必须可审计）", i+1)
		}
	}
	return nil
}

// match returns the first allowlist rule that covers a hit, if any.
func (a *IdentityAllowlist) match(termID, host string) (*IdentityAllowRule, bool) {
	if a == nil {
		return nil, false
	}
	for i := range a.Rules {
		r := &a.Rules[i]
		if r.TermID != "" && r.TermID != termID {
			continue
		}
		if r.Host != "" && r.Host != host {
			continue
		}
		return r, true
	}
	return nil, false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
