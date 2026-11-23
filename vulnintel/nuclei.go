package vulnintel

// nuclei-templates 模板树管理与扫描工具支撑:
// - EnsureTemplates:模板树不存在则 git clone --depth 1,存在则 git pull(fast-forward)
// - 模板树目录默认 <data>/nuclei-templates,由 server 传入
// - FindNucleiTemplates(见 poc.go)按 CVE 找模板相对路径
//
// 刻意不引 go-git:git 命令行可用性在运行镜像里有保证(Dockerfile 装 git),
// 且 --depth 1 的浅克隆用命令行最直接。

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TemplatesDir 是模板树位置(默认可执行文件旁 nuclei-templates/)。
func TemplatesDir(dataDir string) string {
	return filepath.Join(dataDir, "nuclei-templates")
}

// EnsureTemplates clones or updates the template tree. Best-effort: returns
// error but callers log it — scan_with_nuclei degrades to "templates
// unavailable" messaging rather than failing the sync.
//
// proxy 是可选出网代理(http/https/socks5，空=直连)。模板树在 github.com，
// 国内/校园网直连必然超时——不传代理时这里只能报 clone failed，所以调用方要用
// 平台配置的「装机代理/全局代理」喂进来，跟拉更新走同一条出口。
//
// 自愈语义（v0.3.96）：clone/pull 失败时清理半成品目录——git 中断残留的 .git
// 空壳会让目录「存在但没有模板」，状态页永远显示 0 个模板且无法自愈（Kali 实测）。
// 成功后校验 yaml 模板数 >0，空树同样按失败清理，下一轮重clone。
func EnsureTemplates(ctx context.Context, dir, proxy string) error {
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_HTTP_LOW_SPEED_LIMIT=1000", "GIT_HTTP_LOW_SPEED_TIME=30")
	if proxy != "" {
		// git 认的是 http_proxy/https_proxy（大小写都设一份，不同版本读的不一样），
		// socks5 代理只有 ALL_PROXY 走得通。
		env = append(env,
			"http_proxy="+proxy, "https_proxy="+proxy, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy,
			"ALL_PROXY="+proxy, "all_proxy="+proxy)
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		// update: fetch + fast-forward only, ignore local drift
		cmd := exec.CommandContext(ctx, "git", "-C", dir, "pull", "--ff-only", "--quiet")
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			// 拉取失败分两类：网络/超时（目录留着下次再 pull）；仓库本身损坏
			// （pull 反复失败永远修不好，删掉重 clone 才是自愈）。这里保守处理：
			// 只有目录里一个 yaml 都没有时才视为损坏并清理。
			if CountTemplates(dir) == 0 {
				os.RemoveAll(dir)
				return fmt.Errorf("nuclei templates pull 失败且目录无模板（已清理残留，等下轮重 clone）: %v: %s",
					err, strings.TrimSpace(string(out)))
			}
			return fmt.Errorf("nuclei templates pull: %v: %s", err, strings.TrimSpace(string(out)))
		}
		return verifyTemplates(dir)
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", "--single-branch", "--quiet",
		"https://github.com/projectdiscovery/nuclei-templates.git", dir)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		// clone 失败必留半成品（.git 或部分工作树）——不清理的话下一轮看到 .git
		// 就走 pull 分支，对着残缺仓库 pull，永远修不好（Kali 实测挂了 14 小时）。
		os.RemoveAll(dir)
		return fmt.Errorf("nuclei templates clone（残留已清理，等下轮重试）: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return verifyTemplates(dir)
}

// verifyTemplates 克隆/拉取成功后的内容校验：模板树一个 yaml 都没有 = 无效
// （网络代理返回了错误页、磁盘满等场景产出过空工作树），按失败清理。
func verifyTemplates(dir string) error {
	if n := CountTemplates(dir); n == 0 {
		os.RemoveAll(dir)
		return fmt.Errorf("nuclei templates 校验失败：目录无 yaml 模板（已清理残留，等下轮重试）")
	}
	return nil
}

// CountTemplates 递归统计目录下的 .yaml 模板文件数（.yaml，不含 .yml——
// nuclei-templates 仓库全部用 .yaml）。
func CountTemplates(dir string) int {
	n := 0
	filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 不可读的子树跳过，不中断统计
		}
		if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".yaml") {
			n++
		}
		return nil
	})
	return n
}

// NucleiInstalled reports whether the nuclei binary is on PATH.
func NucleiInstalled() bool {
	_, err := exec.LookPath("nuclei")
	return err == nil
}

// ScanArgs is scan_with_nuclei's validated input.
type ScanArgs struct {
	Target       string        // URL/host to scan
	CVEID        string        // optional: restrict to templates mentioning this CVE
	Severity     string        // optional: comma list critical,high,medium,low
	TimeoutTotal time.Duration // whole-run ceiling (default 10m, cap 30m)
	// Proxy 是出口代理 URL（可空）。空=直连，命令里不出现 -proxy——
	// nuclei 的 -proxy 是 string[]，空条目会让代理解析失败。
	Proxy string
}

// EffectiveTimeout 归一化整轮超时：<=0 用 10m，>30m 钳到 30m。
// BuildNucleiCmd 与 agent 侧的 GNU timeout 包裹共用这一套规则，避免两处钳制漂移。
func EffectiveTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 10 * time.Minute
	}
	if d > 30*time.Minute {
		return 30 * time.Minute
	}
	return d
}

// normalizeNucleiProxy 把 ToolSet 的出口代理归一化成 nuclei -proxy 接受的形式。
// 规则与 agent 侧 buildHTTPClient 一致：只有缺 scheme 时才补 http://，绝不无条件拼
// （生产值经 traffic.ProxyAddr 恒带 http://，无条件拼会得到 http://http://…）。
// 空/纯空白=直连，调用方不发射 -proxy。逗号一律拒绝：-proxy 是 string[]，逗号会被当成
// 多代理分隔符，带逗号口令的 URL 会被静默拆坏（-silent 下等同“无命中”）。这里不做
// 百分号编码——编码后的 userinfo 代理端未必认，宁可显式报错。
// 端口必填：nuclei v3.11.1 启动时按 Hostname():Port() 做 TCP 探活，缺端口直接在
// Logger.Fatal，工具层提前报错才能给出可读原因。
func normalizeNucleiProxy(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", nil
	}
	if strings.Contains(p, ",") {
		return "", fmt.Errorf("代理地址含逗号(%q):nuclei 会把 -proxy 当多代理列表拆开,请改用不含逗号的地址", p)
	}
	if !strings.Contains(p, "://") {
		p = "http://" + p
	}
	u, err := url.Parse(p)
	if err != nil {
		return "", fmt.Errorf("代理地址无法解析(%q): %v", p, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https", "socks5":
	default:
		return "", fmt.Errorf("不支持的代理协议(%q):只接受 http/https/socks5", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("代理地址缺少主机(%q)", p)
	}
	if u.Port() == "" {
		return "", fmt.Errorf("代理地址缺少端口(%q):nuclei 启动时按 host:port 探活,缺端口会直接退出", p)
	}
	return p, nil
}

// BuildNucleiCmd assembles the nuclei invocation. Templates restricted to the
// local tree (-t <dir>) so we never trigger nuclei's own template download
// (offline-friendly, version-pinned); -silent keeps output parseable; JSONL
// output goes to stdout for the agent to read. The returned cancel MUST be
// called by the caller after the run (it bounds the whole-run ceiling).
func BuildNucleiCmd(ctx context.Context, templatesDir string, a ScanArgs) (*exec.Cmd, context.CancelFunc, error) {
	if strings.TrimSpace(a.Target) == "" {
		return nil, nil, fmt.Errorf("target 不能为空")
	}
	if _, err := os.Stat(filepath.Join(templatesDir, ".git")); err != nil {
		return nil, nil, fmt.Errorf("模板树不可用(%s):先等同步器完成初始化", templatesDir)
	}
	timeout := EffectiveTimeout(a.TimeoutTotal)
	runCtx, cancel := context.WithTimeout(ctx, timeout)

	args := []string{
		"-target", a.Target,
		"-t", templatesDir,
		"-jsonl",
		"-silent",
		"-no-color",
		"-disable-update-check",
	}
	// 出口代理：Traffic 捕获 / 全局代理 / 严格出口哨兵都经 ToolSet.egressProxy 流进来。
	// 必须在这里发射：scan_with_nuclei 只组命令，nuclei 由 Bash 执行，
	// “nuclei 对 env 支持不稳”这条约束光靠提示词无法强制。
	if prox, perr := normalizeNucleiProxy(a.Proxy); perr != nil {
		cancel()
		return nil, nil, perr
	} else if prox != "" {
		args = append(args, "-proxy", prox)
	}
	if cve := strings.TrimSpace(a.CVEID); cve != "" {
		templates := FindNucleiTemplates(templatesDir, cve)
		if len(templates) == 0 {
			cancel()
			return nil, nil, fmt.Errorf("模板树中没有命中 %s 的模板(树可能过期,等下轮同步)", cve)
		}
		for _, rel := range templates {
			args = append(args, "-t", filepath.Join(templatesDir, filepath.FromSlash(rel)))
		}
	}
	if sev := strings.TrimSpace(a.Severity); sev != "" {
		args = append(args, "-severity", sev)
	}
	return exec.CommandContext(runCtx, "nuclei", args...), cancel, nil
}
