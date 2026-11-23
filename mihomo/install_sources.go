package mihomo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Autumn-27/artex/proxyprobe"
)

// 本文件是 mihomo 的「替代安装源」：GitHub Release 资产在很多生产/客户网络里
// 根本连不上（实测：api.github.com 可达，但 github.com → objects.githubusercontent.com
// 的资产连接 20s 超时），而原安装器又只有一个 60s 总超时的 GitHub 路径，于是
// 「安装 mihomo」在生产/客户环境必然失败。这里补三条路：
//   - 官方 GitHub（保留，下载改为可续传 + 分次超时）；
//   - 自定义 URL（内网镜像 / 任意可访问的 .gz/.zip/裸二进制）；
//   - 服务器本地文件（离线拷贝后安装）。
//
// 自定义来源允许传 sha256；给了就强校验，没给则回显实际哈希供人工比对。

const (
	installAPITimeout    = 30 * time.Second // GitHub API 元数据
	installIdleTimeout   = 60 * time.Second // 连接/读 body 无进展即判定本次尝试失败（可续传重试）
	installMaxAttempts   = 6                // 断点续传重试次数
	installRetryBackoff  = 3 * time.Second  // 重试间隔
	installOverallBudget = 30 * time.Minute // 整个安装过程上限（慢速但持续有进展的链路）
)

// DefaultMirrors 是 GitHub 资产的默认加速前缀（设置项 proxypool_mihomo_mirrors 可覆盖）。
// 只在拿到 GitHub API 的官方 SHA-256 时启用：镜像只搬运字节，哈希对不上自动换下一个源。
var DefaultMirrors = []string{
	"https://gh-proxy.com/", // 实测 4MB/s（2026-11-14）
	"https://ghfast.top/",
	"https://ghproxy.net/", // 实测 42KB/s，仅作兜底
}

// installClient 返回不设全局超时的客户端：单次下载按 attempt 窗口控制，
// 浏览器/网关的 60s 总超时会误杀大文件慢速下载（本机实测 10KB/s）。
func installClient(proxyURL string) (*http.Client, error) {
	return proxyprobe.ClientFor(strings.TrimSpace(proxyURL), 0)
}

// ensureWritable 在下载前先验证目录可写，把「装到一半才报权限」变成快速失败。
func (m *Manager) ensureWritable() error {
	if err := os.MkdirAll(m.dir, 0o755); err != nil {
		return fmt.Errorf("创建 mihomo 目录失败（检查 %s 的属主/权限）: %w", m.dir, err)
	}
	probe, err := os.CreateTemp(m.dir, ".install-probe-*")
	if err != nil {
		return fmt.Errorf("mihomo 目录不可写（%s）：请确认服务用户对 data 目录有写权限: %w", m.dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

// payloadFromArchive 按文件名后缀解包；未知后缀按裸二进制处理（自定义来源常见）。
func payloadFromArchive(name string, data []byte) ([]byte, error) {
	lower := strings.ToLower(name)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return unzipBinary(data)
	case strings.HasSuffix(lower, ".gz"):
		return gunzip(data)
	default:
		return data, nil
	}
}

// urlBaseName 取 URL 路径最后一段（忽略 query），用于判断包格式。
func urlBaseName(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Path != "" {
		return filepath.Base(u.Path)
	}
	return filepath.Base(raw)
}

// saveInstalledBinary 原子落盘并更新管理器状态。
func (m *Manager) saveInstalledBinary(payload []byte, version, source string, wantSHA string, checksumVerified bool) (InstallResult, error) {
	if len(payload) == 0 {
		return InstallResult{}, errors.New("安装包解压后为空")
	}
	// 先校验再落盘：校验失败不能覆盖掉上一个可用的二进制。
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	if wantSHA != "" && !strings.EqualFold(wantSHA, sha) {
		return InstallResult{}, fmt.Errorf("校验失败：期望 %s，实际 %s", strings.ToLower(wantSHA), sha)
	}
	bin := filepath.Join(m.dir, "mihomo")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// 先写临时文件再 rename：安装失败不会留下半截可执行文件占用端口/被误启动。
	tmp := bin + ".new"
	if err := os.WriteFile(tmp, payload, 0o755); err != nil {
		return InstallResult{}, fmt.Errorf("写入 mihomo 失败: %w", err)
	}
	if err := os.Rename(tmp, bin); err != nil {
		_ = os.Remove(tmp)
		return InstallResult{}, fmt.Errorf("替换 mihomo 失败: %w", err)
	}
	_ = os.Chmod(bin, 0o755)

	if version == "" {
		version = detectVersion(bin)
	}

	m.mu.Lock()
	m.binary = bin
	m.version = version
	m.mu.Unlock()
	return InstallResult{Path: bin, Version: version, SHA256: sha, SourceURL: source, ChecksumVerified: checksumVerified || wantSHA != ""}, nil
}

// InstallFromFile 从服务器本地文件安装（离线/内网拷贝）。文件先读入内存（有上限），
// 再按后缀解包。调用方通常是运维 scp 上传后点「从服务器文件安装」。
func (m *Manager) InstallFromFile(src string) (InstallResult, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return InstallResult{}, errors.New("本地文件路径为空")
	}
	st, err := os.Stat(src)
	if err != nil {
		return InstallResult{}, fmt.Errorf("读取本地安装包失败: %w", err)
	}
	if !st.Mode().IsRegular() {
		return InstallResult{}, fmt.Errorf("不是普通文件: %s", src)
	}
	if st.Size() > downloadLimit {
		return InstallResult{}, fmt.Errorf("安装包超过 %dMB 限制", downloadLimit>>20)
	}
	if err := m.ensureWritable(); err != nil {
		return InstallResult{}, err
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return InstallResult{}, fmt.Errorf("读取本地安装包失败: %w", err)
	}
	payload, err := payloadFromArchive(src, data)
	if err != nil {
		return InstallResult{}, err
	}
	return m.saveInstalledBinary(payload, "", src, "", false)
}

// InstallFromURL 从任意可访问的 URL 安装（内网镜像/自建文件服务）。支持断点续传
// 与多次重试。审计 B8：远程 URL 安装必须提供 sha256 并强校验——任意可写的
// 下载源是典型的供应链投毒入口，「先装上再人工比对哈希」时投毒的二进制已经
// 执行过一次了。离线拷贝（InstallFromFile）不走这条限制，运维本地文件可控。
// 注意：官方 GitHub 资产地址在受限网络里可能永远连不上——那属于网络策略，
// 改用镜像（自带官方哈希）或本地上传即可。
func (m *Manager) InstallFromURL(ctx context.Context, rawURL, wantSHA, proxyURL string) (InstallResult, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return InstallResult{}, errors.New("安装包 URL 为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return InstallResult{}, fmt.Errorf("只支持 http/https 安装包地址: %s", rawURL)
	}
	if strings.TrimSpace(wantSHA) == "" {
		return InstallResult{}, errors.New("远程 URL 安装必须提供 sha256（64 位十六进制）：先在可信环境取到安装包哈希再安装；离线场景请改用「从服务器文件安装」")
	}
	if err := m.ensureWritable(); err != nil {
		return InstallResult{}, err
	}
	client, err := installClient(proxyURL)
	if err != nil {
		return InstallResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, installOverallBudget)
	defer cancel()
	data, err := downloadResumable(ctx, client, rawURL, filepath.Join(m.dir, "mihomo.download"))
	if err != nil {
		return InstallResult{}, err
	}
	payload, err := payloadFromArchive(urlBaseName(rawURL), data)
	if err != nil {
		return InstallResult{}, err
	}
	res, err := m.saveInstalledBinary(payload, "", rawURL, strings.TrimSpace(wantSHA), false)
	if err == nil {
		_ = os.Remove(filepath.Join(m.dir, "mihomo.download"))
	}
	return res, err
}

// downloadResumable 带断点续传的下载：先写 <dst>，连接中断后从已有字节数继续
// （Range: bytes=N-）。服务端忽略 Range 时自动从头重来。
//
// 超时模型：不是「总时长一刀切」，而是「60s 无任何进展就算本次尝试失败」。
// 这样黑洞地址会快速失败并重试；10KB/s 但持续有数据的慢链路可以一直下到完整
// （原实现 client.Timeout=60s 会误杀慢下载，是生产/客户环境安装失败的主因之一）。
func downloadResumable(ctx context.Context, client *http.Client, rawURL, dst string) ([]byte, error) {
	var lastErr error
	zeroStreak := 0 // 连续「一个字节都没下到」的次数：对黑洞地址快速失败，别让用户等 6 轮
	for attempt := 1; attempt <= installMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		off := int64(0)
		if st, err := os.Stat(dst); err == nil {
			off = st.Size()
		}
		if off > downloadLimit {
			_ = os.Remove(dst)
			off = 0
		}
		reqCtx, cancel := context.WithCancel(ctx)
		idle := time.AfterFunc(installIdleTimeout, cancel)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
		if err != nil {
			idle.Stop()
			cancel()
			return nil, err
		}
		req.Header.Set("User-Agent", "pojun-mihomo-installer")
		if off > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
		}
		resp, err := client.Do(req)
		if err != nil {
			idle.Stop()
			cancel()
			lastErr = fmt.Errorf("连接安装包地址失败（第 %d/%d 次，已下载 %d 字节）: %w", attempt, installMaxAttempts, off, err)
			if off == 0 {
				zeroStreak++
			} else {
				zeroStreak = 0
			}
			if zeroStreak >= 2 {
				break // 地址根本连不上：立即给出可操作结论，不再空转
			}
			time.Sleep(installRetryBackoff)
			continue
		}
		status := resp.StatusCode
		if status != http.StatusOK && status != http.StatusPartialContent {
			_ = resp.Body.Close()
			idle.Stop()
			cancel()
			if status == http.StatusRequestedRangeNotSatisfiable && off > 0 {
				if data, err := os.ReadFile(dst); err == nil {
					return data, nil
				}
			}
			return nil, fmt.Errorf("下载安装包返回 %d", status)
		}
		flags := os.O_CREATE | os.O_WRONLY
		if status == http.StatusPartialContent && off > 0 {
			flags |= os.O_APPEND
		} else {
			// 服务端忽略了 Range（返回 200）→ 从头写，避免把两段数据拼坏。
			flags |= os.O_TRUNC
			off = 0
		}
		f, err := os.OpenFile(dst, flags, 0o600)
		if err != nil {
			_ = resp.Body.Close()
			idle.Stop()
			cancel()
			return nil, fmt.Errorf("打开下载文件失败: %w", err)
		}
		// 每读到一段数据就重置「无进展」计时器。
		body := &progressReader{r: resp.Body, touch: func() { idle.Reset(installIdleTimeout) }}
		n, copyErr := io.Copy(f, io.LimitReader(body, downloadLimit-off+1))
		_ = f.Sync()
		_ = f.Close()
		_ = resp.Body.Close()
		idle.Stop()
		cancel()
		total := off + n
		if total > downloadLimit {
			_ = os.Remove(dst)
			return nil, fmt.Errorf("安装包超过 %dMB 限制", downloadLimit>>20)
		}
		if copyErr != nil {
			lastErr = fmt.Errorf("下载中断（第 %d/%d 次，已保存 %d 字节，可续传）: %w", attempt, installMaxAttempts, total, copyErr)
			if n == 0 && off == 0 {
				zeroStreak++
			} else {
				zeroStreak = 0
			}
			if zeroStreak >= 2 {
				break
			}
			time.Sleep(installRetryBackoff)
			continue
		}
		if total == 0 {
			lastErr = fmt.Errorf("下载安装包为空（第 %d/%d 次）", attempt, installMaxAttempts)
			time.Sleep(installRetryBackoff)
			continue
		}
		data, err := os.ReadFile(dst)
		if err != nil {
			return nil, fmt.Errorf("读取下载文件失败: %w", err)
		}
		return data, nil
	}
	if lastErr == nil {
		lastErr = errors.New("下载失败")
	}
	return nil, fmt.Errorf("%w；如本机无法访问该地址，请改用内网镜像 URL 或「从服务器文件安装」", lastErr)
}

// progressReader 每次读到数据就回调一次（用于重置空闲超时计时器）。
type progressReader struct {
	r     io.Reader
	touch func()
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 && p.touch != nil {
		p.touch()
	}
	return n, err
}

// probeSource 用 64KB 的 Range 请求测一个下载源的「首段速度」，返回字节数与耗时。
// 目的：镜像之间速度能差 100 倍（实测 gh-proxy 4MB/s vs ghproxy 42KB/s），
// 顺序尝试会让用户在一个慢源上等十几分钟。
func probeSource(ctx context.Context, client *http.Client, rawURL string) (int64, time.Duration) {
	pctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(pctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, time.Hour
	}
	req.Header.Set("User-Agent", "pojun-mihomo-installer")
	req.Header.Set("Range", "bytes=0-65535")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, time.Hour
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return 0, time.Hour
	}
	n, _ := io.CopyN(io.Discard, resp.Body, 64<<10)
	elapsed := time.Since(start)
	if n == 0 {
		return 0, time.Hour
	}
	return n, elapsed
}

// pickFastestSource 并发测速并返回最快的源；全部失败返回空串。
func pickFastestSource(ctx context.Context, client *http.Client, sources []string) string {
	type result struct {
		src string
		bps float64
	}
	ch := make(chan result, len(sources))
	for _, src := range sources {
		go func(u string) {
			n, d := probeSource(ctx, client, u)
			ch <- result{u, float64(n) / d.Seconds()}
		}(src)
	}
	best, bestBPS := "", 0.0
	for range sources {
		r := <-ch
		if r.bps > bestBPS {
			best, bestBPS = r.src, r.bps
		}
	}
	return best
}
