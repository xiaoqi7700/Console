package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Autumn-27/artex/traffic"
)

// runIDScan implements the offline identity scanner (issue #40). It is
// deliberately dispatched before the shared pojun-maint FlagSet: the scanner
// needs no PostgreSQL, and the shared FlagSet would reject its own flags with
// exit 2 before any work began.
func runIDScan(args []string) {
	fs := flag.NewFlagSet("idscan", flag.ExitOnError)
	cfgPath := fs.String("config", "/opt/pojun/config.json", "config.json 路径（仅用于推导默认 data 目录）")
	dataDir := fs.String("data", "", "数据目录（默认取 config 目录下的 data）")
	dbPath := fs.String("db", "", "直接指定 index.sqlite（优先于 --data）")
	wordlist := fs.String("wordlist", "", "词表 JSON（默认内置；同 id 覆盖，新 id 追加）")
	allowlist := fs.String("allowlist", "", "白名单 JSON（term_id/host + reason）")
	taskMapPath := fs.String("task-map", "", "host→task 映射 JSON（可选，用于每任务汇总）")
	tiers := fs.String("tiers", "A,B", "启用词表：A,B 或 A,B,C")
	hosts := fs.String("host", "", "只扫描这些 host（逗号分隔）")
	since := fs.Int64("since", 0, "只扫描 ts >= 该 Unix 秒")
	until := fs.Int64("until", 0, "只扫描 ts < 该 Unix 秒")
	limit := fs.Int("limit", 0, "最多扫描多少条 exchange（0=不限）")
	batch := fs.Int("batch", 200, "每批行数（上限 1000）")
	maxBody := fs.Int64("max-body-bytes", traffic.IdentityDefaultMaxBodyBytes, "单条正文最多读取字节（默认 5 MiB，覆盖录制阈值内的全部正文）")
	outPath := fs.String("out", "", "把完整报告写成 JSON（0600）")
	failOnFindings := fs.Bool("fail-on-findings", false, "存在 finding 时退出码 3（可用于回归门禁）")
	_ = fs.Parse(args)

	if *dataDir == "" && *dbPath == "" {
		*dataDir = filepath.Join(filepath.Dir(*cfgPath), "data")
	}
	opt := traffic.IdentityScanOptions{
		DBPath:       *dbPath,
		DataDir:      *dataDir,
		Tiers:        splitCSV(*tiers),
		Hosts:        splitCSV(*hosts),
		Since:        *since,
		Until:        *until,
		Limit:        *limit,
		Batch:        *batch,
		MaxBodyBytes: *maxBody,
	}
	if *wordlist != "" {
		lex, err := traffic.LoadLexicon(*wordlist)
		if err != nil {
			fail(err)
		}
		opt.Lexicon = lex
	}
	if *allowlist != "" {
		allow, err := traffic.LoadAllowlist(*allowlist)
		if err != nil {
			fail(err)
		}
		opt.Allowlist = allow
	}
	if *taskMapPath != "" {
		m, err := loadIDScanTaskMap(*taskMapPath)
		if err != nil {
			fail(err)
		}
		opt.TaskMap = m
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := traffic.ScanIdentity(ctx, opt)
	if err != nil {
		fail(err)
	}
	printIDScanSummary(rep)
	if *outPath != "" {
		raw, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			fail(err)
		}
		if err := os.WriteFile(*outPath, raw, 0o600); err != nil {
			fail(err)
		}
		// WriteFile only applies the mode when creating; chmod so an existing
		// file cannot keep a wider mode.
		_ = os.Chmod(*outPath, 0o600)
		fmt.Printf("\n完整报告已写入 %s（0600）\n", *outPath)
	}
	if *failOnFindings && rep.FindingsTotal > 0 {
		os.Exit(3)
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

type idscanTaskMapFile struct {
	Hosts map[string][]int64 `json:"hosts"`
}

func loadIDScanTaskMap(path string) (map[string][]int64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取任务映射失败：%w", err)
	}
	var f idscanTaskMapFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("解析任务映射失败：%w", err)
	}
	if len(f.Hosts) == 0 {
		return nil, fmt.Errorf("任务映射文件没有 hosts")
	}
	return f.Hosts, nil
}

func printIDScanSummary(rep *traffic.IdentityReport) {
	fmt.Println("离线身份扫描（只读）")
	fmt.Printf("  库: %s（mode=%s）\n", rep.DB.Path, rep.DB.Mode)
	fmt.Printf("  词表: %s（%s）  A=%d B=%d C=%d\n", rep.Lexicon.Version, rep.Lexicon.Source,
		rep.Lexicon.Counts["A"], rep.Lexicon.Counts["B"], rep.Lexicon.Counts["C"])
	fmt.Printf("  扫描: %d 行 / %d 批 / 截断=%s / 用时 %dms\n", rep.Scan.Scanned, rep.Scan.Batches,
		boolText(rep.Scan.Truncated), rep.Scan.DurationMillis)
	cov := rep.Coverage
	fmt.Printf("  覆盖率: 有正文 %d/%d（%.1f%%）  请求 %d  响应 %d\n", cov.WithBody, cov.Eligible,
		cov.CaptureCoverage*100, cov.RequestCapture, cov.ResponseCapture)
	fmt.Printf("  扫描覆盖: %.1f%%  正文读取 %d 字节  截断 %d  二进制跳过 %d  blob 缺失 %d\n",
		cov.ScanCoverage*100, cov.BodyBytesRead, cov.BodyTruncated, rep.Scan.BinarySkipped, rep.Scan.BlobMissing)
	fmt.Printf("  排除: HEAD=%d 1xx=%d 204/205=%d 304=%d status0=%d legacy=%d\n",
		cov.Excluded.HEAD, cov.Excluded.Informational1xx, cov.Excluded.NoContent,
		cov.Excluded.NotModified304, cov.Excluded.FailedStatus0, cov.LegacyRows)
	fmt.Printf("  A: %d 命中 / %d exchange   B: %d / %d   C: %d / %d\n",
		rep.Lists["A"].Hits, rep.Lists["A"].Exchanges,
		rep.Lists["B"].Hits, rep.Lists["B"].Exchanges,
		rep.Lists["C"].Hits, rep.Lists["C"].Exchanges)
	fmt.Printf("  findings: %d（报告内列出 %d 条）  白名单抑制 %d\n",
		rep.FindingsTotal, len(rep.Findings), rep.Suppressed.ByAllowlist)

	hosts := append([]traffic.IdentityHostStat(nil), rep.Hosts...)
	sort.Slice(hosts, func(i, j int) bool {
		hi, hj := hosts[i], hosts[j]
		ti := hi.Hits["A"] + hi.Hits["B"] + hi.Hits["C"] + hi.Findings
		tj := hj.Hits["A"] + hj.Hits["B"] + hj.Hits["C"] + hj.Findings
		if ti != tj {
			return ti > tj
		}
		return hi.Host < hj.Host
	})
	if len(hosts) > 0 {
		fmt.Println("\nTop hosts（按命中总数）:")
		fmt.Printf("  %-42s %8s %8s %8s %6s %6s %6s %8s\n", "host", "exch", "eligible", "withBody", "A", "B", "C", "findings")
		for i, h := range hosts {
			if i >= 50 {
				break
			}
			fmt.Printf("  %-42s %8d %8d %8d %6d %6d %6d %8d\n", h.Host, h.Exchanges, h.Eligible, h.WithBody,
				h.Hits["A"], h.Hits["B"], h.Hits["C"], h.Findings)
		}
	}
	if len(rep.Samples) > 0 {
		fmt.Println("\n样例（脱敏，最多 10 条）:")
		for i, s := range rep.Samples {
			if i >= 10 {
				break
			}
			fmt.Printf("  [%s] %s %s %s @%d %s\n", s.List, s.Host, s.TermID, s.Where, s.Offset, s.Snippet)
		}
	}
	if len(rep.Warnings) > 0 {
		fmt.Println("\n警告:")
		for _, w := range rep.Warnings {
			fmt.Printf("  - %s\n", w)
		}
	}
}

func boolText(b bool) string {
	if b {
		return "是"
	}
	return "否"
}
