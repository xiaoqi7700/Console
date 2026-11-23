package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent/validators"
	"github.com/Autumn-27/artex/db"

	actool "github.com/Autumn-27/norma/tool"
)

// validate_finding（v0.4.92 验证层冲刺）：按漏洞类别跑程序化验证探针并对响应做
// 机械断言——XBOW validators / AIxCC PoV 范式的平台落地。与 evidence_check 的
// 静态 13 项互补：这里发真实探针（走出口代理+流量录制），输出机器可判定的
// verdict 与证据标记 validate:<token>:pass，引用进 report_finding 即完成机验闭环。
//
// 作为工具（而非 server 内部钩子）是有意的：探针是对目标的主动请求，走 guard
// 的 PreToolUse 审查链（规则+Judge），探针响应进证据回验台账，全部与普通工具
// 同一纪律。v1 非阻断：validator 结果是加分证据，不影响上报路径。
func (t *ToolSet) validateFinding() actool.CoreTool {
	return writeTool("validate_finding",
		"按漏洞类别自动跑程序化验证探针（XBOW validators 范式）：注入唯一 token 变体并对响应做机械断言，输出机器可判定的 pass/warn/fail 与证据标记。"+
			"当前支持：RCE/命令注入（回显 token+时延）、XSS（反射+上下文+CSP 核查）、SSRF（OOB 回连+文件读取/云元数据响应断言）。"+
			"pass 时输出证据标记 validate:<token>:pass——把它原样写进 report_finding 的 evidence，即完成机验闭环。"+
			"探针走平台出口（代理/录制）且经审查链；同一目标同类验证每次 token 不同，避免跨请求关联。",
		obj(map[string]any{
			"vulnclass": map[string]any{
				"type":        "string",
				"description": "漏洞类别（report_finding 同款白名单，自动归一）：RCE/注入→命令注入验证；XSS→反射验证；SSRF→带外+响应验证。其余类别暂无自动 validator。",
			},
			"url":   map[string]any{"type": "string", "description": "含参数的目标 URL（如 http://target/ping?host=x）；探针注入到 param 指定的参数"},
			"param": map[string]any{"type": "string", "description": "要注入的参数名"},
			"payload": map[string]any{
				"type":        "string",
				"description": "可选：你已验证可触发的前缀 payload（如已知 ; 拼接生效）；缺省用 runner 内置探针集",
			},
			"wait_seconds": map[string]any{
				"type":        "integer",
				"description": "可选：SSRF OOB 回连等待秒数（默认 8，3-30）",
			},
			"insecure": map[string]any{
				"type":        "boolean",
				"description": "可选：跳过 TLS 证书校验（自签名目标用）",
			},
		}),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				VulnClass   string `json:"vulnclass"`
				URL         string `json:"url"`
				Param       string `json:"param"`
				Payload     string `json:"payload"`
				WaitSeconds int    `json:"wait_seconds"`
				Insecure    bool   `json:"insecure"`
			}
			if err := json.Unmarshal(in, &a); err != nil {
				return actool.Errorf(fmt.Sprintf("参数解析失败: %v", err)), nil
			}
			vc := db.NormalizeVulnClass(a.VulnClass)
			if strings.TrimSpace(a.URL) == "" || strings.TrimSpace(a.Param) == "" {
				return actool.Errorf("url 与 param 必填"), nil
			}
			var runner string
			switch vc {
			case "RCE", "注入", "命令注入", "代码注入":
				runner = "rce"
			case "XSS":
				runner = "xss"
			case "SSRF":
				runner = "ssrf"
			default:
				return actool.Errorf(fmt.Sprintf("类别 %q（归一自 %q）暂无自动 validator；当前支持 RCE/注入/XSS/SSRF。其余类别请用独立复现意图补证据", vc, a.VulnClass)), nil
			}

			client, err := t.buildHTTPClient(nil, false, a.Insecure, 30*time.Second)
			if err != nil {
				return actool.Errorf(fmt.Sprintf("构建探针客户端失败: %v", err)), nil
			}

			token := validators.NewToken()
			var res *validators.Result
			switch runner {
			case "rce":
				res = validators.RunRCE(ctx, client, a.URL, a.Param, token)
			case "xss":
				res = validators.RunXSS(ctx, client, a.URL, a.Param, token, validators.XSSOptions{
					Browser:  true,
					ProxyURL: t.egressProxy,
				})
			case "ssrf":
				res = t.runSSRFValidate(ctx, client, a.URL, a.Param, token, a.WaitSeconds)
			}

			out, _ := json.Marshal(map[string]any{
				"class":   res.Class,
				"verdict": string(res.Verdict),
				"token":   res.Token,
				"marker":  res.Marker,
				"probes":  res.Probes,
				"note":    res.Note,
				"hint":    hintFor(res),
			})
			return actool.Text(string(out)), nil
		})
}

func hintFor(res *validators.Result) string {
	switch res.Verdict {
	case validators.VerdictPass:
		return "把证据标记 " + res.Marker + " 原样写进 report_finding 的 evidence（机验闭环），并把探针结果摘要并入证据描述。"
	case validators.VerdictWarn:
		return "部分信号确认但缺执行级证据：" + res.Note + " 可用浏览器 MCP/带外手段补强后再上报。"
	default:
		return "本组探针未命中（不代表漏洞不存在）：换注入上下文/编码方式重试，或用独立复现意图补人工证据。"
	}
}

// runSSRFValidate 把 listener 回连通道接到 validators.RunSSRF（工具层职责：
// 起临时监听、解析回连地址、按 token 查会话 Preview，验证完即停）。
// 监听不可用时不阻断——OOB 探针跳过，响应型探针照跑。
func (t *ToolSet) runSSRFValidate(ctx context.Context, client *http.Client, targetURL, param, token string, waitSeconds int) *validators.Result {
	wait := 8 * time.Second
	if waitSeconds > 0 {
		wait = time.Duration(min(max(waitSeconds, 3), 30)) * time.Second
	}
	name := "ssrf-val-" + token
	if listenerMgr == nil {
		return validators.RunSSRF(ctx, client, targetURL, param, token, validators.SSRFOOB{
			Note: "回连监听器不可用，OOB 探针跳过，仅跑响应型探针。",
		})
	}
	ln, err := listenerMgr.Start(name, 0)
	if err != nil {
		return validators.RunSSRF(ctx, client, targetURL, param, token, validators.SSRFOOB{
			Note: "临时监听启动失败（" + err.Error() + "），仅跑响应型探针",
		})
	}
	defer listenerMgr.Stop(name)
	cb := resolveConnectBack(ln.Port)
	cbBase := "http://" + cb.LHOST + ":" + strconv.Itoa(ln.Port)
	return validators.RunSSRF(ctx, client, targetURL, param, token, validators.SSRFOOB{
		Base: cbBase,
		Wait: wait,
		WaitOOB: func(tok string, timeout time.Duration) bool {
			deadline := time.Now().Add(timeout)
			for time.Now().Before(deadline) {
				if sessions, ok := listenerMgr.Get(name); ok {
					for _, s := range sessions {
						if strings.Contains(s.Preview, tok) {
							return true
						}
					}
				}
				time.Sleep(500 * time.Millisecond)
			}
			return false
		},
	})
}
