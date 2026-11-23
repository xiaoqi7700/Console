package agent

// 后台作业（job_*）子进程的代理环境拼接。
//
// 为什么需要单独一层：POSIX 下重复环境变量以**第一条**为准，直接把
// proxyEnv 的结果 append 到 os.Environ() 后面，子进程仍会读到宿主/服务
// 进程继承来的旧代理值——那等于出口没换。所以必须先把同名键从 base 里
// 剔除，再追加平台出口。

import "strings"

// proxyEnvKeys 是 proxyEnv 会写出的全部键。
var proxyEnvKeys = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
	"ALL_PROXY", "all_proxy", "NODE_USE_ENV_PROXY",
	"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE",
	"GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS",
	"EGRESS_PROXY", "EGRESS_PROXY_CA",
}

// mergeProxyEnv 用平台出口代理覆盖 base（通常是 os.Environ()）。proxyAddr 为空
// 时原样返回 base —— 保持「未配置代理 = 直连、不动父进程环境」的旧语义。
func mergeProxyEnv(base []string, proxyAddr, caCert string) []string {
	if proxyAddr == "" {
		return base
	}
	drop := make(map[string]bool, len(proxyEnvKeys))
	for _, k := range proxyEnvKeys {
		drop[k] = true
	}
	out := make([]string, 0, len(base)+len(proxyEnvKeys))
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i > 0 && drop[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	return append(out, proxyEnv(proxyAddr, caCert)...)
}
