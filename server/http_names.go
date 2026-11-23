package server

import (
	"net/url"
	"strings"
)

// attachmentDisposition 生成既能被老客户端解析、又能正确携带中文名的
// Content-Disposition 头。filename= 里只放 ASCII 兜底（非 ASCII 换成 _），
// 原始名字走 RFC 5987 的 filename*（UTF-8 百分号编码），避免下载名显示成乱码。
func attachmentDisposition(name string) string {
	if name == "" {
		name = "download"
	}
	ascii := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, name)
	if ascii == "" || ascii == "_" {
		ascii = "download"
	}
	if ascii == name {
		return `attachment; filename="` + ascii + `"`
	}
	return `attachment; filename="` + ascii + `"; filename*=UTF-8''` + url.PathEscape(name)
}
