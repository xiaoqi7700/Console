package traffic

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Sample rendering. Every hit leaves the scanner through renderIdentitySample:
// the matched span is replaced by <term:ID> (the term ID is enough to look the
// rule up), the surrounding context is capped, and credential-shaped values in
// that context are masked. stdout and --out JSON share this one function so the
// two output paths cannot diverge.

const (
	identitySampleRadius  = 32
	identitySampleRunes   = 160
	identitySampleUnknown = "<redacted>"
)

var (
	identityHeaderRe = regexp.MustCompile(`(?im)(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*[^\r\n]*`)
	identityKVRe     = regexp.MustCompile(`(?i)["']?(authorization|proxy-authorization|x-api-key|x-auth-token|password|passwd|pwd|secret|token|api[_-]?key|session(?:[_-]?id)?|csrf)["']?\s*[=:]\s*["']?[^&\s"',}]+`)
	identityJWTRe    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	identityHexRe    = regexp.MustCompile(`\b[A-Fa-f0-9]{32,}\b`)
	identityB64Re    = regexp.MustCompile(`\b[A-Za-z0-9+/]{40,}={0,2}`)
	identityEmailRe  = regexp.MustCompile(`\b([A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]*@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`)
	identityUserRe   = regexp.MustCompile(`(?i)(://)[^/@\s:]+:[^/@\s]+@`)
)

func renderIdentitySample(text string, start, end int, termID string) string {
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	if end > len(text) {
		end = len(text)
	}
	if start > len(text) {
		start = len(text)
	}
	from := start - identitySampleRadius
	if from < 0 {
		from = 0
	}
	// Extend to the start of the line containing the window edge (bounded) so an
	// Authorization or Cookie value whose beginning lies outside the ±32-byte
	// window can still be recognised and masked as a whole.
	if line := identityLineStart(text, from, identitySampleRadius*8); line < from {
		from = line
	}
	for from < start && !utf8.RuneStart(text[from]) {
		from++
	}
	to := end + identitySampleRadius
	if to > len(text) {
		to = len(text)
	}
	if line := identityLineEnd(text, to, identitySampleRadius*8); line > to {
		to = line
	}
	for to > end && to < len(text) && !utf8.RuneStart(text[to]) {
		to--
	}
	snippet := text[from:start] + "<" + termID + ">" + text[end:to]
	snippet = maskIdentitySample(snippet)
	snippet = identityTruncateAround(snippet, "<"+termID+">", identitySampleRunes)
	return escapeIdentitySnippet(snippet)
}

func identityLineStart(text string, at, maxBack int) int {
	if at <= 0 {
		return 0
	}
	limit := at - maxBack
	if limit < 0 {
		limit = 0
	}
	if i := strings.LastIndexByte(text[limit:at], '\n'); i >= 0 {
		return limit + i + 1
	}
	if limit == 0 {
		return 0
	}
	return at
}

func identityLineEnd(text string, at, maxForward int) int {
	if at >= len(text) {
		return len(text)
	}
	limit := at + maxForward
	if limit > len(text) {
		limit = len(text)
	}
	if i := strings.IndexByte(text[at:limit], '\n'); i >= 0 {
		return at + i
	}
	if limit >= len(text) {
		return len(text)
	}
	return at
}

func identityTruncateAround(s, marker string, max int) string {
	runes := []rune(s)
	if max <= 0 || len(runes) <= max {
		return s
	}
	mi := strings.Index(s, marker)
	if mi < 0 {
		return string(runes[:max-1]) + "…"
	}
	pre := utf8.RuneCountInString(s[:mi])
	markerWidth := utf8.RuneCountInString(marker)
	start := pre - (max-markerWidth)/2
	if start < 0 {
		start = 0
	}
	end := start + max
	if end > len(runes) {
		end = len(runes)
		start = end - max
		if start < 0 {
			start = 0
		}
	}
	out := string(runes[start:end])
	if start > 0 {
		out = "…" + out
	}
	if end < len(runes) {
		out += "…"
	}
	return out
}

func maskIdentitySample(s string) string {
	s = identityHeaderRe.ReplaceAllString(s, `${1}: <redacted>`)
	s = identityKVRe.ReplaceAllString(s, `${1}=<redacted>`)
	s = identityJWTRe.ReplaceAllString(s, `<jwt>`)
	s = identityHexRe.ReplaceAllStringFunc(s, maskKeepEnds)
	s = identityB64Re.ReplaceAllStringFunc(s, maskKeepEnds)
	s = identityEmailRe.ReplaceAllString(s, `${1}***@${2}`)
	s = identityUserRe.ReplaceAllString(s, `${1}<redacted>@`)
	return s
}

func maskKeepEnds(v string) string {
	if len(v) <= 8 {
		return identitySampleUnknown
	}
	return v[:4] + "***" + v[len(v)-4:]
}

func escapeIdentitySnippet(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
