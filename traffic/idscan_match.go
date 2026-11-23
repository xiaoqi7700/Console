package traffic

import "bytes"

// foldASCII returns a lowercased copy of s. Folding is byte-for-byte length
// preserving and only touches A-Z, so offsets found in the folded copy address
// the original text directly. Non-ASCII bytes (including CJK) are untouched.
func foldASCII(s string) []byte {
	b := []byte(s)
	foldASCIIInPlace(b)
	return b
}

func foldASCIIInPlace(b []byte) {
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
}

// identityFind returns the first accepted match offset, or -1.
func identityFind(hay, pat []byte, boundary bool) int {
	if len(pat) == 0 || len(pat) > len(hay) {
		return -1
	}
	pos := 0
	for pos <= len(hay)-len(pat) {
		i := bytes.Index(hay[pos:], pat)
		if i < 0 {
			return -1
		}
		start := pos + i
		end := start + len(pat)
		if !boundary || identityBoundaryOK(hay, start, end) {
			return start
		}
		pos = start + 1
	}
	return -1
}

// identityBoundaryOK enforces an ASCII identifier-like boundary. Underscore is
// deliberately not a boundary byte: env prefixes such as POJUN_WORKER_CHAT are
// brand evidence, not a word continuation.
func identityBoundaryOK(hay []byte, start, end int) bool {
	if start > 0 && isIdentityWordByte(hay[start-1]) {
		return false
	}
	if end < len(hay) && isIdentityWordByte(hay[end]) {
		return false
	}
	return true
}

func isIdentityWordByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}
