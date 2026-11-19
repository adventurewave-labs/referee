package labels

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxVariants bounds the decode fan-out so adversarial inputs cannot blow up
// the containment matcher.
const maxVariants = 64

// Decodings returns the argument value plus every successfully decoded
// variant of it (URL-encoding — iterated, base64 standard/unpadded/URL forms,
// hex, JSON/unicode escapes). Encoded secrets still match: the containment
// matcher runs over all variants (PRD §5.1).
func Decodings(s string) []string {
	out := map[string]struct{}{s: {}}
	frontier := []string{s}
	// two bounded rounds: catches url(base64(x)) style double encodings
	for round := 0; round < 2 && len(frontier) > 0; round++ {
		var next []string
		for _, v := range frontier {
			for _, d := range decodeOnce(v) {
				if _, seen := out[d]; !seen && len(out) < maxVariants {
					out[d] = struct{}{}
					next = append(next, d)
				}
			}
		}
		frontier = next
	}
	res := make([]string, 0, len(out))
	for v := range out {
		res = append(res, v)
	}
	return res
}

// decodeOnce applies each single-round decoding to v.
func decodeOnce(v string) []string {
	var out []string
	add := func(d string) {
		if d != "" && d != v && utf8.ValidString(d) && len(out) < maxVariants {
			out = append(out, d)
		}
	}

	// URL decoding, iterated here once per call (loop unrolls across rounds)
	if strings.ContainsAny(v, "%+") {
		if d, err := url.QueryUnescape(v); err == nil {
			add(d)
		}
		if d, err := url.PathUnescape(v); err == nil {
			add(d)
		}
	}

	// base64: standard, raw (unpadded), URL, raw-URL — decode when valid
	if looksBase64(v) {
		for _, enc := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding,
			base64.URLEncoding, base64.RawURLEncoding,
		} {
			if d, err := enc.DecodeString(v); err == nil && len(d) > 0 {
				add(string(d))
			}
		}
	}

	// hex (even length, hex alphabet)
	if looksHex(v) {
		if d, err := hex.DecodeString(v); err == nil && len(d) > 0 {
			add(string(d))
		}
	}

	// encoded blobs embedded in prose ("attach <base64>", "key=<hex>"):
	// decode each separator-delimited field on its own, bounded.
	for _, f := range embeddedFields(v) {
		if looksBase64(f) {
			for _, enc := range []*base64.Encoding{
				base64.StdEncoding, base64.RawStdEncoding,
				base64.URLEncoding, base64.RawURLEncoding,
			} {
				if d, err := enc.DecodeString(f); err == nil && len(d) > 0 {
					add(string(d))
				}
			}
		}
		if looksHex(f) {
			if d, err := hex.DecodeString(f); err == nil && len(d) > 0 {
				add(string(d))
			}
		}
	}

	// JSON string escapes: if the value is a quoted JSON string, unquote it
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' && strings.ContainsRune(v, '\\') {
		if u, err := strconv.Unquote(v); err == nil {
			add(u)
		}
	}

	// bare unicode escapes (\uXXXX) anywhere in the string
	if strings.Contains(v, `\u`) {
		if u, changed := unescapeUnicode(v); changed {
			add(u)
		}
	}

	// bare backslash escapes commonly seen in JSON-embedded args (\n \" \\ \t)
	if strings.Contains(v, `\`) {
		if u, changed := unescapeSimple(v); changed {
			add(u)
		}
	}
	return out
}

// maxFields bounds how many embedded fields one value is split into.
const maxFields = 32

// embeddedFields splits v on whitespace and common delimiters, returning the
// fields long enough to carry an encoded blob (and only when v actually has
// more than one field — the whole value is decoded separately).
func embeddedFields(v string) []string {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ':', ',', ';', '"', '\'', '(', ')', '[', ']', '{', '}', '<', '>':
			return true
		}
		return false
	})
	if len(fields) < 2 {
		return nil
	}
	var out []string
	for _, f := range fields {
		// key=value: the value side is the candidate blob
		if i := strings.IndexByte(f, '='); i > 0 && i < len(f)-1 {
			f = f[i+1:]
		}
		if len(f) >= 8 {
			out = append(out, f)
			if len(out) >= maxFields {
				break
			}
		}
	}
	return out
}

func looksBase64(v string) bool {
	if len(v) < 8 || len(v)%4 == 1 {
		return false
	}
	for _, c := range v {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '+', c == '/', c == '-', c == '_', c == '=':
		default:
			return false
		}
	}
	return true
}

func looksHex(v string) bool {
	if len(v) < 8 || len(v)%2 != 0 {
		return false
	}
	for _, c := range v {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// unescapeUnicode rewrites \uXXXX sequences (case-insensitive hex) to runes.
func unescapeUnicode(s string) (string, bool) {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); {
		if s[i] == '\\' && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') {
			if cp, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
				b.WriteRune(rune(cp))
				i += 6
				changed = true
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String(), changed
}

// unescapeSimple handles \n \t \r \" \\ \xNN without strconv.Unquote's
// strict quoting requirements.
func unescapeSimple(s string) (string, bool) {
	var b strings.Builder
	changed := false
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		switch s[i+1] {
		case 'n':
			b.WriteByte('\n')
			i += 2
			changed = true
		case 't':
			b.WriteByte('\t')
			i += 2
			changed = true
		case 'r':
			b.WriteByte('\r')
			i += 2
			changed = true
		case '"':
			b.WriteByte('"')
			i += 2
			changed = true
		case '\\':
			b.WriteByte('\\')
			i += 2
			changed = true
		case 'x':
			if i+3 < len(s) {
				if n, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
					b.WriteByte(byte(n))
					i += 4
					changed = true
					continue
				}
			}
			b.WriteByte(s[i])
			i++
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String(), changed
}

// NormalizeForMatch collapses case and whitespace runs so fuzzy containment
// tolerates reformatting that preserves content.
func NormalizeForMatch(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range strings.ToLower(s) {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}
