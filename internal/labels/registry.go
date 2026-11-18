package labels

import (
	"path/filepath"
	"strings"
)

// SourceKind enumerates where a block came from; the registry maps each kind
// to its default labels (PRD §5.1 sources).
type SourceKind string

const (
	KindOperator   SourceKind = "operator"   // trusted / normal
	KindUser       SourceKind = "user"       // semi-trusted / normal (configurable)
	KindToolResult SourceKind = "tool-result" // untrusted / normal
	KindWeb        SourceKind = "web"        // untrusted / normal
	KindRAG        SourceKind = "rag"        // untrusted / normal
	KindFile       SourceKind = "file-read"  // trust AND sensitivity by path policy
)

// PathRule assigns labels to file reads under a glob pattern. Secrets dirs
// label content high; trust is likewise per-path (PRD §5.1).
type PathRule struct {
	Pattern     string
	Trust       Trust
	Sensitivity Sensitivity
}

// Registry is the source registry: default labels per source kind plus the
// path policy that classifies file reads.
type Registry struct {
	OperatorTrust       Trust
	OperatorSensitivity Sensitivity
	UserTrust           Trust
	UserSensitivity     Sensitivity
	ToolResultTrust     Trust
	ToolResultSens      Sensitivity
	WebTrust            Trust
	WebSens             Sensitivity
	RAGTrust            Trust
	RAGSens             Sensitivity
	FileDefaultTrust    Trust
	FileDefaultSens     Sensitivity
	PathRules           []PathRule
}

// Default returns the registry with the PRD §5.1 defaults.
func Default() *Registry {
	return &Registry{
		OperatorTrust:       TrustTrusted,
		OperatorSensitivity: SensNormal,
		UserTrust:           TrustSemi,
		UserSensitivity:     SensNormal,
		ToolResultTrust:     TrustUntrusted,
		ToolResultSens:      SensNormal,
		WebTrust:            TrustUntrusted,
		WebSens:             SensNormal,
		RAGTrust:            TrustUntrusted,
		RAGSens:             SensNormal,
		FileDefaultTrust:    TrustUntrusted,
		FileDefaultSens:     SensNormal,
	}
}

// ForKind returns the default (trust, sensitivity) for a source kind.
func (r *Registry) ForKind(kind SourceKind) (Trust, Sensitivity) {
	switch kind {
	case KindOperator:
		return r.OperatorTrust, r.OperatorSensitivity
	case KindUser:
		return r.UserTrust, r.UserSensitivity
	case KindToolResult:
		return r.ToolResultTrust, r.ToolResultSens
	case KindWeb:
		return r.WebTrust, r.WebSens
	case KindRAG:
		return r.RAGTrust, r.RAGSens
	case KindFile:
		return r.FileDefaultTrust, r.FileDefaultSens
	}
	return TrustUntrusted, SensNormal
}

// ForPath labels a file read by path policy; the most specific matching
// pattern wins (longest pattern), falling back to the file-read defaults.
func (r *Registry) ForPath(path string) (Trust, Sensitivity) {
	best := -1
	trust, sens := r.FileDefaultTrust, r.FileDefaultSens
	for i, rule := range r.PathRules {
		if !GlobMatch(rule.Pattern, filepath.ToSlash(path)) {
			continue
		}
		if best == -1 || len(rule.Pattern) > len(r.PathRules[best].Pattern) {
			best = i
			trust, sens = rule.Trust, rule.Sensitivity
		}
	}
	return trust, sens
}

// GlobMatch reports whether s matches a shell-style pattern where
//   ** matches any sequence including path separators,
//   *  matches any sequence except path separators,
//   ?  matches any single character.
// It lives here (not caps) because both path policy and capability scopes
// share the exact same semantics.
func GlobMatch(pattern, s string) bool {
	return globMatch(pattern, s)
}

func globMatch(pattern, s string) bool {
	// Iterative two-pointer matcher with ** fallback.
	var p, i int
	starP, starI := -1, -1
	for i < len(s) {
		if p < len(pattern) {
			if pattern[p] == '*' {
				if p+1 < len(pattern) && pattern[p+1] == '*' {
					// "**" — consume both, match any remainder including '/'
					if p+2 == len(pattern) {
						return true
					}
					// try matching the rest at every position
					for j := i; j <= len(s); j++ {
						if globMatch(pattern[p+2:], s[j:]) {
							return true
						}
					}
					return false
				}
				// single '*' — any run not containing '/'
				starP, starI = p, i
				p++
				continue
			}
			if pattern[p] == '?' || pattern[p] == s[i] {
				p++
				i++
				continue
			}
		}
		if starP >= 0 {
			// backtrack: let the last '*' absorb one more char (not '/')
			starI++
			if starI > len(s) || s[starI-1] == '/' {
				return false
			}
			i = starI
			p = starP + 1
			continue
		}
		return false
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// NormalizePath expands a leading "~/" for path-policy comparisons.
func NormalizePath(p string) string {
	p = filepath.ToSlash(p)
	if strings.HasPrefix(p, "~/") {
		p = strings.TrimPrefix(p, "~/")
	}
	return p
}
