package hostpolicy

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/yitech/discord-forward-auth/internal/authz"
	"github.com/yitech/discord-forward-auth/internal/config"
)

var ErrNotFound = errors.New("host policy not found")

var ErrInvalid = errors.New("host and required_groups required")

var ErrInvalidPattern = errors.New("invalid host pattern")

type Policy struct {
	Host           string    `json:"host"`
	RequiredGroups []string  `json:"required_groups"`
	UpdatedAt      time.Time `json:"updated_at"`
	UpdatedBy      *string   `json:"updated_by,omitempty"`
}

type Store interface {
	List(ctx context.Context) ([]Policy, error)
	Get(ctx context.Context, host string) (*Policy, error)
	Match(ctx context.Context, host string) (*Policy, error)
	Upsert(ctx context.Context, host string, requiredGroups []string, updatedBy string) error
	Delete(ctx context.Context, host string) error
}

// NormalizeGroups trims, dedupes, and sorts group names (case preserved).
func NormalizeGroups(groups []string) []string {
	seen := make(map[string]struct{}, len(groups))
	var out []string
	for _, g := range groups {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// NormalizePattern lowercases and strips a trailing port, preserving a leading "*.".
func NormalizePattern(pattern string) string {
	return config.NormalizeHost(pattern)
}

// ValidatePattern accepts an exact DNS hostname or a single leading "*.hostname".
func ValidatePattern(pattern string) error {
	pattern = NormalizePattern(pattern)
	if pattern == "" {
		return ErrInvalidPattern
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		if suffix == "" || strings.Contains(suffix, "*") || !isDNSHostname(suffix) {
			return ErrInvalidPattern
		}
		return nil
	}
	if strings.Contains(pattern, "*") || !isDNSHostname(pattern) {
		return ErrInvalidPattern
	}
	return nil
}

// MatchHost reports whether pattern matches host.
// Exact patterns require equality. "*.example.com" matches a single label
// under example.com (grafana.example.com), not the apex or deeper subdomains.
func MatchHost(pattern, host string) bool {
	pattern = NormalizePattern(pattern)
	host = config.NormalizeHost(host)
	if pattern == "" || host == "" {
		return false
	}
	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}
	suffix := pattern[1:] // ".example.com"
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	prefix := strings.TrimSuffix(host, suffix)
	if prefix == "" || strings.Contains(prefix, ".") {
		return false
	}
	return isDNSLabel(prefix)
}

// BestMatch returns the most specific policy matching host.
// Exact hosts beat wildcards; among wildcards, longer fixed suffixes win.
// Equal specificity breaks ties by lexicographically smaller pattern.
func BestMatch(host string, policies []Policy) (*Policy, bool) {
	host = config.NormalizeHost(host)
	if host == "" || len(policies) == 0 {
		return nil, false
	}
	bestIdx := -1
	bestScore := -1
	for i := range policies {
		if !MatchHost(policies[i].Host, host) {
			continue
		}
		score := specificity(policies[i].Host)
		if bestIdx < 0 || score > bestScore || (score == bestScore && policies[i].Host < policies[bestIdx].Host) {
			bestIdx = i
			bestScore = score
		}
	}
	if bestIdx < 0 {
		return nil, false
	}
	cp := policies[bestIdx]
	cp.RequiredGroups = append([]string(nil), cp.RequiredGroups...)
	if cp.UpdatedBy != nil {
		v := *cp.UpdatedBy
		cp.UpdatedBy = &v
	}
	return &cp, true
}

func specificity(pattern string) int {
	pattern = NormalizePattern(pattern)
	if strings.HasPrefix(pattern, "*.") {
		return labelCount(pattern[2:])
	}
	// Exact always outranks any wildcard.
	return 1000 + labelCount(pattern)
}

func labelCount(host string) int {
	if host == "" {
		return 0
	}
	return strings.Count(host, ".") + 1
}

func isDNSHostname(host string) bool {
	if host == "" || len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !isDNSLabel(label) {
			return false
		}
	}
	return true
}

func isDNSLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if r > unicode.MaxASCII {
			return false
		}
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// Allowed reports whether sessionGroups may access host.
// Empty host or AUTH_HOST skips host ACL. Admin group always bypasses.
// When hasPolicy is false for any other host, access is denied (fail-closed).
func Allowed(host, authHost, adminGroup string, sessionGroups []string, policy *Policy, hasPolicy bool) bool {
	if authz.HasGroup(sessionGroups, adminGroup) {
		return true
	}
	host = config.NormalizeHost(host)
	if host == "" || host == config.NormalizeHost(authHost) {
		return true
	}
	if !hasPolicy || policy == nil {
		return false
	}
	for _, g := range sessionGroups {
		if authz.HasGroup(policy.RequiredGroups, g) {
			return true
		}
	}
	return false
}
