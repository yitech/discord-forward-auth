package httpapi

import (
	"net/url"
	"strings"
)

// SafeReturnPath returns a same-origin relative path or "/" if invalid.
// Rejects scheme-relative, absolute, and protocol-relative URLs.
func SafeReturnPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	if strings.HasPrefix(raw, "//") {
		return "/"
	}
	if strings.Contains(raw, "://") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	if u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	path := u.RequestURI()
	if path == "" || !strings.HasPrefix(path, "/") {
		return "/"
	}
	return path
}
