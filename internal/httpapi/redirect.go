package httpapi

import (
	"net/url"
	"strings"
)

// SafeReturnPath returns a relative path or "/" if invalid.
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

// ReturnURL builds the post-login redirect target.
// When host is empty or equals authHost, returns a relative path (stays on AUTH_HOST).
// Otherwise returns an absolute https URL to the validated return host.
func ReturnURL(path, host, authHost string) string {
	path = SafeReturnPath(path)
	host = strings.ToLower(strings.TrimSpace(host))
	authHost = strings.ToLower(strings.TrimSpace(authHost))
	if host == "" || host == authHost {
		return path
	}
	return "https://" + host + path
}
