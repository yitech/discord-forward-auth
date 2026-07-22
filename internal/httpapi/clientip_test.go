package httpapi

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	t.Parallel()

	req := func(remote string, headers map[string]string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: make(http.Header)}
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}

	cases := []struct {
		name string
		r    *http.Request
		want string
	}{
		{"xff first hop", req("10.0.0.1:1234", map[string]string{"X-Forwarded-For": "203.0.113.9, 10.0.0.1"}), "203.0.113.9"},
		{"xff trim", req("10.0.0.1:1234", map[string]string{"X-Forwarded-For": " 198.51.100.2 "}), "198.51.100.2"},
		{"x-real-ip", req("10.0.0.1:1234", map[string]string{"X-Real-IP": "198.51.100.3"}), "198.51.100.3"},
		{"remote host:port", req("127.0.0.1:54321", nil), "127.0.0.1"},
		{"remote bare", req("127.0.0.1", nil), "127.0.0.1"},
		{"nil", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientIP(tc.r); got != tc.want {
				t.Fatalf("clientIP()=%q want %q", got, tc.want)
			}
		})
	}
}
