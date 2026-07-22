package httpapi

import "testing"

func TestSafeReturnPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "/"},
		{"/admin/", "/admin/"},
		{"/app?x=1", "/app?x=1"},
		{"https://evil.com/", "/"},
		{"http://evil.com/x", "/"},
		{"//evil.com/x", "/"},
		{"/ok", "/ok"},
		{"relative", "/"},
		{"  /dash  ", "/dash"},
	}
	for _, tc := range cases {
		got := SafeReturnPath(tc.in)
		if got != tc.want {
			t.Fatalf("SafeReturnPath(%q)=%q want %q", tc.in, got, tc.want)
		}
	}
}

func TestReturnURL(t *testing.T) {
	cases := []struct {
		path, host, auth, want string
	}{
		{"/admin/", "", "auth.example.com", "/admin/"},
		{"/admin/", "auth.example.com", "auth.example.com", "/admin/"},
		{"/secret", "app.example.com", "auth.example.com", "https://app.example.com/secret"},
		{"https://evil.com", "app.example.com", "auth.example.com", "https://app.example.com/"},
	}
	for _, tc := range cases {
		got := ReturnURL(tc.path, tc.host, tc.auth)
		if got != tc.want {
			t.Fatalf("ReturnURL(%q,%q,%q)=%q want %q", tc.path, tc.host, tc.auth, got, tc.want)
		}
	}
}
