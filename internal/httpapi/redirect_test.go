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
