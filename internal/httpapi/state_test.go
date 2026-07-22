package httpapi

import (
	"testing"

	"github.com/yitech/discord-forward-auth/internal/config"
)

func testStateCfg() *config.Config {
	return &config.Config{
		AuthHost:     "auth.example.com",
		CookieDomain: ".example.com",
	}
}

func TestEncodeDecodeState(t *testing.T) {
	raw, err := encodeState("/admin/", "app.example.com")
	if err != nil {
		t.Fatal(err)
	}
	st, err := decodeState(raw, testStateCfg())
	if err != nil {
		t.Fatal(err)
	}
	if st.Return != "/admin/" {
		t.Fatalf("return=%q", st.Return)
	}
	if st.Host != "app.example.com" {
		t.Fatalf("host=%q", st.Host)
	}
	if st.Nonce == "" {
		t.Fatal("missing nonce")
	}
}

func TestDecodeStateRejectsExternalReturn(t *testing.T) {
	raw, err := encodeState("https://evil.example/phish", "")
	if err != nil {
		t.Fatal(err)
	}
	st, err := decodeState(raw, testStateCfg())
	if err != nil {
		t.Fatal(err)
	}
	if st.Return != "/" {
		t.Fatalf("expected sanitized /, got %q", st.Return)
	}
}

func TestDecodeStateRejectsDisallowedHost(t *testing.T) {
	raw, err := encodeState("/x", "evil.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeState(raw, testStateCfg()); err == nil {
		t.Fatal("expected disallowed host error")
	}
}

func TestDecodeStateInvalid(t *testing.T) {
	if _, err := decodeState("not-valid", testStateCfg()); err == nil {
		t.Fatal("expected error")
	}
}
