package httpapi

import "testing"

func TestEncodeDecodeState(t *testing.T) {
	raw, err := encodeState("/admin/")
	if err != nil {
		t.Fatal(err)
	}
	st, err := decodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	if st.Return != "/admin/" {
		t.Fatalf("return=%q", st.Return)
	}
	if st.Nonce == "" {
		t.Fatal("missing nonce")
	}
}

func TestDecodeStateRejectsExternalReturn(t *testing.T) {
	// Craft payload with external URL; decode must sanitize.
	raw, err := encodeState("https://evil.example/phish")
	if err != nil {
		t.Fatal(err)
	}
	st, err := decodeState(raw)
	if err != nil {
		t.Fatal(err)
	}
	if st.Return != "/" {
		t.Fatalf("expected sanitized /, got %q", st.Return)
	}
}

func TestDecodeStateInvalid(t *testing.T) {
	if _, err := decodeState("not-valid"); err == nil {
		t.Fatal("expected error")
	}
}
