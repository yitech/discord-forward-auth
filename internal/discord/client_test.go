package discord

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestExchangeCodeRetriesTransientTransportError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("hijack unsupported")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600,"scope":"identify"}`)
	}))
	defer srv.Close()

	c := testClient(srv)
	tok, err := c.ExchangeCode(context.Background(), "code1")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if tok.AccessToken != "tok" {
		t.Fatalf("token=%q", tok.AccessToken)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestExchangeCodeDoesNotRetryAPIError(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	c := testClient(srv)
	_, err := c.ExchangeCode(context.Background(), "code1")
	if !errors.Is(err, ErrAPI) {
		t.Fatalf("err=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls=%d want 1", calls.Load())
	}
}

func testClient(srv *httptest.Server) *Client {
	return &Client{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURI:  "https://auth.example.com/_oauth",
		HTTP: &http.Client{
			Timeout: 5 * time.Second,
			Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				req = req.Clone(req.Context())
				req.URL.Scheme = "http"
				req.URL.Host = srv.Listener.Addr().String()
				req.Host = req.URL.Host
				return http.DefaultTransport.RoundTrip(req)
			}),
		},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
