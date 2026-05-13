package httpx

import (
	"net/http"
	"testing"
)

func TestStripHopByHopHeaders_StandardList(t *testing.T) {
	h := http.Header{}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization", "Te",
		"Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Set(name, "x")
	}
	h.Set("Content-Type", "application/json")

	StripHopByHopHeaders(h)

	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive",
		"Proxy-Authenticate", "Proxy-Authorization", "Te",
		"Trailer", "Transfer-Encoding", "Upgrade",
	} {
		if v := h.Get(name); v != "" {
			t.Errorf("%s not stripped: %q", name, v)
		}
	}
	if h.Get("Content-Type") != "application/json" {
		t.Error("Content-Type (end-to-end) was incorrectly stripped")
	}
}

func TestStripHopByHopHeaders_StripsConnectionNamed(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Custom-1, X-Custom-2")
	h.Set("X-Custom-1", "a")
	h.Set("X-Custom-2", "b")
	h.Set("X-Keep", "keep")

	StripHopByHopHeaders(h)

	if h.Get("X-Custom-1") != "" {
		t.Error("X-Custom-1 not stripped")
	}
	if h.Get("X-Custom-2") != "" {
		t.Error("X-Custom-2 not stripped")
	}
	if h.Get("Connection") != "" {
		t.Error("Connection not stripped")
	}
	if h.Get("X-Keep") != "keep" {
		t.Error("end-to-end X-Keep incorrectly stripped")
	}
}

func TestStripHopByHopHeaders_Idempotent(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "close")
	h.Set("Content-Type", "application/json")
	h.Set("X-Trace-Id", "abc")

	StripHopByHopHeaders(h)
	first := h.Clone()
	StripHopByHopHeaders(h)
	StripHopByHopHeaders(h)

	if got, want := h.Get("Content-Type"), first.Get("Content-Type"); got != want {
		t.Errorf("Content-Type changed: %q -> %q", want, got)
	}
	if got, want := h.Get("X-Trace-Id"), first.Get("X-Trace-Id"); got != want {
		t.Errorf("X-Trace-Id changed: %q -> %q", want, got)
	}
	if h.Get("Connection") != "" {
		t.Error("Connection reappeared")
	}
}

func TestStripHopByHopHeaders_PreservesEndToEnd(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("Content-Length", "42")
	h.Set("Authorization", "Bearer x")
	h.Set("X-Request-Id", "abc")

	StripHopByHopHeaders(h)

	if h.Get("Content-Type") != "application/json" {
		t.Error("Content-Type stripped")
	}
	if h.Get("Content-Length") != "42" {
		t.Error("Content-Length stripped")
	}
	if h.Get("Authorization") != "Bearer x" {
		t.Error("Authorization stripped")
	}
	if h.Get("X-Request-Id") != "abc" {
		t.Error("X-Request-Id stripped")
	}
}

func TestStripHopByHopHeaders_NilSafe(t *testing.T) {
	// Should not panic.
	StripHopByHopHeaders(nil)
}

func TestStripHopByHopHeaders_ConnectionWithWhitespaceAndEmpty(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", " X-A ,  ,X-B")
	h.Set("X-A", "1")
	h.Set("X-B", "2")

	StripHopByHopHeaders(h)

	if h.Get("X-A") != "" || h.Get("X-B") != "" {
		t.Error("whitespace-trimmed connection-named headers not stripped")
	}
}
