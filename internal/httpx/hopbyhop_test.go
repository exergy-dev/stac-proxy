package httpx

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
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
		assert.Empty(t, h.Get(name), "%s not stripped", name)
	}
	assert.Equal(t, "application/json", h.Get("Content-Type"), "Content-Type (end-to-end) was incorrectly stripped")
}

func TestStripHopByHopHeaders_StripsConnectionNamed(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "X-Custom-1, X-Custom-2")
	h.Set("X-Custom-1", "a")
	h.Set("X-Custom-2", "b")
	h.Set("X-Keep", "keep")

	StripHopByHopHeaders(h)

	assert.Empty(t, h.Get("X-Custom-1"), "X-Custom-1 not stripped")
	assert.Empty(t, h.Get("X-Custom-2"), "X-Custom-2 not stripped")
	assert.Empty(t, h.Get("Connection"), "Connection not stripped")
	assert.Equal(t, "keep", h.Get("X-Keep"), "end-to-end X-Keep incorrectly stripped")
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

	assert.Equal(t, first.Get("Content-Type"), h.Get("Content-Type"), "Content-Type changed")
	assert.Equal(t, first.Get("X-Trace-Id"), h.Get("X-Trace-Id"), "X-Trace-Id changed")
	assert.Empty(t, h.Get("Connection"), "Connection reappeared")
}

func TestStripHopByHopHeaders_NilSafe(t *testing.T) {
	// Should not panic.
	StripHopByHopHeaders(nil)
}

func TestStripHopByHopHeaders_StripsForwarded(t *testing.T) {
	h := http.Header{}
	h.Set("Forwarded", "for=192.0.2.60;proto=http;by=203.0.113.43")
	h.Set("Content-Type", "application/json")

	StripHopByHopHeaders(h)

	assert.Empty(t, h.Get("Forwarded"), "RFC 7239 Forwarded header not stripped")
	assert.Equal(t, "application/json", h.Get("Content-Type"), "end-to-end Content-Type incorrectly stripped")
}
