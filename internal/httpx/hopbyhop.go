package httpx

import (
	"net/http"
	"strings"
)

// hopByHopHeaders are connection-scoped headers that MUST NOT be
// forwarded across a proxy (RFC 7230 §6.1). Proxy-Connection is not
// in the RFC but is commonly emitted by misbehaving clients and must
// also be stripped. Forwarded (RFC 7239) is included so we don't
// pass through a chain whose values reflect the inbound edge rather
// than what we choose to advertise (the server's clientIPMiddleware
// sets X-Forwarded-* / Forwarded as appropriate).
var hopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
	"Forwarded",
}

// StripHopByHopHeaders removes RFC 7230 §6.1 hop-by-hop headers
// (Connection, Keep-Alive, Proxy-Authenticate, Proxy-Authorization,
// Te, Trailer, Transfer-Encoding, Upgrade) plus any extra headers
// named in h.Get("Connection"). Also removes Proxy-Connection and
// the RFC 7239 Forwarded header. Idempotent.
func StripHopByHopHeaders(h http.Header) {
	if h == nil {
		return
	}
	// Read the Connection header first; the loop below will remove it.
	if conn := h.Get("Connection"); conn != "" {
		for _, name := range strings.Split(conn, ",") {
			n := strings.TrimSpace(name)
			if n != "" {
				h.Del(n)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}
