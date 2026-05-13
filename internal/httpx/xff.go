package httpx

import (
	"net"
	"net/http"
)

// SetXForwarded mirrors httputil.ProxyRequest.SetXForwarded semantics
// for non-ReverseProxy call sites. It:
//   - appends the client IP (derived from in.RemoteAddr) to any
//     existing X-Forwarded-For chain on out;
//   - sets X-Forwarded-Proto on out from in.TLS != nil (https/http),
//     OR preserves a non-empty inbound X-Forwarded-Proto on in if
//     present (trusted upstream took the TLS termination);
//   - sets X-Forwarded-Host on out from in.Host.
//
// The headers are taken from `in` (the inbound request) and written to
// `out` (the outbound request the caller is about to dispatch).
func SetXForwarded(out, in *http.Request) {
	if out == nil || in == nil {
		return
	}
	if out.Header == nil {
		out.Header = make(http.Header)
	}

	// X-Forwarded-For: append client IP to existing chain.
	if in.RemoteAddr != "" {
		clientIP, _, err := net.SplitHostPort(in.RemoteAddr)
		if err != nil {
			clientIP = in.RemoteAddr
		}
		if clientIP != "" {
			if prior := out.Header.Get("X-Forwarded-For"); prior != "" {
				out.Header.Set("X-Forwarded-For", prior+", "+clientIP)
			} else {
				out.Header.Set("X-Forwarded-For", clientIP)
			}
		}
	}

	// X-Forwarded-Proto: trust inbound header if set (set by upstream
	// edge), otherwise derive from in.TLS.
	if v := in.Header.Get("X-Forwarded-Proto"); v != "" {
		out.Header.Set("X-Forwarded-Proto", v)
	} else if in.TLS != nil {
		out.Header.Set("X-Forwarded-Proto", "https")
	} else {
		out.Header.Set("X-Forwarded-Proto", "http")
	}

	// X-Forwarded-Host: from the inbound Host.
	if in.Host != "" {
		out.Header.Set("X-Forwarded-Host", in.Host)
	}
}
