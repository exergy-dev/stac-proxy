package middleware

import (
	"net"
	"net/http"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// ClientIP returns the client IP for r: the value stored by whichever
// chi ClientIPFrom* middleware the router wired (per
// server.client_ip config), falling back to the bare host of
// r.RemoteAddr when none ran or the configured source failed closed.
//
// The fallback keeps two properties: unit tests and direct-construction
// callers that skip the router still get a usable key, and a request
// whose trusted header/XFF chain didn't yield an IP degrades to the
// TCP peer instead of an empty key (which would collapse every such
// caller into one rate-limit bucket).
func ClientIP(r *http.Request) string {
	if ip := chimiddleware.GetClientIP(r.Context()); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr may already be a bare IP (tests, exotic listeners).
		return r.RemoteAddr
	}
	return host
}
