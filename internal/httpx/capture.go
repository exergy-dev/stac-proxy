package httpx

import (
	"bytes"
	"net/http"
)

// ResponseCapture is a buffering http.ResponseWriter suitable for
// passing to httputil.ReverseProxy.ServeHTTP. The captured status,
// headers, and body are exposed for the caller to inspect or mutate
// before re-emitting to the real downstream writer.
type ResponseCapture interface {
	http.ResponseWriter
	// Status returns the captured status code. If WriteHeader was
	// never called, it returns http.StatusOK (200) to match net/http
	// behavior.
	Status() int
	// BodyBytes returns the bytes accumulated by Write(). The returned
	// slice aliases the internal buffer; callers must not mutate it.
	BodyBytes() []byte
	// HeadersOut returns the same http.Header that Header() returns
	// (the live, mutable map). Callers may modify it in place before
	// re-emitting the response.
	HeadersOut() http.Header
}

// NewResponseCapture returns a fresh ResponseCapture with an empty
// header map and zero captured status.
func NewResponseCapture() ResponseCapture {
	return &responseCapture{}
}

type responseCapture struct {
	header http.Header
	status int
	body   bytes.Buffer
}

// Header implements http.ResponseWriter. It lazy-inits the underlying
// map so callers can use the zero value of responseCapture safely.
func (rc *responseCapture) Header() http.Header {
	if rc.header == nil {
		rc.header = make(http.Header)
	}
	return rc.header
}

// WriteHeader records the status code. Subsequent calls are ignored
// (matching net/http.ResponseWriter contract: only the first
// WriteHeader takes effect).
func (rc *responseCapture) WriteHeader(statusCode int) {
	if rc.status != 0 {
		return
	}
	rc.status = statusCode
}

// Write accumulates bytes into the body buffer. If WriteHeader was
// not called, status defaults to 200 on first Write (matching
// net/http behavior).
func (rc *responseCapture) Write(p []byte) (int, error) {
	if rc.status == 0 {
		rc.status = http.StatusOK
	}
	return rc.body.Write(p)
}

// Status returns the captured status code, or 200 if none was ever
// set.
func (rc *responseCapture) Status() int {
	if rc.status == 0 {
		return http.StatusOK
	}
	return rc.status
}

// BodyBytes returns the accumulated body bytes.
func (rc *responseCapture) BodyBytes() []byte {
	return rc.body.Bytes()
}

// HeadersOut returns the live header map (same instance as Header()).
func (rc *responseCapture) HeadersOut() http.Header {
	return rc.Header()
}
