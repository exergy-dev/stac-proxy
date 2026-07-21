package httpx

import (
	"bytes"
	"errors"
	"net/http"
)

// ErrResponseTooLarge is returned by ResponseCapture.Write when the
// cumulative number of bytes written would exceed the capture's
// configured maximum. Once this error is returned, the capture rejects
// all further writes; the captured body remains exactly the bytes
// from the last successful write (the offending chunk is dropped
// entirely — partial writes are not retained).
var ErrResponseTooLarge = errors.New("httpx: response body exceeded capture limit")

// ResponseCapture is a buffering http.ResponseWriter suitable for
// passing to httputil.ReverseProxy.ServeHTTP. The captured status,
// headers, and body are exposed for the caller to inspect or mutate
// before re-emitting to the real downstream writer.
type ResponseCapture struct {
	header  http.Header
	status  int
	body    bytes.Buffer
	max     int64 // 0 = unbounded
	written int64 // cumulative bytes accepted into body
	closed  bool  // true once we've rejected a write; further writes also reject
}

// NewResponseCapture returns an unbounded ResponseCapture (no byte
// cap). This is a thin wrapper around NewResponseCaptureWithLimit(0).
func NewResponseCapture() *ResponseCapture {
	return NewResponseCaptureWithLimit(0)
}

// NewResponseCaptureWithLimit returns a ResponseCapture that errors
// out (and stops accepting writes) once total bytes would exceed max.
// max == 0 means unbounded (matching the historical NewResponseCapture
// behavior).
func NewResponseCaptureWithLimit(max int64) *ResponseCapture {
	return &ResponseCapture{max: max}
}

// Header implements http.ResponseWriter. It lazy-inits the underlying
// map so callers can use the zero value of ResponseCapture safely. The
// returned map is the live, mutable instance: callers may modify it in
// place before re-emitting the response.
func (rc *ResponseCapture) Header() http.Header {
	if rc.header == nil {
		rc.header = make(http.Header)
	}
	return rc.header
}

// WriteHeader records the status code. Subsequent calls are ignored
// (matching net/http.ResponseWriter contract: only the first
// WriteHeader takes effect).
func (rc *ResponseCapture) WriteHeader(statusCode int) {
	if rc.status != 0 {
		return
	}
	rc.status = statusCode
}

// Write accumulates bytes into the body buffer. If WriteHeader was
// not called, status defaults to 200 on first Write (matching
// net/http behavior). When a byte cap is configured and the
// cumulative total would exceed it, Write fills the body up to the
// cap (so the captured body is exactly max bytes), returns
// ErrResponseTooLarge, and rejects all subsequent writes with the
// same error.
func (rc *ResponseCapture) Write(p []byte) (int, error) {
	if rc.status == 0 {
		rc.status = http.StatusOK
	}
	if rc.closed {
		return 0, ErrResponseTooLarge
	}
	if rc.max > 0 && rc.written+int64(len(p)) > rc.max {
		// Fill the body up to the cap, then reject.
		remaining := rc.max - rc.written
		if remaining > 0 {
			n, _ := rc.body.Write(p[:remaining])
			rc.written += int64(n)
		}
		rc.closed = true
		return 0, ErrResponseTooLarge
	}
	n, err := rc.body.Write(p)
	rc.written += int64(n)
	return n, err
}

// Status returns the captured status code. If WriteHeader was never
// called, it returns http.StatusOK (200) to match net/http behavior.
func (rc *ResponseCapture) Status() int {
	if rc.status == 0 {
		return http.StatusOK
	}
	return rc.status
}

// BodyBytes returns the bytes accumulated by Write(). The returned
// slice aliases the internal buffer; callers must not mutate it.
func (rc *ResponseCapture) BodyBytes() []byte {
	return rc.body.Bytes()
}
