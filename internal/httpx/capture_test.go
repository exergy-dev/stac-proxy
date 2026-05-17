package httpx

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResponseCapture_DefaultStatusIs200(t *testing.T) {
	rc := NewResponseCapture()
	require.Equal(t, http.StatusOK, rc.Status(), "default Status()")
}

func TestResponseCapture_WriteHeaderUpdatesStatus(t *testing.T) {
	rc := NewResponseCapture()
	rc.WriteHeader(http.StatusTeapot)
	require.Equal(t, http.StatusTeapot, rc.Status())
	// Second WriteHeader is ignored (matches net/http behavior).
	rc.WriteHeader(http.StatusGone)
	require.Equal(t, http.StatusTeapot, rc.Status(), "Status() after 2nd WriteHeader")
}

func TestResponseCapture_WriteAccumulatesBody(t *testing.T) {
	rc := NewResponseCapture()
	_, err := rc.Write([]byte("hello "))
	require.NoError(t, err)
	_, err = rc.Write([]byte("world"))
	require.NoError(t, err)
	require.Equal(t, "hello world", string(rc.BodyBytes()))
	// Write without prior WriteHeader yields 200.
	require.Equal(t, http.StatusOK, rc.Status(), "Status after implicit")
}

func TestResponseCapture_HeaderMutable(t *testing.T) {
	rc := NewResponseCapture()
	h := rc.Header()
	h.Set("Content-Type", "application/json")
	h.Add("X-Multi", "a")
	h.Add("X-Multi", "b")

	require.Equal(t, "application/json", rc.Header().Get("Content-Type"))
	require.Equal(t, []string{"a", "b"}, rc.Header().Values("X-Multi"))
}

func TestResponseCapture_HeadersOutSameAsHeader(t *testing.T) {
	rc := NewResponseCapture()
	h1 := rc.Header()
	h1.Set("X-A", "1")
	h2 := rc.HeadersOut()
	require.Equal(t, "1", h2.Get("X-A"), "HeadersOut() did not return the same map as Header()")
	// Mutating via HeadersOut() is visible via Header().
	h2.Set("X-B", "2")
	require.Equal(t, "2", rc.Header().Get("X-B"), "HeadersOut() mutation not reflected in Header()")
}

func TestResponseCapture_ImplementsResponseWriter(t *testing.T) {
	var _ http.ResponseWriter = NewResponseCapture()
}

func TestResponseCapture_RejectsOversize(t *testing.T) {
	rc := NewResponseCaptureWithLimit(10)

	// First write: 10 bytes, exactly at the cap — must succeed.
	n, err := rc.Write([]byte("0123456789"))
	require.NoError(t, err, "first write returned err")
	require.Equal(t, 10, n, "first write n")

	// Second write: 2 more bytes, pushing total to 12. Must error
	// with ErrResponseTooLarge.
	n, err = rc.Write([]byte("ab"))
	require.ErrorIs(t, err, ErrResponseTooLarge, "second write err")
	require.Equal(t, 0, n, "second write n")

	// Body must be exactly the 10 successful bytes.
	assert.True(t, bytes.Equal(rc.BodyBytes(), []byte("0123456789")), "body")

	// Subsequent writes also rejected.
	n, err = rc.Write([]byte("cd"))
	require.ErrorIs(t, err, ErrResponseTooLarge, "third write err")
	require.Equal(t, 0, n, "third write n")
}

func TestResponseCapture_RejectsOversizeSingleWrite(t *testing.T) {
	// A single Write that overshoots must still leave the body
	// exactly max bytes long.
	rc := NewResponseCaptureWithLimit(10)
	_, err := rc.Write([]byte("0123456789AB")) // 12 bytes, cap=10
	require.ErrorIs(t, err, ErrResponseTooLarge)
	require.Len(t, rc.BodyBytes(), 10, "body len")
}

func TestResponseCapture_ZeroIsUnbounded(t *testing.T) {
	rc := NewResponseCaptureWithLimit(0)
	chunk := bytes.Repeat([]byte("x"), 1<<20) // 1 MiB
	for i := 0; i < 10; i++ {                 // 10 MiB total
		n, err := rc.Write(chunk)
		require.NoError(t, err, "iter %d: unexpected err", i)
		require.Equal(t, len(chunk), n, "iter %d: n", i)
	}
	require.Len(t, rc.BodyBytes(), 10*(1<<20), "body len")
}

func TestResponseCapture_WriteHeaderThenWrite_StatusPreserved(t *testing.T) {
	rc := NewResponseCapture()
	rc.WriteHeader(http.StatusCreated)
	_, err := rc.Write([]byte("body"))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, rc.Status())
	require.Equal(t, "body", string(rc.BodyBytes()))
}
