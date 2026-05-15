package httpx

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
)

func TestResponseCapture_DefaultStatusIs200(t *testing.T) {
	rc := NewResponseCapture()
	if got := rc.Status(); got != http.StatusOK {
		t.Fatalf("default Status() = %d, want 200", got)
	}
}

func TestResponseCapture_WriteHeaderUpdatesStatus(t *testing.T) {
	rc := NewResponseCapture()
	rc.WriteHeader(http.StatusTeapot)
	if got := rc.Status(); got != http.StatusTeapot {
		t.Fatalf("Status() = %d, want 418", got)
	}
	// Second WriteHeader is ignored (matches net/http behavior).
	rc.WriteHeader(http.StatusGone)
	if got := rc.Status(); got != http.StatusTeapot {
		t.Fatalf("Status() after 2nd WriteHeader = %d, want 418", got)
	}
}

func TestResponseCapture_WriteAccumulatesBody(t *testing.T) {
	rc := NewResponseCapture()
	if _, err := rc.Write([]byte("hello ")); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Write([]byte("world")); err != nil {
		t.Fatal(err)
	}
	if got := string(rc.BodyBytes()); got != "hello world" {
		t.Fatalf("body = %q, want %q", got, "hello world")
	}
	// Write without prior WriteHeader yields 200.
	if got := rc.Status(); got != http.StatusOK {
		t.Fatalf("Status after implicit = %d, want 200", got)
	}
}

func TestResponseCapture_HeaderMutable(t *testing.T) {
	rc := NewResponseCapture()
	h := rc.Header()
	h.Set("Content-Type", "application/json")
	h.Add("X-Multi", "a")
	h.Add("X-Multi", "b")

	if got := rc.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if got := rc.Header().Values("X-Multi"); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("X-Multi = %v", got)
	}
}

func TestResponseCapture_HeadersOutSameAsHeader(t *testing.T) {
	rc := NewResponseCapture()
	h1 := rc.Header()
	h1.Set("X-A", "1")
	h2 := rc.HeadersOut()
	if h2.Get("X-A") != "1" {
		t.Fatal("HeadersOut() did not return the same map as Header()")
	}
	// Mutating via HeadersOut() is visible via Header().
	h2.Set("X-B", "2")
	if rc.Header().Get("X-B") != "2" {
		t.Fatal("HeadersOut() mutation not reflected in Header()")
	}
}

func TestResponseCapture_ImplementsResponseWriter(t *testing.T) {
	var _ http.ResponseWriter = NewResponseCapture()
}

func TestResponseCapture_RejectsOversize(t *testing.T) {
	rc := NewResponseCaptureWithLimit(10)

	// First write: 10 bytes, exactly at the cap — must succeed.
	n, err := rc.Write([]byte("0123456789"))
	if err != nil {
		t.Fatalf("first write returned err: %v", err)
	}
	if n != 10 {
		t.Fatalf("first write n = %d, want 10", n)
	}

	// Second write: 2 more bytes, pushing total to 12. Must error
	// with ErrResponseTooLarge.
	n, err = rc.Write([]byte("ab"))
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("second write err = %v, want ErrResponseTooLarge", err)
	}
	if n != 0 {
		t.Fatalf("second write n = %d, want 0", n)
	}

	// Body must be exactly the 10 successful bytes.
	if got := rc.BodyBytes(); !bytes.Equal(got, []byte("0123456789")) {
		t.Fatalf("body = %q, want %q", got, "0123456789")
	}

	// Subsequent writes also rejected.
	n, err = rc.Write([]byte("cd"))
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("third write err = %v, want ErrResponseTooLarge", err)
	}
	if n != 0 {
		t.Fatalf("third write n = %d, want 0", n)
	}
}

func TestResponseCapture_RejectsOversizeSingleWrite(t *testing.T) {
	// A single Write that overshoots must still leave the body
	// exactly max bytes long.
	rc := NewResponseCaptureWithLimit(10)
	_, err := rc.Write([]byte("0123456789AB")) // 12 bytes, cap=10
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
	if got := rc.BodyBytes(); len(got) != 10 {
		t.Fatalf("body len = %d, want 10", len(got))
	}
}

func TestResponseCapture_ZeroIsUnbounded(t *testing.T) {
	rc := NewResponseCaptureWithLimit(0)
	chunk := bytes.Repeat([]byte("x"), 1<<20) // 1 MiB
	for i := 0; i < 10; i++ {                 // 10 MiB total
		n, err := rc.Write(chunk)
		if err != nil {
			t.Fatalf("iter %d: unexpected err: %v", i, err)
		}
		if n != len(chunk) {
			t.Fatalf("iter %d: n = %d, want %d", i, n, len(chunk))
		}
	}
	if got := len(rc.BodyBytes()); got != 10*(1<<20) {
		t.Fatalf("body len = %d, want %d", got, 10*(1<<20))
	}
}

func TestResponseCapture_WriteHeaderThenWrite_StatusPreserved(t *testing.T) {
	rc := NewResponseCapture()
	rc.WriteHeader(http.StatusCreated)
	if _, err := rc.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	if rc.Status() != http.StatusCreated {
		t.Fatalf("Status = %d, want 201", rc.Status())
	}
	if string(rc.BodyBytes()) != "body" {
		t.Fatalf("body = %q", rc.BodyBytes())
	}
}
