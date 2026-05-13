package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestNewChain_Empty tests creating an empty chain.
func TestNewChain_Empty(t *testing.T) {
	t.Parallel()

	chain := NewChain()

	if chain == nil {
		t.Fatal("NewChain returned nil")
	}

	if chain.Len() != 0 {
		t.Errorf("expected empty chain, got length %d", chain.Len())
	}

	names := chain.Names()
	if len(names) != 0 {
		t.Errorf("expected no names, got %v", names)
	}
}

// TestNewChain_Single tests creating a chain with a single middleware.
func TestNewChain_Single(t *testing.T) {
	t.Parallel()

	mw := newTestMiddleware("test", 100)
	chain := NewChain(mw)

	if chain.Len() != 1 {
		t.Errorf("expected chain length 1, got %d", chain.Len())
	}

	names := chain.Names()
	if len(names) != 1 || names[0] != "test" {
		t.Errorf("expected names [test], got %v", names)
	}
}

// TestNewChain_Multiple tests creating a chain with multiple middleware.
func TestNewChain_Multiple(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mwCount   int
		wantNames []string
	}{
		{
			name:      "two middleware",
			mwCount:   2,
			wantNames: []string{"mw-0", "mw-1"},
		},
		{
			name:      "five middleware",
			mwCount:   5,
			wantNames: []string{"mw-0", "mw-1", "mw-2", "mw-3", "mw-4"},
		},
		{
			name:      "ten middleware",
			mwCount:   10,
			wantNames: []string{"mw-0", "mw-1", "mw-2", "mw-3", "mw-4", "mw-5", "mw-6", "mw-7", "mw-8", "mw-9"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mws := make([]Middleware, tt.mwCount)
			for i := 0; i < tt.mwCount; i++ {
				mws[i] = newTestMiddleware(fmt.Sprintf("mw-%d", i), i*100)
			}

			chain := NewChain(mws...)

			if chain.Len() != tt.mwCount {
				t.Errorf("expected chain length %d, got %d", tt.mwCount, chain.Len())
			}

			names := chain.Names()
			if len(names) != len(tt.wantNames) {
				t.Errorf("expected %d names, got %d", len(tt.wantNames), len(names))
			}

			for i, name := range tt.wantNames {
				if i >= len(names) {
					break
				}
				if names[i] != name {
					t.Errorf("names[%d]: expected %s, got %s", i, name, names[i])
				}
			}
		})
	}
}

// TestNewChain_PriorityOrdering tests that middleware is sorted by priority.
func TestNewChain_PriorityOrdering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		priorities []int
		wantOrder  []string
	}{
		{
			name:       "already sorted",
			priorities: []int{100, 200, 300},
			wantOrder:  []string{"mw-100", "mw-200", "mw-300"},
		},
		{
			name:       "reverse sorted",
			priorities: []int{300, 200, 100},
			wantOrder:  []string{"mw-100", "mw-200", "mw-300"},
		},
		{
			name:       "unsorted",
			priorities: []int{200, 100, 400, 300},
			wantOrder:  []string{"mw-100", "mw-200", "mw-300", "mw-400"},
		},
		{
			name:       "with duplicates",
			priorities: []int{100, 100, 200, 200, 300},
			wantOrder:  []string{"mw-100", "mw-100", "mw-200", "mw-200", "mw-300"},
		},
		{
			name:       "negative priorities",
			priorities: []int{100, -50, 0, 200},
			wantOrder:  []string{"mw--50", "mw-0", "mw-100", "mw-200"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mws := make([]Middleware, len(tt.priorities))
			for i, priority := range tt.priorities {
				mws[i] = newTestMiddleware(fmt.Sprintf("mw-%d", priority), priority)
			}

			chain := NewChain(mws...)
			names := chain.Names()

			if len(names) != len(tt.wantOrder) {
				t.Errorf("expected %d middleware, got %d", len(tt.wantOrder), len(names))
			}

			for i, want := range tt.wantOrder {
				if i >= len(names) {
					break
				}
				if names[i] != want {
					t.Errorf("position %d: expected %s, got %s", i, want, names[i])
				}
			}
		})
	}
}

// TestChain_Add tests adding middleware to an existing chain.
func TestChain_Add(t *testing.T) {
	t.Parallel()

	// Start with empty chain
	chain := NewChain()
	if chain.Len() != 0 {
		t.Fatalf("expected empty chain, got %d", chain.Len())
	}

	// Add first middleware
	mw1 := newTestMiddleware("first", 100)
	chain.Add(mw1)
	if chain.Len() != 1 {
		t.Errorf("expected length 1, got %d", chain.Len())
	}

	// Add second middleware with higher priority (should be added at end)
	mw2 := newTestMiddleware("second", 200)
	chain.Add(mw2)
	if chain.Len() != 2 {
		t.Errorf("expected length 2, got %d", chain.Len())
	}

	names := chain.Names()
	if names[0] != "first" || names[1] != "second" {
		t.Errorf("expected [first, second], got %v", names)
	}

	// Add third middleware with lower priority (should be inserted at beginning)
	mw3 := newTestMiddleware("third", 50)
	chain.Add(mw3)
	if chain.Len() != 3 {
		t.Errorf("expected length 3, got %d", chain.Len())
	}

	names = chain.Names()
	if names[0] != "third" || names[1] != "first" || names[2] != "second" {
		t.Errorf("expected [third, first, second], got %v", names)
	}
}

// TestChain_Execute_EmptyChain tests executing an empty chain.
func TestChain_Execute_EmptyChain(t *testing.T) {
	t.Parallel()

	chain := NewChain()
	ctx := context.Background()
	req := newTestRequest()

	upstreamCalled := false
	expectedResp := &STACResponse{
		StatusCode: http.StatusOK,
		Body:       []byte(`{"test": "response"}`),
		Headers:    make(http.Header),
	}

	upstream := func(r *STACRequest) (*STACResponse, error) {
		upstreamCalled = true
		if r != req {
			t.Error("upstream received different request")
		}
		return expectedResp, nil
	}

	resp, err := chain.Execute(ctx, req, upstream)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !upstreamCalled {
		t.Error("upstream was not called")
	}

	if resp != expectedResp {
		t.Error("response does not match expected response")
	}
}

// TestChain_Execute_SingleMiddleware tests executing a chain with one middleware.
func TestChain_Execute_SingleMiddleware(t *testing.T) {
	t.Parallel()

	mw := newTestMiddleware("test", 100)
	chain := NewChain(mw)
	ctx := context.Background()
	req := newTestRequest()

	upstreamResp := &STACResponse{
		StatusCode: http.StatusOK,
		Body:       []byte(`{}`),
		Headers:    make(http.Header),
	}

	upstream := func(r *STACRequest) (*STACResponse, error) {
		return upstreamResp, nil
	}

	resp, err := chain.Execute(ctx, req, upstream)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}

	if mw.reqCallCount != 1 {
		t.Errorf("expected ProcessRequest called 1 time, got %d", mw.reqCallCount)
	}

	if mw.respCallCount != 1 {
		t.Errorf("expected ProcessResponse called 1 time, got %d", mw.respCallCount)
	}
}

// TestChain_Execute_ForwardOrder tests that requests are processed in forward order.
func TestChain_Execute_ForwardOrder(t *testing.T) {
	t.Parallel()

	var callOrder []string
	var mu sync.Mutex

	mw1 := newTestMiddlewareWithReqFunc("first", 100, func(ctx context.Context, req *STACRequest) (*STACRequest, error) {
		mu.Lock()
		callOrder = append(callOrder, "first-req")
		mu.Unlock()
		return req, nil
	})

	mw2 := newTestMiddlewareWithReqFunc("second", 200, func(ctx context.Context, req *STACRequest) (*STACRequest, error) {
		mu.Lock()
		callOrder = append(callOrder, "second-req")
		mu.Unlock()
		return req, nil
	})

	mw3 := newTestMiddlewareWithReqFunc("third", 300, func(ctx context.Context, req *STACRequest) (*STACRequest, error) {
		mu.Lock()
		callOrder = append(callOrder, "third-req")
		mu.Unlock()
		return req, nil
	})

	chain := NewChain(mw1, mw2, mw3)
	ctx := context.Background()
	req := newTestRequest()

	upstream := func(r *STACRequest) (*STACResponse, error) {
		mu.Lock()
		callOrder = append(callOrder, "upstream")
		mu.Unlock()
		return &STACResponse{StatusCode: http.StatusOK, Headers: make(http.Header)}, nil
	}

	_, err := chain.Execute(ctx, req, upstream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedOrder := []string{"first-req", "second-req", "third-req", "upstream"}
	if len(callOrder) != len(expectedOrder) {
		t.Errorf("expected %d calls, got %d: %v", len(expectedOrder), len(callOrder), callOrder)
	}

	for i, expected := range expectedOrder {
		if i >= len(callOrder) {
			break
		}
		if callOrder[i] != expected {
			t.Errorf("call order[%d]: expected %s, got %s", i, expected, callOrder[i])
		}
	}
}

// TestChain_Execute_ReverseOrder tests that responses are processed in reverse order.
func TestChain_Execute_ReverseOrder(t *testing.T) {
	t.Parallel()

	var callOrder []string
	var mu sync.Mutex

	mw1 := newTestMiddlewareWithRespFunc("first", 100, func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
		mu.Lock()
		callOrder = append(callOrder, "first-resp")
		mu.Unlock()
		return resp, nil
	})

	mw2 := newTestMiddlewareWithRespFunc("second", 200, func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
		mu.Lock()
		callOrder = append(callOrder, "second-resp")
		mu.Unlock()
		return resp, nil
	})

	mw3 := newTestMiddlewareWithRespFunc("third", 300, func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
		mu.Lock()
		callOrder = append(callOrder, "third-resp")
		mu.Unlock()
		return resp, nil
	})

	chain := NewChain(mw1, mw2, mw3)
	ctx := context.Background()
	req := newTestRequest()

	upstream := func(r *STACRequest) (*STACResponse, error) {
		return &STACResponse{StatusCode: http.StatusOK, Headers: make(http.Header)}, nil
	}

	_, err := chain.Execute(ctx, req, upstream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Response processing should be in reverse order: third -> second -> first
	expectedOrder := []string{"third-resp", "second-resp", "first-resp"}
	if len(callOrder) != len(expectedOrder) {
		t.Errorf("expected %d calls, got %d: %v", len(expectedOrder), len(callOrder), callOrder)
	}

	for i, expected := range expectedOrder {
		if i >= len(callOrder) {
			break
		}
		if callOrder[i] != expected {
			t.Errorf("call order[%d]: expected %s, got %s", i, expected, callOrder[i])
		}
	}
}

// TestChain_Execute_RequestError tests error handling in request processing.
func TestChain_Execute_RequestError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		errorAtMw    int // which middleware should return error (0-indexed)
		wantReqCall  int // how many request processors should be called
		wantRespCall int // how many response processors should be called
	}{
		{
			name:         "error at first middleware",
			errorAtMw:    0,
			wantReqCall:  1,
			wantRespCall: 0, // no response processing if request fails
		},
		{
			name:         "error at second middleware",
			errorAtMw:    1,
			wantReqCall:  2,
			wantRespCall: 0,
		},
		{
			name:         "error at third middleware",
			errorAtMw:    2,
			wantReqCall:  3,
			wantRespCall: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var totalReqCalls, totalRespCalls int
			var mu sync.Mutex

			mws := make([]Middleware, 3)
			for i := 0; i < 3; i++ {
				idx := i
				mws[i] = newTestMiddlewareWithBothFuncs(
					fmt.Sprintf("mw-%d", i),
					i*100,
					func(ctx context.Context, req *STACRequest) (*STACRequest, error) {
						mu.Lock()
						totalReqCalls++
						mu.Unlock()
						if idx == tt.errorAtMw {
							return nil, errors.New("request processing error")
						}
						return req, nil
					},
					func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
						mu.Lock()
						totalRespCalls++
						mu.Unlock()
						return resp, nil
					},
				)
			}

			chain := NewChain(mws...)
			ctx := context.Background()
			req := newTestRequest()

			upstreamCalled := false
			upstream := func(r *STACRequest) (*STACResponse, error) {
				upstreamCalled = true
				return &STACResponse{StatusCode: http.StatusOK, Headers: make(http.Header)}, nil
			}

			resp, err := chain.Execute(ctx, req, upstream)

			if err == nil {
				t.Error("expected error, got nil")
			}

			if resp != nil {
				t.Error("expected nil response on error")
			}

			if upstreamCalled {
				t.Error("upstream should not be called when request processing fails")
			}

			if totalReqCalls != tt.wantReqCall {
				t.Errorf("expected %d request calls, got %d", tt.wantReqCall, totalReqCalls)
			}

			if totalRespCalls != tt.wantRespCall {
				t.Errorf("expected %d response calls, got %d", tt.wantRespCall, totalRespCalls)
			}
		})
	}
}

// TestChain_Execute_ResponseError tests error handling in response processing.
func TestChain_Execute_ResponseError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		errorAtMw    int // which middleware should return error (0-indexed from end)
		wantRespCall int // how many response processors should be called
	}{
		{
			name:         "error at last middleware (first in response chain)",
			errorAtMw:    2,
			wantRespCall: 1,
		},
		{
			name:         "error at middle middleware",
			errorAtMw:    1,
			wantRespCall: 2,
		},
		{
			name:         "error at first middleware (last in response chain)",
			errorAtMw:    0,
			wantRespCall: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var totalRespCalls int
			var mu sync.Mutex

			mws := make([]Middleware, 3)
			for i := 0; i < 3; i++ {
				idx := i
				mws[i] = newTestMiddlewareWithRespFunc(
					fmt.Sprintf("mw-%d", i),
					i*100,
					func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
						mu.Lock()
						totalRespCalls++
						mu.Unlock()
						if idx == tt.errorAtMw {
							return nil, errors.New("response processing error")
						}
						return resp, nil
					},
				)
			}

			chain := NewChain(mws...)
			ctx := context.Background()
			req := newTestRequest()

			upstream := func(r *STACRequest) (*STACResponse, error) {
				return &STACResponse{StatusCode: http.StatusOK, Headers: make(http.Header)}, nil
			}

			resp, err := chain.Execute(ctx, req, upstream)

			if err == nil {
				t.Error("expected error, got nil")
			}

			if resp != nil {
				t.Error("expected nil response on error")
			}

			if totalRespCalls != tt.wantRespCall {
				t.Errorf("expected %d response calls, got %d", tt.wantRespCall, totalRespCalls)
			}
		})
	}
}

// TestChain_Execute_UpstreamError tests handling of upstream errors.
func TestChain_Execute_UpstreamError(t *testing.T) {
	t.Parallel()

	mw := newTestMiddleware("test", 100)
	chain := NewChain(mw)
	ctx := context.Background()
	req := newTestRequest()

	upstreamErr := errors.New("upstream error")
	upstream := func(r *STACRequest) (*STACResponse, error) {
		return nil, upstreamErr
	}

	resp, err := chain.Execute(ctx, req, upstream)

	if err != upstreamErr {
		t.Errorf("expected upstream error, got %v", err)
	}

	if resp != nil {
		t.Error("expected nil response")
	}

	if mw.reqCallCount != 1 {
		t.Errorf("expected ProcessRequest called 1 time, got %d", mw.reqCallCount)
	}

	// Response processing should not happen if upstream returns error
	if mw.respCallCount != 0 {
		t.Errorf("expected ProcessResponse not called, got %d calls", mw.respCallCount)
	}
}

// TestChain_Execute_RequestModification tests request modification through chain.
func TestChain_Execute_RequestModification(t *testing.T) {
	t.Parallel()

	mw1 := newTestMiddlewareWithReqFunc("mw1", 100, func(ctx context.Context, req *STACRequest) (*STACRequest, error) {
		req.Params["mw1"] = "modified"
		return req, nil
	})

	mw2 := newTestMiddlewareWithReqFunc("mw2", 200, func(ctx context.Context, req *STACRequest) (*STACRequest, error) {
		req.Params["mw2"] = "modified"
		return req, nil
	})

	chain := NewChain(mw1, mw2)
	ctx := context.Background()
	req := newTestRequest()
	req.Params = make(map[string]interface{})

	var receivedReq *STACRequest
	upstream := func(r *STACRequest) (*STACResponse, error) {
		receivedReq = r
		return &STACResponse{StatusCode: http.StatusOK, Headers: make(http.Header)}, nil
	}

	_, err := chain.Execute(ctx, req, upstream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedReq == nil {
		t.Fatal("upstream did not receive request")
	}

	if receivedReq.Params["mw1"] != "modified" {
		t.Error("mw1 modification not present")
	}

	if receivedReq.Params["mw2"] != "modified" {
		t.Error("mw2 modification not present")
	}
}

// TestChain_Execute_ResponseModification tests response modification through chain.
func TestChain_Execute_ResponseModification(t *testing.T) {
	t.Parallel()

	mw1 := newTestMiddlewareWithRespFunc("mw1", 100, func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
		resp.Headers.Add("X-Middleware-1", "processed")
		return resp, nil
	})

	mw2 := newTestMiddlewareWithRespFunc("mw2", 200, func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
		resp.Headers.Add("X-Middleware-2", "processed")
		return resp, nil
	})

	chain := NewChain(mw1, mw2)
	ctx := context.Background()
	req := newTestRequest()

	upstream := func(r *STACRequest) (*STACResponse, error) {
		return &STACResponse{
			StatusCode: http.StatusOK,
			Headers:    make(http.Header),
		}, nil
	}

	resp, err := chain.Execute(ctx, req, upstream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp == nil {
		t.Fatal("response is nil")
	}

	if resp.Headers.Get("X-Middleware-1") != "processed" {
		t.Error("mw1 did not add header")
	}

	if resp.Headers.Get("X-Middleware-2") != "processed" {
		t.Error("mw2 did not add header")
	}
}

// TestChain_Execute_ContextPropagation tests that context is passed through the chain.
func TestChain_Execute_ContextPropagation(t *testing.T) {
	t.Parallel()

	type ctxKey string
	const testKey ctxKey = "test"

	ctx := context.WithValue(context.Background(), testKey, "test-value")

	var reqCtx, respCtx, upstreamCtx context.Context

	mw := newTestMiddlewareWithBothFuncs("test", 100,
		func(c context.Context, req *STACRequest) (*STACRequest, error) {
			reqCtx = c
			return req, nil
		},
		func(c context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
			respCtx = c
			return resp, nil
		},
	)

	chain := NewChain(mw)
	req := newTestRequest()

	upstream := func(r *STACRequest) (*STACResponse, error) {
		upstreamCtx = ctx
		return &STACResponse{StatusCode: http.StatusOK, Headers: make(http.Header)}, nil
	}

	_, err := chain.Execute(ctx, req, upstream)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify context was passed to ProcessRequest
	if reqCtx == nil {
		t.Error("ProcessRequest did not receive context")
	} else if v := reqCtx.Value(testKey); v != "test-value" {
		t.Errorf("ProcessRequest context value: expected 'test-value', got %v", v)
	}

	// Verify context was passed to ProcessResponse
	if respCtx == nil {
		t.Error("ProcessResponse did not receive context")
	} else if v := respCtx.Value(testKey); v != "test-value" {
		t.Errorf("ProcessResponse context value: expected 'test-value', got %v", v)
	}

	// Verify context was available in upstream
	if upstreamCtx == nil {
		t.Error("upstream did not receive context")
	} else if v := upstreamCtx.Value(testKey); v != "test-value" {
		t.Errorf("upstream context value: expected 'test-value', got %v", v)
	}
}

// TestChain_Wrap tests the Wrap function for handler wrapping.
func TestChain_Wrap(t *testing.T) {
	t.Parallel()

	mw := newTestMiddleware("test", 100)
	chain := NewChain(mw)

	handlerCalled := false
	handler := HandlerFunc(func(ctx context.Context, req *STACRequest) (*STACResponse, error) {
		handlerCalled = true
		return &STACResponse{
			StatusCode: http.StatusOK,
			Body:       []byte(`{"test": "response"}`),
			Headers:    make(http.Header),
		}, nil
	})

	wrapped := chain.Wrap(handler)

	ctx := context.Background()
	req := newTestRequest()

	resp, err := wrapped.Handle(ctx, req)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !handlerCalled {
		t.Error("wrapped handler was not called")
	}

	if resp == nil {
		t.Fatal("response is nil")
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected status 200, got %d", resp.StatusCode)
	}

	if mw.reqCallCount != 1 {
		t.Errorf("expected ProcessRequest called 1 time, got %d", mw.reqCallCount)
	}

	if mw.respCallCount != 1 {
		t.Errorf("expected ProcessResponse called 1 time, got %d", mw.respCallCount)
	}
}

// TestChain_Wrap_WithMultipleMiddleware tests Wrap with multiple middleware.
func TestChain_Wrap_WithMultipleMiddleware(t *testing.T) {
	t.Parallel()

	var callOrder []string
	var mu sync.Mutex

	mw1 := newTestMiddlewareWithBothFuncs("mw1", 100,
		func(ctx context.Context, req *STACRequest) (*STACRequest, error) {
			mu.Lock()
			callOrder = append(callOrder, "mw1-req")
			mu.Unlock()
			return req, nil
		},
		func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
			mu.Lock()
			callOrder = append(callOrder, "mw1-resp")
			mu.Unlock()
			return resp, nil
		},
	)

	mw2 := newTestMiddlewareWithBothFuncs("mw2", 200,
		func(ctx context.Context, req *STACRequest) (*STACRequest, error) {
			mu.Lock()
			callOrder = append(callOrder, "mw2-req")
			mu.Unlock()
			return req, nil
		},
		func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
			mu.Lock()
			callOrder = append(callOrder, "mw2-resp")
			mu.Unlock()
			return resp, nil
		},
	)

	chain := NewChain(mw1, mw2)

	handler := HandlerFunc(func(ctx context.Context, req *STACRequest) (*STACResponse, error) {
		mu.Lock()
		callOrder = append(callOrder, "handler")
		mu.Unlock()
		return &STACResponse{StatusCode: http.StatusOK, Headers: make(http.Header)}, nil
	})

	wrapped := chain.Wrap(handler)

	ctx := context.Background()
	req := newTestRequest()

	_, err := wrapped.Handle(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedOrder := []string{"mw1-req", "mw2-req", "handler", "mw2-resp", "mw1-resp"}
	if len(callOrder) != len(expectedOrder) {
		t.Errorf("expected %d calls, got %d: %v", len(expectedOrder), len(callOrder), callOrder)
	}

	for i, expected := range expectedOrder {
		if i >= len(callOrder) {
			break
		}
		if callOrder[i] != expected {
			t.Errorf("call order[%d]: expected %s, got %s", i, expected, callOrder[i])
		}
	}
}

// TestChain_Wrap_ErrorHandling tests error handling in wrapped handler.
func TestChain_Wrap_ErrorHandling(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		setupChain   func() *Chain
		setupHandler func() Handler
		wantErr      bool
	}{
		{
			name: "request error",
			setupChain: func() *Chain {
				mw := newTestMiddlewareWithReqFunc("test", 100, func(ctx context.Context, req *STACRequest) (*STACRequest, error) {
					return nil, errors.New("request error")
				})
				return NewChain(mw)
			},
			setupHandler: func() Handler {
				return HandlerFunc(func(ctx context.Context, req *STACRequest) (*STACResponse, error) {
					return &STACResponse{StatusCode: http.StatusOK, Headers: make(http.Header)}, nil
				})
			},
			wantErr: true,
		},
		{
			name: "handler error",
			setupChain: func() *Chain {
				return NewChain()
			},
			setupHandler: func() Handler {
				return HandlerFunc(func(ctx context.Context, req *STACRequest) (*STACResponse, error) {
					return nil, errors.New("handler error")
				})
			},
			wantErr: true,
		},
		{
			name: "response error",
			setupChain: func() *Chain {
				mw := newTestMiddlewareWithRespFunc("test", 100, func(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
					return nil, errors.New("response error")
				})
				return NewChain(mw)
			},
			setupHandler: func() Handler {
				return HandlerFunc(func(ctx context.Context, req *STACRequest) (*STACResponse, error) {
					return &STACResponse{StatusCode: http.StatusOK, Headers: make(http.Header)}, nil
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			chain := tt.setupChain()
			handler := tt.setupHandler()
			wrapped := chain.Wrap(handler)

			ctx := context.Background()
			req := newTestRequest()

			_, err := wrapped.Handle(ctx, req)

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}

			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestChain_Names tests the Names function.
func TestChain_Names(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mwNames   []string
		wantNames []string
	}{
		{
			name:      "empty chain",
			mwNames:   []string{},
			wantNames: []string{},
		},
		{
			name:      "single middleware",
			mwNames:   []string{"test"},
			wantNames: []string{"test"},
		},
		{
			name:      "multiple middleware",
			mwNames:   []string{"first", "second", "third"},
			wantNames: []string{"first", "second", "third"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mws := make([]Middleware, len(tt.mwNames))
			for i, name := range tt.mwNames {
				mws[i] = newTestMiddleware(name, i*100)
			}

			chain := NewChain(mws...)
			names := chain.Names()

			if len(names) != len(tt.wantNames) {
				t.Errorf("expected %d names, got %d", len(tt.wantNames), len(names))
			}

			for i, want := range tt.wantNames {
				if i >= len(names) {
					break
				}
				if names[i] != want {
					t.Errorf("names[%d]: expected %s, got %s", i, want, names[i])
				}
			}
		})
	}
}

// TestChain_Len tests the Len function.
func TestChain_Len(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mwCount int
	}{
		{"empty", 0},
		{"one", 1},
		{"five", 5},
		{"ten", 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mws := make([]Middleware, tt.mwCount)
			for i := 0; i < tt.mwCount; i++ {
				mws[i] = newTestMiddleware(fmt.Sprintf("mw-%d", i), i*100)
			}

			chain := NewChain(mws...)

			if chain.Len() != tt.mwCount {
				t.Errorf("expected length %d, got %d", tt.mwCount, chain.Len())
			}
		})
	}
}

// TestChain_PriorityConstants tests using standard priority constants.
func TestChain_PriorityConstants(t *testing.T) {
	t.Parallel()

	mwLogging := newTestMiddleware("logging", PriorityLogging)
	mwAuth := newTestMiddleware("auth", PriorityAuth)
	mwAuthz := newTestMiddleware("authz", PriorityAuthz)
	mwCache := newTestMiddleware("cache", PriorityCache)
	mwTransform := newTestMiddleware("transform", PriorityTransform)

	// Create chain in random order
	chain := NewChain(mwTransform, mwAuth, mwCache, mwLogging, mwAuthz)

	// Expected order based on priority values (cache is intentionally
	// scheduled between auth and authz so cache hits don't consume
	// rate-limit tokens but unauthenticated callers still can't fish
	// for cached content).
	expectedOrder := []string{"logging", "auth", "cache", "authz", "transform"}
	names := chain.Names()

	if len(names) != len(expectedOrder) {
		t.Errorf("expected %d middleware, got %d", len(expectedOrder), len(names))
	}

	for i, expected := range expectedOrder {
		if i >= len(names) {
			break
		}
		if names[i] != expected {
			t.Errorf("position %d: expected %s, got %s", i, expected, names[i])
		}
	}
}

// Helper types and functions for testing

// testMiddleware is a simple test middleware implementation.
type testMiddleware struct {
	name          string
	priority      int
	reqFunc       func(context.Context, *STACRequest) (*STACRequest, error)
	respFunc      func(context.Context, *STACRequest, *STACResponse) (*STACResponse, error)
	reqCallCount  int
	respCallCount int
	mu            sync.Mutex
}

func newTestMiddleware(name string, priority int) *testMiddleware {
	return &testMiddleware{
		name:     name,
		priority: priority,
	}
}

func newTestMiddlewareWithReqFunc(name string, priority int, reqFunc func(context.Context, *STACRequest) (*STACRequest, error)) *testMiddleware {
	return &testMiddleware{
		name:     name,
		priority: priority,
		reqFunc:  reqFunc,
	}
}

func newTestMiddlewareWithRespFunc(name string, priority int, respFunc func(context.Context, *STACRequest, *STACResponse) (*STACResponse, error)) *testMiddleware {
	return &testMiddleware{
		name:     name,
		priority: priority,
		respFunc: respFunc,
	}
}

func newTestMiddlewareWithBothFuncs(name string, priority int, reqFunc func(context.Context, *STACRequest) (*STACRequest, error), respFunc func(context.Context, *STACRequest, *STACResponse) (*STACResponse, error)) *testMiddleware {
	return &testMiddleware{
		name:     name,
		priority: priority,
		reqFunc:  reqFunc,
		respFunc: respFunc,
	}
}

func (m *testMiddleware) Name() string {
	return m.name
}

func (m *testMiddleware) Priority() int {
	return m.priority
}

func (m *testMiddleware) ProcessRequest(ctx context.Context, req *STACRequest) (*STACRequest, error) {
	m.mu.Lock()
	m.reqCallCount++
	m.mu.Unlock()

	if m.reqFunc != nil {
		return m.reqFunc(ctx, req)
	}
	return req, nil
}

func (m *testMiddleware) ProcessResponse(ctx context.Context, req *STACRequest, resp *STACResponse) (*STACResponse, error) {
	m.mu.Lock()
	m.respCallCount++
	m.mu.Unlock()

	if m.respFunc != nil {
		return m.respFunc(ctx, req, resp)
	}
	return resp, nil
}

// newTestRequest creates a test STACRequest.
func newTestRequest() *STACRequest {
	httpReq := httptest.NewRequest(http.MethodGet, "/test", nil)
	return &STACRequest{
		Request:     httpReq,
		Context:     context.Background(),
		RequestType: RequestTypeSearch,
		Params:      make(map[string]interface{}),
	}
}
