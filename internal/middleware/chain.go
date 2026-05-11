// Package middleware provides the middleware chain implementation.
package middleware

import (
	"context"
	"fmt"
	"sort"
)

// Chain manages an ordered list of middleware components.
type Chain struct {
	middlewares []Middleware
}

// NewChain creates a new middleware chain, sorting by priority.
func NewChain(middlewares ...Middleware) *Chain {
	mws := make([]Middleware, len(middlewares))
	copy(mws, middlewares)

	// Sort by priority (lower = earlier in chain)
	sort.Slice(mws, func(i, j int) bool {
		return mws[i].Priority() < mws[j].Priority()
	})

	return &Chain{middlewares: mws}
}

// Add appends a middleware to the chain and re-sorts.
func (c *Chain) Add(mw Middleware) {
	c.middlewares = append(c.middlewares, mw)
	sort.Slice(c.middlewares, func(i, j int) bool {
		return c.middlewares[i].Priority() < c.middlewares[j].Priority()
	})
}

// Execute processes a request through the middleware chain and calls the upstream handler.
func (c *Chain) Execute(ctx context.Context, req *STACRequest,
	upstream func(*STACRequest) (*STACResponse, error)) (*STACResponse, error) {

	// Process request through chain (forward order)
	currentReq := req
	for _, mw := range c.middlewares {
		var err error
		currentReq, err = mw.ProcessRequest(ctx, currentReq)
		if err != nil {
			return nil, fmt.Errorf("middleware %s request error: %w", mw.Name(), err)
		}
	}

	// Call upstream handler
	resp, err := upstream(currentReq)
	if err != nil {
		return nil, err
	}

	// Process response through chain (reverse order)
	currentResp := resp
	for i := len(c.middlewares) - 1; i >= 0; i-- {
		mw := c.middlewares[i]
		currentResp, err = mw.ProcessResponse(ctx, currentReq, currentResp)
		if err != nil {
			return nil, fmt.Errorf("middleware %s response error: %w", mw.Name(), err)
		}
	}

	return currentResp, nil
}

// Wrap creates an http.Handler-compatible wrapper around the chain.
func (c *Chain) Wrap(handler Handler) Handler {
	return HandlerFunc(func(ctx context.Context, req *STACRequest) (*STACResponse, error) {
		return c.Execute(ctx, req, func(r *STACRequest) (*STACResponse, error) {
			return handler.Handle(ctx, r)
		})
	})
}

// Names returns the names of all middleware in execution order.
func (c *Chain) Names() []string {
	names := make([]string, len(c.middlewares))
	for i, mw := range c.middlewares {
		names[i] = mw.Name()
	}
	return names
}

// Len returns the number of middleware in the chain.
func (c *Chain) Len() int {
	return len(c.middlewares)
}
