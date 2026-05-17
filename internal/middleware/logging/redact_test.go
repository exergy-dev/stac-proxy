package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactQuery_DefaultParams(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"limit=10&token=hunter2", "limit=10&token=%2A%2A%2A"},
		{"sig=abc&exp=42", "exp=42&sig=%2A%2A%2A"},
		{"Authorization=Bearer+x&q=foo", "Authorization=Bearer+x&q=foo"}, // header-style not a query name we redact
		{"API_KEY=topsecret", "API_KEY=%2A%2A%2A"},                       // case-insensitive match
		{"", ""},
	}
	for _, c := range cases {
		got := redactQuery(c.raw, defaultRedactedQueryParams)
		assert.Equalf(t, c.want, got, "redactQuery(%q)", c.raw)
	}
}

func TestHashRemoteAddr_StripsPort(t *testing.T) {
	a := hashRemoteAddr("203.0.113.5:11111")
	b := hashRemoteAddr("203.0.113.5:22222")
	require.NotEmpty(t, a, "hashRemoteAddr returned empty")
	assert.Equalf(t, b, a, "hashRemoteAddr port stripped: %q vs %q", a, b)
	assert.Empty(t, hashRemoteAddr(""), "hashRemoteAddr(\"\") should be empty")
}

func TestHashShort_DeterministicAndShort(t *testing.T) {
	assert.Empty(t, hashShort(""), "hashShort(\"\") should be empty")
	a := hashShort("Mozilla/5.0")
	b := hashShort("Mozilla/5.0")
	assert.Equalf(t, a, b, "hashShort not stable: %q vs %q", a, b)
	assert.Lenf(t, a, 8, "hashShort = %q, want 8-char digest", a)
	assert.NotEqual(t, a, hashShort("curl/8"), "distinct inputs collided")
}
