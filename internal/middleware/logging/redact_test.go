package logging

import "testing"

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
		if got != c.want {
			t.Errorf("redactQuery(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}
