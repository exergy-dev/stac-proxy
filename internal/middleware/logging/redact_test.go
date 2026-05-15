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

func TestHashRemoteAddr_StripsPort(t *testing.T) {
	a := hashRemoteAddr("203.0.113.5:11111")
	b := hashRemoteAddr("203.0.113.5:22222")
	if a == "" || a != b {
		t.Errorf("hashRemoteAddr port stripped: %q vs %q", a, b)
	}
	if hashRemoteAddr("") != "" {
		t.Error("hashRemoteAddr(\"\") should be empty")
	}
}

func TestHashShort_DeterministicAndShort(t *testing.T) {
	if hashShort("") != "" {
		t.Error("hashShort(\"\") should be empty")
	}
	a := hashShort("Mozilla/5.0")
	b := hashShort("Mozilla/5.0")
	if a != b || len(a) != 8 {
		t.Errorf("hashShort = %q (len %d), want stable 8-char digest", a, len(a))
	}
	if hashShort("curl/8") == a {
		t.Error("distinct inputs collided")
	}
}
