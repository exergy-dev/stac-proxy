package config

import (
	"strings"
	"testing"
)

// FuzzExpandEnvStrict fuzzes the standalone env-expansion function used
// by Load. It uses a small in-memory lookup map (never the real
// environment) and asserts the core contract invariants:
//
//   - never panics;
//   - "$$" round-trips to a single literal "$";
//   - a bare "$NAME" (no braces) is preserved verbatim;
//   - the output contains no leftover "${...}" for a var that was
//     provided by the lookup.
func FuzzExpandEnvStrict(f *testing.F) {
	seeds := []string{
		"${FOO}",
		"${FOO:-bar}",
		"$$",
		"$1",
		"a $NOT_EXPANDED b",
		"${A}${B:-x}",
		"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	env := map[string]string{
		"FOO": "foo-value",
		"A":   "a-value",
		"B":   "b-value",
	}
	lookup := func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}

	f.Fuzz(func(t *testing.T, s string) {
		out, missing := expandEnvStrict(s, lookup)

		// Invariant: "$$" collapses to a single literal "$".
		if got, _ := expandEnvStrict("$$", lookup); got != "$" {
			t.Fatalf("$$ must expand to a single $, got %q", got)
		}

		// Invariant: a bare "$NAME" with no braces is preserved verbatim.
		if got, _ := expandEnvStrict("$NOT_A_VAR", lookup); got != "$NOT_A_VAR" {
			t.Fatalf("bare $NAME must be preserved, got %q", got)
		}

		// Invariant: no ${VAR} reference for a var we provided survives
		// in the output (it must have been substituted). Skip inputs that
		// can legitimately emit literal "${VAR}" text without it being an
		// unresolved reference: "$$" escapes a "$" that can sit next to a
		// literal "{VAR}" (e.g. "$${A}" → "${A}"), and a ":-default"
		// value is copied verbatim and may itself contain "${VAR}".
		if !strings.Contains(s, "$$") && !strings.Contains(s, ":-") {
			for name := range env {
				if strings.Contains(out, "${"+name+"}") {
					t.Fatalf("resolved var still present in output: input=%q output=%q", s, out)
				}
			}
		}

		// Invariant: any name reported as missing was not in the lookup.
		for _, m := range missing {
			if _, ok := env[m]; ok {
				t.Fatalf("provided var %q reported as missing for input %q", m, s)
			}
		}
	})
}
