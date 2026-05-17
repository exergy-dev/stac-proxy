# Contributing to stac-proxy

Thanks for considering a contribution.

## Dev setup

```bash
git clone https://github.com/yourorg/stac-proxy.git
cd stac-proxy
make build           # ./stac-proxy
make test            # all packages
make race            # with race detector
make lint            # golangci-lint (install: https://golangci-lint.run)
```

Go 1.22+ required; CI runs 1.22.x and 1.23.x.

## Pull requests

1. Open an issue first for any non-trivial change so we can agree on scope.
2. Keep PRs focused. One feature or one bug per PR; mechanical refactors
   in separate commits within the PR.
3. Add tests next to the code you touched. `go test -race ./...` must
   stay green; `make lint` must stay clean.
4. Update relevant docs:
   - `README.md` features list, if behaviour changed
   - `docs/observability.md`, if you added or renamed a log field
   - `docs/policies.md`, if you added an OPA constraint key
   - `CHANGELOG.md` under the next unreleased version
5. Commit messages: imperative mood, first line ≤72 chars, blank line,
   then body explaining *why*. Reference issues with `Fixes #123`.

## Testing patterns

- Unit tests live next to the code (`foo_test.go`).
- Integration tests live in `tests/integration/` and exercise the full
  middleware chain against an httptest upstream.
- Prefer table-driven tests; use `t.Run("name", ...)` so the subtest
  matrix is greppable.
- `httptest.NewServer` for HTTP, `internal/testutil` for STAC fixtures.

## Style

- `golangci-lint` config in `.golangci.yml`; CI gates on it.
- Exported symbols carry doc comments (revive enforces this).
- Errors wrap with `%w` so callers can use `errors.Is/As`.
- Logging via Go's standard `log/slog`; use `slog.Default()` for global,
  or take a `*slog.Logger` in the constructor when it's component-level.

## Release process

Maintainers tag a commit with `vMAJOR.MINOR.PATCH` and push. The
`.github/workflows/release.yml` workflow:
1. Builds linux/amd64 + linux/arm64 binaries with `-ldflags` versioning.
2. Attaches the binaries to a GitHub Release with auto-generated notes.
3. Builds a multi-arch container image and publishes to
   `ghcr.io/<repo>:<tag>` plus `:latest`.

Bump `CHANGELOG.md` in the same commit that gets tagged.

## Scope guardrails

`stac-proxy` is a proxy, not a STAC server. We do not:
- store catalog data,
- transform feature geometry beyond filtering,
- implement Rego-equivalents in Go (OPA is the policy engine).

If a feature would push us across one of those lines, it belongs in a
separate project or upstream contribution.
