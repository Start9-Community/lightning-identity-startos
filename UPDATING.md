# Updating Lightning Identity

There is no upstream: `service/` in this repository is the application and
`startos/` is the package. A release bumps both together.

## Releasing a change

1. In `service/`: `go test ./...` (the `internal/e2e` test runs guard, core and
   edge against a fake LND; it is the gate), then `go mod tidy` so `go.sum`
   matches `go.mod`. Commit `go.sum` — the Dockerfile tolerates a missing one
   for a first build, but a release must not depend on that.
2. Bump `version` and write `releaseNotes` in `startos/versions/current.ts`
   (`<app semver>:<package rev>`). A package-only change bumps the rev; a
   service change bumps the semver and the rev resets to 0.
3. Add a migration only when on-disk data changes: `core.db` is bbolt with
   JSON values and tolerates added fields; a renamed bucket or a changed
   `edge.json` shape needs one.
4. `make` (needs Docker, `start-cli` and a packaging workspace), install, and
   walk `instructions.md` § Getting set up once more before publishing.

## Dependency pins

- `@start9labs/start-sdk` and `lnd-startos` in `package.json`. The LND host
  id and REST port are imported from `lnd-startos/startos/interfaces`; a
  change there is a change here.
- Go modules in `service/go.mod`: `go-nostr` and `khatru` move quickly and
  khatru is in maintenance mode (its successor lives at
  `fiatjaf.com/nostr/khatru`). Pin exact versions, read their changelogs for
  hook-signature changes before bumping, and rerun the e2e test.
- The Alpine base and the Go toolchain in `Dockerfile`. `google.golang.org/grpc`
  is pinned to the newest release that builds with that toolchain (1.80.x for
  Go 1.24); bump both together.
- The vendored LND protos in `service/proto/lnrpc` (see its README): replace
  from the LND tag you support and run `make proto` in `service/`.

## The sandbox modfile

`service/.sandbox/go.mod` exists for a development environment that reaches
GitHub but not the Go module proxy; it replaces non-GitHub modules with
mirrors or empty stubs. Build with `go build -modfile=.sandbox/go.mod ./...`
there, never anywhere else, and never let its replaces into `go.mod`.
