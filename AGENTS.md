# AGENTS.md

This is a StartOS service-package repository — it builds a `.s9pk` for StartOS —
and, unlike most, it also contains the service itself (`service/`, Go).

Develop it inside a StartOS packaging workspace created by `start-cli s9pk init-workspace`,
which provides the packaging guide one level up (or <https://docs.start9.com/packaging>).
Start packaging tasks at the recipe index, <https://docs.start9.com/packaging/recipes.html>.

Keep `README.md` (technical reference) and `instructions.md` (end-user docs) in sync with
your changes; `docs/design.md` is the rationale and is updated when a decision changes, not
for every edit.

## This repo

- The three-process split is the product. Never mount `credentials/`, `guard/` or any LND
  volume into `edge`; never mount LND's `main` volume anywhere (its `store.json` holds the
  wallet password and cipher seed) — the guard mounts the `admin` tier of LND's `public`
  volume and nothing else of LND's; never give `core` the admin macaroon. If a feature seems
  to need one of these, it needs a new socket request type instead, and that request type
  gets size bounds and a test in `internal/e2e`.
- `edge` ↔ `core` speaks exactly the request types in `internal/core/edgeipc.go`. Adding
  one is a security review, not a refactor.
- The uids in `startos/utils.ts`, the users in `Dockerfile` and `assets/prepare-volume.sh`
  must agree. Sockets are world-connectable on purpose; the uid check on accept is the auth.
- `go build` in the sandbox uses `-modfile=.sandbox/go.mod`; the real `go.mod` carries no
  replaces. Run `go mod tidy` on a machine with module access before a release.
- `service/internal/admin/static/icon.svg` is a copy of the root `icon.svg` (the Admin UI
  embeds it; `go:embed` cannot reach above the module). Change the root icon, then copy it
  over; `TestIcon` fails while they differ.
- `internal/site` turns an uploaded zip into public files. Every rule there has a test that
  fails when the rule is removed; keep it that way, and never let an archive be written
  into `site/` itself.
- Everything the internet can send core goes through `internal/e2e`; keep that test green
  and extend it with every protocol change.
