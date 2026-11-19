# Vendored LND protocol definitions

`lightning.proto`, `stateservice.proto` and `routerrpc/router.proto` are copied
verbatim from [`lightningnetwork/lnd`](https://github.com/lightningnetwork/lnd)
at tag **v0.21.2-beta** (`lnrpc/lightning.proto`, `lnrpc/stateservice.proto`,
`lnrpc/routerrpc/router.proto`), under lnd's MIT licence (`LICENSE.lnd`).

They are vendored rather than the `lnd` Go module imported, which would drag
btcd, btcwallet and a few hundred transitive modules into the process that
holds `admin.macaroon`. Nothing here is hand-edited. To move to a newer LND,
replace the files from that tag and run `make proto` in `service/` (needs
`buf`, `protoc-gen-go` and `protoc-gen-go-grpc` on PATH); the generated code
lands in `internal/lndrpc/`.

The buf module is rooted here, not at `proto/`, because `router.proto` says
`import "lightning.proto"` — a bare path that resolves only with
`lightning.proto` at the module root.
