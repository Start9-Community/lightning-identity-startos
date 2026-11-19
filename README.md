<p align="center">
  <img src="icon.svg" alt="Lightning Identity" width="21%">
</p>

# Lightning Identity on StartOS

Lightning Identity gives an LND node **Lightning Addresses**, **Nostr NIP-05 names** and **Nostr Wallet Connect**, for any number of identities, from one public domain.

- **Lightning Addresses:** `name@yourdomain` is payable from any Lightning wallet ([LUD-16](https://github.com/lnurl/luds/blob/luds/16.md)) and can be zapped from Nostr, with a signed zap receipt for every zap ([NIP-57](https://github.com/nostr-protocol/nips/blob/master/57.md)).
- **NIP-05 names:** The same `name@yourdomain` verifies a Nostr profile ([NIP-05](https://github.com/nostr-protocol/nips/blob/master/05.md)).
- **Nostr Wallet Connect:** Nostr apps connect to an identity ([NIP-47](https://github.com/nostr-protocol/nips/blob/master/47.md)) to make invoices, read the balance and history, be notified of payments, and pay invoices. Each connection has its own permissions, budget and expiry.
- **A wallet for each identity:** Every identity has its own balance and history.
- **Sending payments only when authorized:** Receiving works from the start. Sending is off until the operator authorizes it in StartOS, under per-payment and 24-hour caps enforced inside LND.
- **Nothing else to run:** Includes a specialized Nostr relay for wallet traffic and zap receipts.
- **Static site option:** Serves a static website at the root of the public domain, uploaded as a zip archive through a StartOS action.

This is a native StartOS service: this repository is both the package and the upstream. It is designed around one rule: **the process that faces the internet holds no credentials, and the process that holds LND's admin macaroon listens on nothing.**

- **Repo:** <https://github.com/lundog/lightning-identity-startos>
- **Design document:** `docs/design.md` (the trust model, the reasons for it, and what is deferred to later milestones)

---

## Table of Contents

- [Image and Container Runtime](#image-and-container-runtime)
- [Processes and Trust Boundaries](#processes-and-trust-boundaries)
- [Volume and Data Layout](#volume-and-data-layout)
- [File Models](#file-models)
- [Dependencies](#dependencies)
- [Network Access and Interfaces](#network-access-and-interfaces)
- [Installation and First-Run Flow](#installation-and-first-run-flow)
- [Actions](#actions)
- [Tasks](#tasks)
- [Health Checks](#health-checks)
- [Backups and Restore](#backups-and-restore)
- [Limitations and Differences](#limitations-and-differences)
- [Quick Reference for AI Consumers](#quick-reference-for-ai-consumers)

---

## Image and Container Runtime

One image, built from `./Dockerfile`: three static Go binaries (`edge`, `core`, `guard`) from `service/` on Alpine, with three unprivileged users. The image has no entrypoint; each daemon names its binary. `guard` is launched as root and drops to its user itself after one read: LND exports `admin.macaroon` root-owned and not world-readable, on a read-only mount, so it can only be read before the drop (`cmd/guard/main.go`; `GUARD_RUN_AS=guard`). Nothing is created, opened or dialled before the drop, and the drop is verified irreversible.

| Property      | Value                                      |
| ------------- | ------------------------------------------ |
| Image         | `lightning-identity`, built from this repo |
| Architectures | x86_64, aarch64                            |
| Users         | `edge` 1001, `core` 1002, `guard` 1003     |

| Subcontainer | Runs                           | User    | Purpose                                                                         |
| ------------ | ------------------------------ | ------- | ------------------------------------------------------------------------------- |
| `prepare`    | `prepare-volume.sh` (oneshot)  | `root`  | Lays out and chowns the volume subpaths before every start                      |
| `guard`      | `/usr/local/bin/guard`         | `guard` | Reads `admin.macaroon`; bakes and renews the receive credential; reads the node's channels for the dashboard's liquidity view; no TCP listener |
| `core`       | `/usr/local/bin/core`          | `core`  | Identities, invoices, zap receipts, NWC, Admin UI on 8081                        |
| `edge`       | `/usr/local/bin/edge`          | `edge`  | Public HTTP on 8080: LNURL, NIP-05, relay, optional static site                  |
| `site-tool` (temporary) | `/usr/local/bin/edge site install\|remove` | `root` | Exists only while the Upload Site or Remove Site action runs; mounts `upload/` and `site/` and nothing else |

`attach` to `core` for application logs about invoices and NWC, to `guard` for credential problems, to `edge` for public traffic and the relay.

## Processes and Trust Boundaries

StartOS subcontainers share one network namespace and are isolated by mount namespace and uid. The package uses that: every process sees only its slice of the volume, and the three talk over unix sockets whose servers check the peer's uid (`SO_PEERCRED`), never over loopback TCP.

| Process | Can reach                                              | Holds                                                                 | Cannot see                                      |
| ------- | ------------------------------------------------------ | --------------------------------------------------------------------- | ----------------------------------------------- |
| `edge`  | the internet (inbound); `core` over `edge-core.sock`   | nothing secret: the identity document (read-only), relay events       | any credential, any key, the admin UI           |
| `core`  | LND REST over the bridge; `guard` over `guard.sock`; relays (outbound) | `recv.macaroon` (read-only), per-identity zap and NWC keys (sealed), the ledger (bbolt) | `admin.macaroon`, the guard's state directory   |
| `guard` | LND REST over the bridge                               | `admin.macaroon` (read-only directory mount), credentials it bakes    | the public interface, core's data, edge's data |

The receive credential is URI-scoped (`GetInfo`, `AddInvoice`, `LookupInvoice`, `SubscribeInvoices`, `invoicesrpc.Invoices/CancelInvoice` for self-pay — no list or balance RPCs; histories and balances come from core's own per-identity ledger), carries a `time-before` caveat (24 h, renewed hourly) and is verified against LND before it is published. There is deliberately no IP caveat: LND's REST on StartOS sits behind the OS's TLS proxy, so LND sees the proxy as the client of every REST call and an IP lock could not tell this service from a laptop on the LAN (the guard supports one via `GUARD_IPRANGE`, for a future gRPC client where it would mean something). A compromised `edge` can ask `core` for invoices and nothing else; a compromised `core` can create invoices, read its own ledger, and spend up to the guard's caps and no further.

**Sending** exists only after the Authorize Sending action. The guard then bakes a spend credential (`SendPaymentV2`, `TrackPaymentV2`, `DecodePayReq`) carrying, besides the two caveats above, `lnd-custom lightning-identity-guard <nonce>`. LND routes every request bearing that caveat to the guard's registered RPC middleware (gRPC, `RegisterRPCMiddleware`), which prices each `SendPaymentV2` by decoding its invoice, refuses anything over the per-payment cap or the rolling 24-hour cap, reserves the amount plus fee limit until LND reports the payment settled or failed, and refuses every other intercepted method that is not on its read-only list. While the middleware is not registered the credential is dead, not unrestricted. The nonce changes on every enable, so a credential from an earlier authorization is refused by the guard even though LND still accepts its signature. Core's per-connection budgets are a soft layer under the guard's caps; the e2e test proves a core that ignores its budget is still capped.

TLS to LND pins the StartOS root CA: `main` reads it with `sdk.getRootCa` on every start and hands it to `core` and `guard` as `LND_CA_PEM`, so it never lands on a volume; `core` also adds that root to the system roots (Alpine's `ca-certificates-bundle`) it verifies Nostr relays against, so a relay with a StartOS-issued certificate — this service's own public URL, another package's — works like a public one, though `core` never dials its own relay by its public name (loopback instead); LND's certificate is issued by that CA and its SANs cover the bridge address.

## Volume and Data Layout

Two volumes. `main` is split into subpaths, each mounted only where needed; `startos` is never mounted.

| Subpath (`main`) | Mounted in                                   | Owner   | Purpose                                                          |
| ---------------- | -------------------------------------------- | ------- | ---------------------------------------------------------------- |
| `edge/`          | edge rw `/edge`                              | `edge`  | relay event store (`relay.db`)                                   |
| `core/`          | core rw `/core`                              | `core`  | `core.db` (bbolt), `master.key` (0600)                           |
| `identities/`    | core rw, edge ro `/identities`               | `core`  | `edge.json`, the public identity document core writes for edge   |
| `credentials/`   | guard rw, core ro `/credentials`             | `guard` | `recv.macaroon`, `spend.macaroon` (only while sending is on), `status.json` |
| `guard/`         | guard rw `/guard`                            | `guard` | `state.json` (latch, caps, nonce, 24 h ledger); `authorization.json` written by the package action and consumed by the guard |
| `run/`           | all rw `/run/lightning-identity`             | root, 1777 | `guard.sock`, `edge-core.sock`                                |
| `site/`          | edge ro `/site`                              | root    | optional static site served at `/` while it holds an `index.html`; written by the Upload Site and Remove Site actions |
| `upload/`        | no daemon; the Upload Site one-off ro `/upload` | root, 0700 | a site archive between upload and unpacking; emptied of anything older than two hours at start |
| LND `public`, subpath `admin` | guard ro `/lnd/admin` | —  | `admin.macaroon` (and a copy of `tls.cert`) as LND exports it for dependents; LND's `main` volume (wallet seed, `tls.key`, `wallet.db`) is not mounted anywhere |

`startos` volume: `store.json` only (see File Models).

## File Models

| File         | Volume    | Format | Modeled             | Written by                                         |
| ------------ | --------- | ------ | -------------------- | -------------------------------------------------- |
| `store.json` | `startos` | JSON   | Yes, `FileHelper.json` | Set Primary Domain (`primaryUrl`), Set Admin Password (`adminPasswordHash`) |

`main.ts` reads both with `.const()`: changing the domain or the password restarts the service. The password itself is never stored; the scrypt hash reaches `core` as `ADMIN_PASSWORD_HASH`.

Everything the application itself configures (identities, connections) lives in `core/core.db` and is edited only through the Admin UI; the package models none of it.

## Dependencies

| Dependency | Required | Kind      | Health checks | Mounted                                        | Why                                      |
| ---------- | -------- | --------- | ------------- | ---------------------------------------------- | ---------------------------------------- |
| LND        | Yes      | `running` | `lnd`         | the `admin` tier of its `public` volume only, read-only, into `guard` | Invoices, settlement, node info |

LND's REST address is resolved over the bridge (`sdk.host.getBridgeAddress`, host `control`, internal port 8080) and injected as `LND_REST_URL`; its gRPC address (host `grpc`, port 10009, TLS passthrough) goes to the guard alone as `LND_GRPC_ADDRESS` for the middleware stream. Until LND has unlocked and bound it, the variable is omitted, the guard logs that it is waiting, the Credentials check stays red, and `main` heals with one restart when the binding appears. The version range (`>=0.21.1-beta:4`) is where lnd-startos forces `rpcmiddleware.enable`, which phase 2's spend caps need.

## Network Access and Interfaces

| Interface | Id       | Type  | Port | Served by | Description                                                                      |
| --------- | -------- | ----- | ---- | --------- | -------------------------------------------------------------------------------- |
| Public    | `public` | `api` | 8080 | edge      | `/.well-known/lnurlp/{name}`, `/lnurlp/{name}/callback`, `/lnurlp/{name}/verify/{hash}`, `/.well-known/nostr.json`, `/relay` (WebSocket + NIP-11), `/health`, optional static site at `/` |
| Admin UI  | `admin`  | `ui`  | 8081 | core      | Identity and NWC management, password-protected                                 |

Both are `protocol: 'http'` bindings: the OS terminates TLS and adds `X-Forwarded-For`/`-Proto`. **Only the Public interface should ever get a public domain**; the Admin UI is for LAN/Tor. The edge trusts only the rightmost `X-Forwarded-For` value.

Limits on the Public interface, all per client (an IPv4 address, or an IPv6 /64):

| Limit | Value | What happens |
| --- | --- | --- |
| Requests | 60 a minute, 60 at once (`EDGE_REQUESTS_PER_MINUTE`) | `429`, logged at most once a minute per client |
| Not-found answers (`404`/`405`) | more than 20 in a minute | the client is refused everything (`429` with `Retry-After`) for 10 minutes; logged once when the block starts and once when it ends, with the number of requests refused |
| Invoice requests per Lightning Address | 60 a minute (`EDGE_INVOICES_PER_MINUTE`) | LNURL error |

The not-found block is what stops a vulnerability scanner (`/.env`, `/.git/config`, …): a real wallet or browser almost never causes a 404. Only public addresses can be blocked — if the client address is a private one (a proxy in front that does not pass the real address on), every visitor shares it, so it is rate limited but never blocked. `core`'s own loopback connection to the relay is exempt from all three. The static site and the default page answer `GET` and `HEAD` only. `/health` returns `{"ok":true}` (200) or `{"ok":false}` (503) and nothing else, and asks `core` at most once every 10 seconds however often it is requested. The relay has its own per-client connection and event limits.

Outbound: `core` connects to the embedded relay over loopback (`ws://127.0.0.1:8080/relay`) and to any relays an identity lists, to publish zap receipts, NWC responses and notifications and to subscribe to NWC requests.

## Installation and First-Run Flow

1. Install with LND installed and unlocked (order does not matter; the package heals).
2. Two tasks appear: **Set Admin Password** (critical) and **Set Primary Domain** (critical); both must be done before the service can start.
3. Add a public domain to the **Public** interface, then run Set Primary Domain and pick it.
4. Open the Admin UI (LAN), sign in, add an identity. Its address is `name@<domain>` at once; its NIP-05 is live if a Nostr pubkey was given.
5. For NWC, create a connection on the identity's page; the URI/QR is shown once.

No credential exists until LND is unlocked; the guard bakes it within seconds of LND's REST port appearing.

## Actions

### Set Primary Domain (`set-primary-domain`)

- **When:** after adding a public domain to the Public interface; again if it changes.
- **Changes:** `primaryUrl` in `store.json`, hence `BASE_URL`/`RELAY_URL` for core and the host part of every address.
- **Cost:** restarts the service.
- **Repeat safety:** idempotent; last choice wins.
- **Input:** a select of the Public interface's TLS domain addresses only (`filter: { kind: 'domain' }, ssl: true, fallback: false`). Empty means no domain has been added yet.

### Set Admin Password (`set-admin-password`)

- **When:** first run, and to rotate.
- **Changes:** `adminPasswordHash` in `store.json` (scrypt, N=16384 r=8 p=1).
- **Cost:** restarts the service (core reads the hash at start).
- **Repeat safety:** destructive on rerun — replaces the password; the action warns once a hash exists.
- **Output:** the new password, masked and copyable, shown once.

### Authorize Sending (`authorize-sending`)

- **When:** to enable NWC payments, to raise a cap, or to disable sending from StartOS (disabling and lowering are also one click in the Admin UI).
- **Input:** enabled (toggle), maximum per payment (sats), maximum per 24 hours (sats); the first must not exceed the second.
- **Changes:** writes `guard/authorization.json` on the `main` volume — a directory only the guard subcontainer mounts. The guard consumes it within seconds (deletes the file, records its id so a replay is inert), sets the latch and caps, mints a fresh nonce on every enable, and bakes `credentials/spend.macaroon` once its middleware is registered. Disabling removes the credential.
- **Cost:** none to the running service; no restart.
- **Repeat safety:** idempotent per file; each run is a new authorization that replaces the caps.

### Rebake Credentials (`rebake-credentials`)

- **When:** after LND's Revoke Macaroons, or after restoring a backup onto another LND.
- **Changes:** nothing persistent; restarts the service so the guard bakes at once instead of at its next hourly tick.
- **Cost:** a restart. Only while running.


### Upload Site (`upload-site`)

- **When:** to put a static website at the root of the public domain, or to replace or add to the one there.
- **Input:** one `.zip` archive (at most 50 MB; StartOS receives it into `upload/` on the `main` volume, which nothing serves), and **Keep existing files** (off by default).
- **Changes:** the contents of `site/`. With Keep off the archive becomes the whole site: it is unpacked and checked in a hidden work folder first, then swapped in, so an archive that is refused leaves the current site untouched. With Keep on its files are added, replacing those with the same path and removing nothing.
- **What the unpacker accepts** (`service/internal/site`, run once as `edge site install` in a throwaway container that mounts `upload/` and `site/` and nothing else): an `index.html` at the top level, or inside a single folder wrapped around everything (what Finder and Explorer produce), which is then dropped from the paths. At most 2,000 files and 200 MB unpacked, measured as it is written and not taken from the archive's headers. An archive is refused whole if any name is absolute, climbs out with `..`, contains a control character or is not UTF-8, if a path is both a file and a folder, or if it is password-protected. A path listed twice is accepted and the later entry stands (Finder writes a file twice when a folder and the files in it were both selected). Left out without refusing: hidden files and folders (anything starting with a dot, so a zipped project folder does not publish its `.git` or `.env`; a top-level `.well-known` is the one exception), `__MACOSX`, `Thumbs.db` and `desktop.ini`, and links and special files. Files are installed `0644`, folders `0755`.
- **Cost:** none to the running service; no restart. Edge checks for `site/index.html` on each request.
- **Repeat safety:** with Keep off, destructive on rerun (the action warns); with Keep on, additive. The archive is deleted when the action ends, whether or not it succeeded.
- **Output:** how many files were installed and their size, and anything that was left out.

### Remove Site (`remove-site`)

- **When:** to take the static website down.
- **Changes:** deletes everything in `site/`. The domain shows the plain default page again on the next request; the address, NIP-05 and relay endpoints are unaffected.
- **Cost:** none to the running service; no restart.
- **Repeat safety:** destructive (the action warns); a second run finds nothing to remove.

## Tasks

| Task                 | Severity    | Raised when                                    | Cleared when                             |
| -------------------- | ----------- | ---------------------------------------------- | ---------------------------------------- |
| Set Admin Password   | `critical`  | No password hash is stored (fresh install)     | The action runs                          |
| Set Primary Domain   | `critical`  | No domain chosen, or the chosen one is gone    | A current domain is chosen; can return   |

## Health Checks

| Check  | Daemon | Displayed as       | Method                                                    |
| ------ | ------ | ------------------ | --------------------------------------------------------- |
| guard  | guard  | Credentials        | `test -s /credentials/recv.macaroon` (grace 60 s)         |
| core   | core   | Admin UI           | port 8081 listening                                       |
| edge   | edge   | Public endpoints   | port 8080 listening                                       |

Credentials red with the others green means LND is locked or unreachable: the guard's `status.json` (in `credentials/`, also on the Admin UI's System page, with a summary on the dashboard) names the state and the last error. Public endpoints green does not mean invoices work; `core`'s log does.

## Backups and Restore

`main` and `startos`, excluding `credentials/**` and `run/**`. `core/master.key` is included deliberately: a restore brings every identity, zap key and NWC pairing back working. Nothing in the backup is tied to a particular LND node; after restoring beside a different LND, run Rebake Credentials (or wait an hour). Uninstalling revokes nothing on LND — macaroons are revoked by LND's own Revoke Macaroons action.

## Limitations and Differences

1. **Sending is off by default** and `pay_invoice` returns `RESTRICTED` until Authorize Sending has run; keysend is not implemented (see 10). The routing fee limit per payment is an operator setting (default 1 % of the amount, never less than 10 sats; see 7): it is held from the identity's balance and counts toward both caps while the payment is in flight, and only the fee actually paid is kept once it settles. A payment is booked only on LND's verdict: if the wallet's wait (75 s) runs out first, the payment stays **pending**, keeps holding the identity's balance and the guard's window, and is resolved from LND's record (`TrackPaymentV2`, every 30 s) however long that takes — there is no timeout after which it is assumed to have failed. The wallet is told it is still in flight (`OTHER`, not `PAYMENT_FAILED`). Pending payments cannot be resolved while sending is disabled; they stay held until it is enabled again.
2. **One domain, HTTPS only.** Addresses need a public domain on the Public interface; Tor and `.local` cannot be resolved by payers. The relay URL in NWC strings is `wss://<domain>/relay`.
3. **Identities are virtual wallets on one node.** Each has a ledger balance (received + operator adjustments − sent − in flight) that starts at zero, gates `pay_invoice` (`INSUFFICIENT_BALANCE`) and is what `get_balance` reports, regardless of any connection budget. Credits and debits in the Admin UI are bookkeeping only: nothing moves on the node, and the sum of all balances is not checked against channel liquidity, so a payment can still fail at LND. Adjustments appear in `list_transactions` as settled entries without an invoice (synthetic `payment_hash`, `metadata.adjustment: true`), as LNbits reports a top-up. `lookup_invoice` finds both directions for the identity, by payment hash or BOLT11 string: an invoice it issued or a payment it sent (pending, settled or failed); where one identity paid its own invoice, the connection that made the invoice gets the incoming side and a connection that only paid gets the outgoing one. Another identity's records are `NOT_FOUND`. Who a transaction was with comes from the zap request, in `metadata.nostr`: an incoming zap carries the request this service received (its `pubkey` is the sender); an outgoing payment carries whatever the paying app attached to `pay_invoice` as `metadata` (or a zap request sent as a JSON string in `description`), whose `p` tag is the recipient. An app that attaches nothing — Damus's zap button, as of its 2026-09 source — leaves the recipient unknown, and its wallet view says so; the `nwc: pay_invoice` log line shows what the app sent. That metadata is the app's own claim, kept verbatim up to 8 KiB and not checked against the invoice. A self-payment with none falls back to the zap request on this node's own invoice. A private zap's request is signed by a throwaway key with the real sender encrypted inside for the recipient; this service passes it on untouched and cannot read it. A `list_transactions` reply is one Nostr event and is trimmed to fit the relay (60,000 bytes of JSON on the embedded relay, 40,000 on any other): when a page is too large, settled entries lose their BOLT11 string first, then the oldest entries lose `metadata` (the zap request), then the oldest entries are dropped; payment hash, preimage, amounts and times are never removed from an entry that is sent.
4. **No BOLT12/BIP-353** in this release.
5. **The relay stores only** zap receipts and NWC info events, from keys this service knows; NWC requests, responses and notifications are ephemeral and never written to disk — requests and responses are held in memory for 60 seconds so that a wallet which asks before it subscribes (Damus does), or a request that arrives while `core`'s subscription is restarting, is not lost — and profiles, relay lists and notes are refused. It is not a general relay and is not advertised in NIP-05. An identity may run its NWC on a different relay instead (per-identity setting); the embedded relay is the default.
6. **LND 0.21.6-beta:3 or later** is required: it is the first build that exports `admin.macaroon` on LND's `public` volume, which is what the guard mounts. LND's two other tiers are not used: `payments` carries an uncapped `SendPaymentV2` and `readonly` cannot bake, and neither can register the middleware the caps depend on. Also fixed: `core` connects only to public addresses, except for relays the operator configured (the embedded relay, an identity's receipt relays or NWC relay). A relay on the LAN that a zapper names in a zap request is skipped unless it is also listed on the identity; at most 16 relays from one zap request are tried.
7. **Lightning settings** (route hints, self-pay, invoice expiry, routing fee limit) live on the Admin UI dashboard and apply to new invoices and payments at once; `INVOICE_PRIVATE` and `INVOICE_EXPIRY_SECONDS` in core's environment only set the defaults before the operator first saves. Self-pay settles one of this node's own invoices between identities in the ledger (LND cannot route to itself): the payer is debited, the payee credited with the real preimage, the LND invoice is cancelled, no fee, and the guard's caps are not consumed. With self-pay off such a payment is refused up front. The routing fee limit is what core passes to LND as `fee_limit_msat`: a percentage of the amount (0–10 %) with a floor (0–1000 sats), not both zero. The floor matters more than the percentage for zaps — most nodes charge a base fee of about a sat per hop whatever the amount, so a limit of 1 % of 3 sats finds no route (the first on-node zaps failed with `FAILURE_REASON_NO_ROUTE` under the original 1-sat floor). A payment needs amount + limit available in the identity's balance, so with the default a 1-sat zap needs 11 sats on hand and gets back whatever the route did not charge.
8. **Every Nostr event is logged** at info level: events received on the NWC subscription (kind, id, pubkey, `p`, relay), every NWC request with its method and outcome, every event this service publishes (kind, id, which relays accepted or failed), every zap request at the edge, and every event the relay accepts or rejects with the reason and the client IP; `edge` also writes one access-log line per HTTP request (client IP, method, path, status, duration, user agent). The client IP is the rightmost `X-Forwarded-For` the OS proxy sets. Events reaching `core` over Nostr carry no IP (the relay is the only process that sees the socket); the event id is shared between `edge`'s accept line and `core`'s received line, which is how to join them. Read `core`'s log for NWC and zaps, `edge`'s for the relay and HTTP.
9. **Liquidity on the dashboard is a reading, not a control.** The guard reads LND's channel list with the admin macaroon (core's credentials cannot) at most every 30 seconds and reports totals over its socket: what the node can send and receive across online channels (each side's balance less the reserve it must keep; routing fees and per-payment limits are not counted) and a row per channel. The page shows the two totals and the rows without that explanation. The dashboard warns when there is no room to receive, when channels are offline, and when the identities' balances add up to more than the node can send. None of it is exposed to wallets: NWC `get_balance` remains the identity's ledger balance. Amounts in the Admin UI are written as wallets write them: thousands separators and "sats" (`1,290,000 sats`, `1 sat`).
10. **Nostr Wallet Connect: what is implemented.** The five methods of [NIP-47](https://github.com/nostr-protocol/nips/blob/master/47.md) (`pay_invoice`, `make_invoice`, `lookup_invoice`, `get_balance`, `get_info`) and three of the optional [NWC specifications](https://github.com/nostr-wallet-connect/nwc): **02** notifications (`payment_received`, `payment_sent`; kind 23197 under NIP-44 and kind 23196 under NIP-04), **05** `list_transactions`, and **06** metadata conventions (metadata over 4096 characters is dropped). The info event and `get_info` list them as `extensions: 02 05 06`; NIP-44 is preferred, NIP-04 accepted, and anything else is answered with `UNSUPPORTED_ENCRYPTION`. Not implemented, and not advertised: hold invoices (03), keysend (04), connection deep links (07, 08), `lookup_payment` (09), BOLT12 (12), `get_budget` (13) and BIP-321 (321). `get_info` gives a connected app the node's alias and public key, as the method is defined. A connection's secret is shown once and never stored, as NIP-47 asks, so a lost connection string means a new connection.
11. **The static site is static files and nothing else.** No server-side code, no per-path headers, no redirects. It is served only while `site/` holds an `index.html`; folders without one of their own are not listed; requests other than GET and HEAD are refused; and no path with a hidden segment is ever served (`/.env`, `/.git/…`, the installer's work folders), except under a top-level `/.well-known/`. The Upload Site action accepts `.zip` only. Files put into `site/` by hand over SSH are served under the same rules.
12. **StartOS 0.4.2 or later** is required: the Upload Site action uses the action file uploads that arrived with it (start-sdk 4.1.0).
13. **The Admin UI runs no script.** Its content security policy allows none, so every page is plain HTML and forms: a destructive button opens an inline confirmation instead of a dialog, and a result (including a new NWC connection string) is put away by a link that reloads the page. The dashboard carries what an operator acts on — identities, liquidity, sending caps, Lightning settings — and names any fault; the node, the guard and the credentials it bakes are on the **System** page.
14. **Payments are learned from LND's invoice stream, with a direct check behind it.** A settlement normally arrives on the stream within milliseconds. Because a stream can stall without ending, core also looks up its open invoices in LND every two minutes, restarts the stream if that finds a payment it should already have delivered, and asks LND about a single invoice when a wallet looks it up (NWC `lookup_invoice`, LUD-21 `verify`), limited to about one lookup every three seconds per invoice. Whichever path sees a payment first, it is settled, receipted and notified once.

---

## Quick Reference for AI Consumers

```yaml
package_id: lightning-identity
image: built from ./Dockerfile # service/ (Go) → edge, core, guard on Alpine
architectures: [x86_64, aarch64]
subcontainers:
  prepare: { oneshot: prepare-volume.sh, user: root }
  guard: { binary: /usr/local/bin/guard, user: root -> drops to guard (uid 1003) after reading admin.macaroon into memory; exits on macaroon rotation so the runtime restarts it }
  core: { binary: /usr/local/bin/core, user: core, uid: 1002 }
  edge: { binary: /usr/local/bin/edge, user: edge, uid: 1001 }
volumes:
  main:
    edge/: edge rw
    core/: core rw # core.db, master.key
    identities/: core rw, edge ro # edge.json
    credentials/: guard rw, core ro # recv.macaroon, status.json
    guard/: guard rw
    run/: all, sockets
    site/: edge ro, optional static site # written by upload-site / remove-site
    upload/: no daemon # a site archive between upload and unpacking
  startos: not mounted # store.json
file_models:
  - store.json # primaryUrl, adminPasswordHash
dependencies:
  - lnd # required >=0.21.6-beta:3, running, healthChecks [lnd]; mount volume `public` subpath `admin` ro into guard only
interfaces:
  public: { type: api, port: 8080, process: edge, paths: [/.well-known/lnurlp/*, /lnurlp/*, /.well-known/nostr.json, /relay, /health, /] }
  admin: { type: ui, port: 8081, process: core }
startos_managed_env_vars:
  - LND_REST_URL # bridge address; omitted until LND binds
  - LND_GRPC_ADDRESS # guard only; bridge address of LND's gRPC
  - BASE_URL, RELAY_URL # from primaryUrl; omitted until set
  - ADMIN_PASSWORD_HASH # from store.json; omitted until set
  - GUARD_IPRANGE # <os ip>/24
actions: [set-primary-domain, set-admin-password, rebake-credentials, authorize-sending, upload-site, remove-site]
tasks:
  - { action: set-admin-password, severity: critical }
  - { action: set-primary-domain, severity: important }
health_checks: [guard "Credentials", core "Admin UI", edge "Public endpoints"]
credentials:
  receive: { methods: [GetInfo, AddInvoice, LookupInvoice, SubscribeInvoices, invoicesrpc.Invoices/CancelInvoice], caveats: [time-before 24h], renew: 1h }
  spend: { methods: [routerrpc.Router/SendPaymentV2, routerrpc.Router/TrackPaymentV2, lnrpc.Lightning/DecodePayReq], caveats: [time-before 24h, lnd-custom lightning-identity-guard <nonce>], exists: only while sending is authorized and the middleware is registered }
guard_socket_requests: [status, rebake, lower_caps, disable_sending] # core only; raising caps/enabling is the action
static_site: { action_input: one .zip, max_archive_mb: 50, max_unpacked_mb: 200, max_files: 2000, requires: index.html at top level (one wrapping folder allowed), skipped: [hidden files except top-level .well-known, __MACOSX, Thumbs.db, desktop.ini, links], modes: [replace (default), keep existing files], restart: none, unpacker: 'edge site install|remove' in a temp container mounting upload/ and site/ only }
min_startos: 0.4.2 # start-sdk 4.1.0, for action file uploads
nwc: { nip47_methods: [pay_invoice, make_invoice, lookup_invoice, get_balance, get_info], extensions: ['02', '05', '06'], extension_methods: [list_transactions], notifications: [payment_received, payment_sent], notification_kinds: { nip44_v2: 23197, nip04: 23196 }, encryption: [nip44_v2, nip04], metadata_max_chars: 4096 }
```
