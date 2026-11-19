# Lightning Identity

## What it gives you on StartOS

Two interfaces. The **Public** interface is the one you put a domain on: it answers Lightning Address lookups, NIP-05 lookups and hosts a small Nostr relay, and it holds no keys or credentials. The **Admin UI** is where you manage identities; keep it on your LAN or Tor.

Everything is paid into your own LND. Sending from it over Nostr Wallet Connect is off until you turn it on with the **Authorize Sending** action, where you also set two hard caps — per payment and per 24 hours — that a separate guard process enforces inside LND on every payment this service makes, so no app and no bug in this service can exceed them. Payments you make from other wallets on the same node are unaffected; the caps bound this service, not your node.

## Getting set up

Install LND first and unlock it. Then:

1. Run **Set Admin Password** from the Actions list and copy the password it shows. It is not shown again; run the action again to get a new one.
2. Open the **Public** interface, add a **public domain** (for example `yourdomain.com`, or a subdomain `pay.yourdomain.com`) and let the certificate be issued.
3. Run **Set Primary Domain** and pick that domain. The service restarts.
4. Open the **Admin UI**, sign in with the password, and click **Add identity**. Enter the name you want before the `@`, and your Nostr public key (npub) if you want NIP-05 for that name.

Your Lightning Address is now `name@yourdomain` and, with an npub set, the same text works as your NIP-05 in Nostr clients. Add as many identities as you like; each has its own address, its own zap-signing key and its own wallet service key.

If you want a static website on the same domain, run **Upload Site** from the Actions list and choose a `.zip` of your site. It needs an `index.html` at its top level; zipping the site's folder itself is fine. The public interface serves it at `/` straight away, with no restart, while keeping the address endpoints. To change the site, upload again: by default the new archive replaces the old site entirely, or turn on **Keep existing files** to add to it. **Remove Site** takes it down. The archive may be up to 50 MB, with at most 2,000 files and 200 MB unpacked. Hidden files (names starting with a dot, such as `.git` or `.env`) are left out so that zipping a project folder does not publish them; a top-level `.well-known` folder is the exception. Keep your own copy of the site: this service's backups include it, but Remove Site and a replacing upload delete it for good.

Anything on a public domain gets probed by scanners looking for files such as `/.env` or `/.git/config`. None of that exists here, and an address that asks for more than 20 missing pages in a minute is refused entirely for 10 minutes. You will see one `edge: address blocked` line in the log when that happens, instead of hundreds of `404` lines.

## Using the available features

**Lightning Addresses and zaps.** Anyone can pay `name@yourdomain` from a Lightning wallet. Nostr clients zap it, and the receipt is published to the relays the zapper named, to any extra receipt relays you listed on the identity, and to this service's own relay. Each identity has its own minimum, maximum and comment length.

**NIP-05.** Put `name@yourdomain` in the NIP-05 field of your Nostr profile; clients verify it against this service. It returns no relay hint: this service's relay is not where your notes live, and nothing about it needs to appear in your profile.

**Nostr Wallet Connect.** Each identity's wallet service runs on this service's own relay unless you give the identity a different NWC relay in its settings; whichever it is, the connection string names it and the app connects there, and only there, for its wallet traffic. On an identity's page, create a connection: pick the permissions (including `pay_invoice` if the app should be able to pay), an optional budget per day/week/month and a per-payment limit for that app, an optional expiry, and whether the app should be notified of payments. Paste or scan the connection string into the app right away; it is shown once and never stored. Revoke a connection from the same page whenever you like. Every app sees the identity's own balance (see below), whether or not its connection has a budget. An app that asks for wallet information (`get_info`) is told your node's alias and public key, so connect only apps you are content to show that to. What a connected app can do: make and look up invoices, read the balance and history, be notified of payments, and pay invoices if you allow it. Keysend, hold invoices and BOLT12 are not supported.

**Balances.** Each identity is a wallet of its own, starting at 0 sats. Payments to its address add to its balance; payments it sends subtract the amount and fee. On the identity's page you can credit or debit the balance by hand, for an opening balance or to move value between identities. That changes the number only — no sats move on your node — so if you credit more than your node can actually send, a payment will still fail at LND. An identity can never spend more than its balance, even when sending is authorized with higher caps. Credits and debits show up in your wallet app's history like any other transaction, just without an invoice behind them.

**The Admin UI** opens on a dashboard that lists your identities first, then liquidity, sending and Lightning settings. Click an identity's name to manage it; **← Dashboard** at the top of every page brings you back. The **System** page (top right) shows the technical details: your LND node, the guard, and the credentials it has baked. You only need it when something is wrong, and when something is, the dashboard says so in a **Needs attention** box.

**Liquidity** on the Admin UI dashboard shows what your node's channels can carry right now: how much it can send and how much it can receive. Identity balances are bookkeeping; this is the real limit behind them. A warning appears when there is no room to receive (payments to your addresses and zaps will fail), when a channel's peer is offline, or when your identities together hold more than the node could pay out. The figures are approximate and refresh about every 30 seconds.

**Lightning settings** on the Admin UI dashboard apply to new invoices immediately. Turn **route hints** on if your channels are private (unannounced) — without them nobody can find a path to you. **Self-pay** settles an invoice issued by this node between two of your identities without a Lightning payment, since a node cannot route to itself; the payer's balance goes down, the payee's goes up, and no fee is charged. Note that this only applies to payments made through this service's wallet connections: a wallet that pays through LND directly (Zeus on the same node, for example) can never pay this node's own invoices. **Invoice expiry** is how long each invoice stays payable once it has been created for someone paying your Lightning Address or zapping you. Your address itself never expires; a payer who waits too long simply gets a fresh invoice the next time they try. **Routing fee limit** is the most an outgoing payment may cost to route: a percentage of the amount, but never less than a minimum you set (1% and 10 sats by default). It is a ceiling, not a charge — the real fee is usually a few sats and only that is deducted. If small payments or zaps from a connected wallet fail with "no route" while the same invoice pays fine from another wallet, raise the minimum: most nodes charge about a sat per hop no matter how small the payment. The limit is set aside from the identity's balance while a payment is in flight, so a payment needs its amount plus the limit available (a 1-sat zap needs 11 sats on hand with the defaults), and it counts toward the per-payment cap you chose when you authorized sending.

**Sending.** Run **Authorize Sending** in StartOS, choose the per-payment and 24-hour caps, and save. Within a few seconds the Admin UI dashboard shows sending enabled with the caps in force. Lowering a cap or disabling sending is a click on that dashboard; raising a cap or re-enabling always goes back through the StartOS action. A payment an app requests is refused if it would exceed the identity's balance, the connection's own budget, the per-payment cap, or what is left of the 24-hour cap, and the app is told which. A payment that has not finished when the app stops waiting is not treated as failed: it shows as pending on the identity's page, its amount stays set aside, and it is marked sent or released once your node knows how it ended. If an app says a payment is "still in flight", do not pay the same invoice again another way until it resolves.

**The relay** at `wss://yourdomain/relay` is not a general relay and you never need to add it to a Nostr client. It carries the wallet traffic between your apps and this service (held in memory for a minute at most, never saved), keeps each identity's wallet-service info event, and stores zap receipts. It accepts nothing else and from no other keys.

**Keys.** Each identity's zap key and wallet key can be rotated from its page. Rotating the wallet key revokes all of that identity's connections, since each connection string names the key.

**Logs.** Every Nostr event in or out is logged with its kind, id and the sender's public key: wallet requests and their outcome in the `core` log, events the relay accepted or refused (and why, and from which IP) plus every web request with its IP in the `edge` log. When a zap or a wallet app misbehaves, that is the place to look.

**Rebake Credentials** restarts the service so it fetches a fresh LND credential immediately. Use it after revoking macaroons in LND or after restoring a backup onto a different node; otherwise credentials renew on their own every hour.

## Documentation

- [LUD-16 Lightning Address](https://github.com/lnurl/luds/blob/luds/16.md) — the address format wallets resolve
- [NIP-05 Nostr verification](https://github.com/nostr-protocol/nips/blob/master/05.md) — how `name@domain` is verified in Nostr clients
- [NIP-47 Nostr Wallet Connect](https://github.com/nostr-protocol/nips/blob/master/47.md) — the protocol your Nostr apps use to talk to this wallet service
- [NIP-57 Lightning Zaps](https://github.com/nostr-protocol/nips/blob/master/57.md) — zap requests and receipts
