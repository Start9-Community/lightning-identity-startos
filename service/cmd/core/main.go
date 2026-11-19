// Command core runs the identity/invoice/NWC service and the admin UI.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/admin"
	"github.com/lundog/lightning-identity-startos/service/internal/core"
	"github.com/lundog/lightning-identity-startos/service/internal/httpx"
	"github.com/lundog/lightning-identity-startos/service/internal/nwc"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: httpx.LogLevel()}))
	slog.SetDefault(log)

	baseURL := strings.TrimRight(httpx.Env("BASE_URL", ""), "/")
	relayURL := httpx.Env("RELAY_URL", "")
	if relayURL == "" && baseURL != "" {
		relayURL = "wss://" + strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://") + "/relay"
	}
	caFile, err := httpx.CAFile("/etc/lightning-identity/lnd-ca.pem")
	if err != nil {
		log.Error("LND CA", "err", err)
		os.Exit(2)
	}
	// Nostr relays are dialled through the default transport: trust the
	// system roots and, on top, the StartOS root CA (the same PEM that pins
	// LND), so a relay on this box or this LAN with a StartOS-issued
	// certificate — our own public URL, another package's relay — verifies
	// like any public one. LND itself keeps its own pinned-only transport.
	if err := httpx.TrustExtraCA(caFile); err != nil {
		log.Warn("could not add the StartOS root CA to the relay trust store", "err", err)
	}
	cfg := core.Config{
		DataDir:        httpx.Env("CORE_DATA", "/core"),
		CredentialsDir: httpx.Env("CREDENTIALS_DIR", "/credentials"),
		IdentitiesDir:  httpx.Env("IDENTITIES_DIR", "/identities"),
		GuardSocket:    httpx.Env("GUARD_SOCKET", "/run/lightning-identity/guard.sock"),
		EdgeSocket:     httpx.Env("EDGE_SOCKET", "/run/lightning-identity/edge-core.sock"),
		EdgeUIDs:       httpx.EnvUIDs("EDGE_UIDS"),
		LNDRestURL:     httpx.Env("LND_REST_URL", ""),
		LNDCAFile:      caFile,
		BaseURL:        baseURL,
		RelayURL:       relayURL,
		LocalRelayURL:  httpx.Env("LOCAL_RELAY_URL", "ws://127.0.0.1:8080/relay"),
		DefaultRelays:  splitList(httpx.Env("DEFAULT_RELAYS", "")),
		InvoiceExpiry:  time.Duration(httpx.EnvInt("INVOICE_EXPIRY_SECONDS", 900)) * time.Second,
		InvoicePrivate: httpx.Env("INVOICE_PRIVATE", "true") != "false",
		Log:            log,
	}
	if cfg.LNDRestURL == "" {
		log.Warn("LND_REST_URL is not set: LND has not bound its REST port yet; invoices will fail until it does")
	}
	svc, err := core.New(cfg)
	if err != nil {
		log.Error("core setup", "err", err)
		os.Exit(1)
	}
	defer svc.Close()
	svc.PublishIdentities()

	n := nwc.New(svc, log)
	adm, err := admin.New(admin.Options{Core: svc, NWC: n, PasswordHash: httpx.Env("ADMIN_PASSWORD_HASH", ""), Log: log})
	if err != nil {
		log.Error("admin setup", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := svc.ServeEdge(ctx); err != nil {
			log.Error("edge socket", "err", err)
			stop()
		}
	}()
	// From here on, relay connections go only to public addresses or to
	// relays the operator configured. Before anything dials.
	if err := httpx.RestrictOutbound(svc.TrustedDial); err != nil {
		log.Error("cannot restrict outbound connections", "err", err)
		os.Exit(2)
	}
	go svc.WatchInvoices(ctx)
	go svc.RetryReceipts(ctx)
	go svc.ReconcilePayments(ctx)
	go n.Run(ctx)

	hs := &http.Server{
		Addr:              httpx.Env("ADMIN_LISTEN", ":8081"),
		Handler:           adm,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(c)
	}()
	log.Info("core: admin UI listening", "addr", hs.Addr, "domain", svc.Domain())
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("admin server", "err", err)
		os.Exit(1)
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
