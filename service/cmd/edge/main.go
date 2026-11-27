// Command edge is the public HTTP process (see internal/edge).
package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/edge"
	"github.com/lundog/lightning-identity-startos/service/internal/httpx"
	"github.com/lundog/lightning-identity-startos/service/internal/identity"
	"github.com/lundog/lightning-identity-startos/service/internal/ipc"
	"github.com/lundog/lightning-identity-startos/service/internal/relay"
)

func main() {
	// `edge site ...` is a one-off, not the daemon: see site.go.
	if len(os.Args) > 1 && os.Args[1] == "site" {
		os.Exit(siteCommand(os.Args[2:]))
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: httpx.LogLevel()}))
	slog.SetDefault(logger)

	listen := httpx.Env("EDGE_LISTEN", ":8080")
	identitiesDir := httpx.Env("IDENTITIES_DIR", "/identities")
	coreSock := httpx.Env("CORE_SOCKET", "/run/lightning-identity/core/edge-core.sock")
	dataDir := httpx.Env("EDGE_DATA", "/edge")
	siteDir := httpx.Env("SITE_DIR", "")

	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		logger.Error("edge data dir", "err", err)
		os.Exit(1)
	}
	ids := identity.NewWatcher(identitiesDir)
	stop := make(chan struct{})
	go ids.Run(stop, 3*time.Second, func(err error) { logger.Warn("edge: identities reload", "err", err) })

	rstore, err := relay.OpenStore(filepath.Join(dataDir, "relay.db"))
	if err != nil {
		logger.Error("relay store", "err", err)
		os.Exit(1)
	}
	defer rstore.Close()
	doc := ids.Doc()
	rl := relay.New(relay.Options{
		Name:        "lightning-identity relay",
		Description: "Relay for the Lightning Addresses, zap receipts and Nostr Wallet Connect served on this domain.",
		ServiceURL:  doc.RelayURL,
		Identities:  ids,
		Store:       rstore,
		Log:         log.New(os.Stdout, "[relay] ", log.LstdFlags),
	})
	if days := httpx.EnvInt("RELAY_RETAIN_DAYS", 0); days > 0 {
		go func() {
			t := time.NewTicker(6 * time.Hour)
			defer t.Stop()
			for range t.C {
				if n, err := rstore.Sweep(time.Duration(days) * 24 * time.Hour); err != nil {
					logger.Warn("relay sweep", "err", err)
				} else if n > 0 {
					logger.Info("relay sweep", "removed", n)
				}
			}
		}()
	}

	srv := edge.New(edge.Options{
		Identities:        ids,
		Core:              &ipc.Client{Path: coreSock, Timeout: 20 * time.Second},
		Relay:             rl,
		SiteDir:           siteDir,
		Log:               logger,
		InvoicesPerMinute: httpx.EnvInt("EDGE_INVOICES_PER_MINUTE", 60),
		RequestsPerMinute: httpx.EnvInt("EDGE_REQUESTS_PER_MINUTE", edge.DefaultRequestsPerMinute),
	})
	hs := &http.Server{
		Addr:              listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout/IdleTimeout: the relay's WebSockets are long-lived
		// and khatru runs its own ping/pong deadlines.
		MaxHeaderBytes: 16 << 10,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		close(stop)
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = hs.Shutdown(shutdownCtx)
	}()
	logger.Info("edge: listening", "addr", listen, "site", siteDir != "", "domain", doc.Domain)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("edge", "err", err)
		os.Exit(1)
	}
}
