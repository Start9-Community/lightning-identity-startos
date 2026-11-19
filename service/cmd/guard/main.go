// Command guard is the credential broker (see internal/guard).
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/guard"
	"github.com/lundog/lightning-identity-startos/service/internal/httpx"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: httpx.LogLevel()}))
	slog.SetDefault(log)

	// Root for one purpose: LND's macaroon directory is root-only and comes
	// in as a read-only mount, so the file can only be read before dropping
	// to the guard user. Everything after this line runs unprivileged;
	// nothing — not even a temp file — is created before the drop.
	adminPath := httpx.Env("LND_ADMIN_MACAROON", "/lnd/admin/admin.macaroon")
	var adminHex string
	if runAs := httpx.Env("GUARD_RUN_AS", ""); runAs != "" && os.Getuid() == 0 {
		u, err := user.Lookup(runAs)
		if err != nil {
			log.Error("GUARD_RUN_AS user not found", "user", runAs, "err", err)
			os.Exit(2)
		}
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		gid, _ := strconv.ParseUint(u.Gid, 10, 32)
		hex, err := guard.ReadMacaroonHex(adminPath)
		if err != nil {
			// Once dropped, the file can never be read, so there is no
			// point continuing: exit and let the runtime restart the guard
			// as root, by which time LND may have created it.
			log.Error("admin macaroon not readable; exiting to retry as root", "path", adminPath, "err", err)
			time.Sleep(10 * time.Second)
			os.Exit(3)
		}
		adminHex = hex
		if err := guard.DropPrivileges(uint32(uid), uint32(gid)); err != nil {
			log.Error("privilege drop", "err", err)
			os.Exit(2)
		}
		log.Info("guard: dropped privileges", "user", runAs, "uid", uid, "gid", gid, "admin_macaroon_loaded", hex != "")
	}

	caFile, err := httpx.CAFile("/etc/lightning-identity/lnd-ca.pem")
	if err != nil {
		log.Error("LND CA", "err", err)
		os.Exit(2)
	}
	cfg := guard.Config{
		LNDRestURL:       httpx.Env("LND_REST_URL", ""),
		LNDGRPCAddress:   httpx.Env("LND_GRPC_ADDRESS", ""),
		LNDCAFile:        caFile,
		AdminMacaroon:    adminPath,
		AdminMacaroonHex: adminHex,
		CredentialsDir:   httpx.Env("CREDENTIALS_DIR", "/credentials"),
		StateDir:         httpx.Env("GUARD_DIR", "/guard"),
		SocketPath:       httpx.Env("GUARD_SOCKET", "/run/lightning-identity/guard.sock"),
		AllowedUIDs:      httpx.EnvUIDs("GUARD_ALLOWED_UIDS"),
		Log:              log,
	}
	if cfg.LNDRestURL == "" {
		log.Error("LND_REST_URL is not set; LND has not bound its REST port yet")
		os.Exit(2)
	}
	if cidr := httpx.Env("GUARD_IPRANGE", ""); cidr != "" {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Error("GUARD_IPRANGE is not a CIDR", "value", cidr, "err", err)
			os.Exit(2)
		}
		cfg.IPRange = ipnet
	}

	g, err := guard.New(cfg)
	if err != nil {
		log.Error("guard setup", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := g.Run(ctx); err != nil {
		log.Error("guard", "err", err)
		os.Exit(1)
	}
}
