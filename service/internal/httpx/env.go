// Package httpx holds the small shared helpers: environment parsing, logging
// level, JSON responses and a token-bucket limiter.
package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// CAFile returns the path of the LND CA bundle: LND_CA_FILE when set, else the
// contents of LND_CA_PEM written to a private temporary file (how the StartOS
// package hands the root CA over without touching a volume).
func CAFile(def string) (string, error) {
	if p := Env("LND_CA_FILE", ""); p != "" {
		return p, nil
	}
	if pem := os.Getenv("LND_CA_PEM"); strings.TrimSpace(pem) != "" {
		f, err := os.CreateTemp("", "lnd-ca-*.pem")
		if err != nil {
			return "", err
		}
		if _, err := f.WriteString(pem); err != nil {
			f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		return f.Name(), nil
	}
	return def, nil
}

// Env returns the variable or def when unset or empty.
func Env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// EnvInt parses an integer variable, falling back to def.
func EnvInt(key string, def int) int {
	if v, err := strconv.Atoi(Env(key, "")); err == nil {
		return v
	}
	return def
}

// EnvUIDs parses a comma-separated uid list ("1002,1003").
func EnvUIDs(key string) []uint32 {
	var out []uint32
	for _, p := range strings.Split(Env(key, ""), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if v, err := strconv.ParseUint(p, 10, 32); err == nil {
			out = append(out, uint32(v))
		}
	}
	return out
}

// LogLevel reads LOG_LEVEL (debug, info, warn, error).
func LogLevel() slog.Level {
	switch strings.ToLower(Env("LOG_LEVEL", "info")) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// TrustExtraCA adds the certificates in pemFile to the roots the default
// HTTP transport verifies against, keeping the system roots. Used for Nostr
// relay dials; clients with their own pinned transport are unaffected.
func TrustExtraCA(pemFile string) error {
	pem, err := os.ReadFile(pemFile)
	if err != nil {
		return err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("no certificates found in " + pemFile)
	}
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errors.New("default transport is not an *http.Transport")
	}
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{}
	}
	t.TLSClientConfig.RootCAs = pool
	return nil
}
