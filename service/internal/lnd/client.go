// Package lnd is a small client for the subset of LND's REST API this
// service uses. It deliberately speaks REST rather than gRPC: the dependency
// footprint is the standard library, the macaroon travels as a header, and the
// streaming endpoints are plain chunked JSON lines.
//
// Every connection pins the StartOS root CA handed to the process (the only
// issuer of both LND's own certificate and the OS proxy's device certificate),
// so no public CA can validate a man-in-the-middle of the LND leg.
package lnd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Client talks to one LND node with one macaroon.
type Client struct {
	baseURL  string
	macaroon string // hex
	http     *http.Client
}

// Error is a non-2xx answer from LND, carrying its message and gRPC code.
type Error struct {
	Status  int
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("lnd: HTTP %d code %d: %s", e.Status, e.Code, e.Message)
}

// IsPermissionDenied reports whether LND refused the macaroon.
func IsPermissionDenied(err error) bool {
	var e *Error
	return errors.As(err, &e) && (e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden || e.Code == 7)
}

// New builds a client for baseURL (https://host:port) that trusts only the PEM
// bundle at caFile and authenticates with the macaroon file at macaroonPath.
// An empty macaroonPath yields an unauthenticated client (only useful for the
// state and unlocker endpoints).
func New(baseURL, caFile, macaroonPath string) (*Client, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read LND CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("LND CA file %s holds no certificate", caFile)
	}
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
				MaxIdleConns:        4,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				// Streaming responses must not be buffered or gzipped away.
				DisableCompression: true,
			},
		},
	}
	if macaroonPath != "" {
		if err := c.LoadMacaroon(macaroonPath); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// LoadMacaroon (re)reads the macaroon file; the guard renews credentials, so
// callers reload before long-lived streams are reopened.
func (c *Client) LoadMacaroon(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read macaroon: %w", err)
	}
	c.macaroon = hex.EncodeToString(raw)
	return nil
}

// SetMacaroonHex installs a macaroon given as hex (the guard's bake answer).
func (c *Client) SetMacaroonHex(h string) { c.macaroon = h }

func (c *Client) do(ctx context.Context, method, path string, body, out any, timeout time.Duration) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	if c.macaroon != "" {
		req.Header.Set("Grpc-Metadata-macaroon", c.macaroon)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		e := &Error{Status: res.StatusCode}
		_ = json.Unmarshal(raw, e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(raw))
		}
		return e
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return nil
}

// stream opens a server-streaming endpoint and yields each JSON line's
// "result" object to fn until the context ends or the stream closes.
func (c *Client) stream(ctx context.Context, path string, fn func(json.RawMessage) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.macaroon != "" {
		req.Header.Set("Grpc-Metadata-macaroon", c.macaroon)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 64<<10))
		e := &Error{Status: res.StatusCode}
		_ = json.Unmarshal(raw, e)
		if e.Message == "" {
			e.Message = strings.TrimSpace(string(raw))
		}
		return e
	}
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var env struct {
			Result json.RawMessage `json:"result"`
			Error  *Error          `json:"error"`
		}
		if err := json.Unmarshal(line, &env); err != nil {
			return fmt.Errorf("decode stream line: %w", err)
		}
		if env.Error != nil {
			return env.Error
		}
		if env.Result == nil {
			continue
		}
		if err := fn(env.Result); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return err
	}
	return ctx.Err()
}
