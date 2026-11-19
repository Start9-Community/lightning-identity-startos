// Package lndgrpc dials LND's gRPC endpoint. Only the guard uses it: the RPC
// middleware is a bidirectional stream, and the intercepted messages it
// carries are serialized protobuf, so the guard needs the generated types
// either way and the stream belongs on gRPC. Core keeps the REST client.
package lndgrpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	lnrpc "github.com/lundog/lightning-identity-startos/service/internal/lndrpc"
	"github.com/lundog/lightning-identity-startos/service/internal/lndrpc/routerrpc"
)

// macaroonCreds sends the macaroon as per-RPC metadata, as lncli does.
type macaroonCreds struct{ hex string }

func (m macaroonCreds) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if m.hex == "" {
		return nil, nil
	}
	return map[string]string{"macaroon": m.hex}, nil
}

func (m macaroonCreds) RequireTransportSecurity() bool { return true }

// Conn bundles the connection and the service clients the guard uses.
type Conn struct {
	cc        *grpc.ClientConn
	Lightning lnrpc.LightningClient
	Router    routerrpc.RouterClient
	State     lnrpc.StateClient
}

// Dial connects to host:port (an `https://` prefix is tolerated), trusting
// only the PEM bundle at caFile, and authenticating every call with the
// macaroon given as hex (empty for the macaroon-less State service).
func Dial(ctx context.Context, address, caFile, macaroonHex string) (*Conn, error) {
	address = strings.TrimPrefix(strings.TrimPrefix(address, "https://"), "http://")
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read LND CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("LND CA file %s holds no certificate", caFile)
	}
	tlsCreds := credentials.NewTLS(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	cc, err := grpc.NewClient(address,
		grpc.WithTransportCredentials(tlsCreds),
		grpc.WithPerRPCCredentials(macaroonCreds{hex: macaroonHex}),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(50<<20)),
	)
	if err != nil {
		return nil, err
	}
	return &Conn{
		cc:        cc,
		Lightning: lnrpc.NewLightningClient(cc),
		Router:    routerrpc.NewRouterClient(cc),
		State:     lnrpc.NewStateClient(cc),
	}, nil
}

// Close closes the connection.
func (c *Conn) Close() error { return c.cc.Close() }
