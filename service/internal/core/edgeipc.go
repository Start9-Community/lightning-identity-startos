package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/ipc"
	"github.com/lundog/lightning-identity-startos/service/internal/lnurl"
	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

// ServeEdge runs the unix socket edge talks to. Exactly three request types
// exist; anything else is an error.
func (s *Service) ServeEdge(ctx context.Context) error {
	srv := &ipc.Server{
		Path:        s.cfg.EdgeSocket,
		AllowedUIDs: s.cfg.EdgeUIDs,
		Handler:     s.handleEdge,
		MaxInFlight: 32,
		Timeout:     25 * time.Second,
		Log:         s.log,
	}
	return srv.ListenAndServe(ctx)
}

func (s *Service) handleEdge(ctx context.Context, req ipc.Request) (any, error) {
	switch req.Type {
	case "create_invoice":
		var p lnurl.CallbackRequest
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, errors.New("bad request")
		}
		if len(p.ZapRequest) > lnurl.MaxZapRequest || len(p.PayerData) > lnurl.MaxPayerData || len(p.Comment) > lnurl.MaxCommentAllowed {
			return nil, errors.New("request too large")
		}
		source := store.SourceLNURL
		if p.ZapRequest != "" {
			source = store.SourceZap
		}
		inv, err := s.CreateInvoice(ctx, CreateInvoiceParams{
			Identity:   strings.ToLower(p.Identity),
			AmountMsat: p.AmountMsat,
			Comment:    p.Comment,
			PayerData:  p.PayerData,
			ZapRequest: p.ZapRequest,
			Source:     source,
		})
		if err != nil {
			return nil, err
		}
		return map[string]string{"pr": inv.Bolt11, "payment_hash": inv.PaymentHash}, nil
	case "verify_invoice":
		var p struct {
			PaymentHash string `json:"payment_hash"`
			Identity    string `json:"identity"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil || len(p.PaymentHash) != 64 {
			return nil, errors.New("bad request")
		}
		return s.Verify(ctx, p.PaymentHash, p.Identity)
	case "status":
		_, err := s.NodeInfo(ctx)
		return map[string]bool{"ok": err == nil}, nil
	default:
		return nil, fmt.Errorf("unknown request %q", req.Type)
	}
}
