package core

import (
	"errors"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

// DefaultSettings is what applies until the operator saves settings: route
// hints on (a node with only unannounced channels is otherwise unpayable),
// self-pay on (the LNbits default people expect), expiry from the config,
// and the default fee limit.
func (s *Service) DefaultSettings() store.Settings {
	return store.Settings{
		RouteHints:           s.cfg.InvoicePrivate,
		SelfPay:              true,
		InvoiceExpirySeconds: int64(s.cfg.InvoiceExpiry / time.Second),
		FeeLimitPPM:          DefaultFeeLimitPPM,
		FeeLimitMinMsat:      DefaultFeeLimitMinMsat,
	}
}

// FeeLimit is the most a payment of amountMsat may cost to route under st:
// the percentage, or the floor when that is larger. The floor is what small
// payments live on — most nodes charge a base fee of about a sat per hop
// whatever the amount, so 1 % of a 3-sat zap buys no route at all.
func FeeLimit(amountMsat int64, st store.Settings) int64 {
	limit := amountMsat / 1_000_000 * st.FeeLimitPPM
	limit += amountMsat % 1_000_000 * st.FeeLimitPPM / 1_000_000
	if limit < st.FeeLimitMinMsat {
		limit = st.FeeLimitMinMsat
	}
	return limit
}

// Settings returns the operator settings, defaults applied.
func (s *Service) Settings() store.Settings {
	st, ok, err := s.store.GetSettings()
	if err != nil || !ok {
		return s.DefaultSettings()
	}
	if st.InvoiceExpirySeconds <= 0 {
		st.InvoiceExpirySeconds = int64(s.cfg.InvoiceExpiry / time.Second)
	}
	if st.FeeLimitPPM == 0 && st.FeeLimitMinMsat == 0 {
		// Saved before fee limits were a setting.
		st.FeeLimitPPM, st.FeeLimitMinMsat = DefaultFeeLimitPPM, DefaultFeeLimitMinMsat
	}
	return st
}

// UpdateSettings validates and stores operator settings.
func (s *Service) UpdateSettings(st store.Settings) error {
	if st.InvoiceExpirySeconds < 60 || st.InvoiceExpirySeconds > 7*24*3600 {
		return errors.New("invoice expiry must be between 1 minute and 7 days")
	}
	if st.FeeLimitPPM < 0 || st.FeeLimitPPM > MaxFeeLimitPPM {
		return errors.New("the fee limit must be between 0 and 10 percent")
	}
	if st.FeeLimitMinMsat < 0 || st.FeeLimitMinMsat > MaxFeeLimitMinMsat {
		return errors.New("the minimum fee limit must be between 0 and 1000 sats")
	}
	if st.FeeLimitPPM == 0 && st.FeeLimitMinMsat == 0 {
		return errors.New("a fee limit of zero would make every payment fail to route; set a percentage or a minimum")
	}
	if err := s.store.PutSettings(st); err != nil {
		return err
	}
	s.log.Info("settings updated", "route_hints", st.RouteHints, "self_pay", st.SelfPay, "invoice_expiry_s", st.InvoiceExpirySeconds, "fee_limit_ppm", st.FeeLimitPPM, "fee_limit_min_msat", st.FeeLimitMinMsat)
	return nil
}
