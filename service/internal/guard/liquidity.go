package guard

import (
	"context"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
)

// Liquidity: what the node's channels can carry right now.
//
// Identity balances are a ledger. Nothing in core knows whether the node
// could actually pay them out, or whether a payment to a Lightning Address
// has room to arrive, and core is deliberately not allowed to ask LND: its
// credentials cannot read channels. The guard can, so it reads them, boils
// them down to a few totals and hands those to core for the operator's
// dashboard. They go nowhere else: not into status.json, and nothing in the
// wallet protocol reports them.

// LiquidityTTL is how long one reading is reused. Core asks for the guard's
// status often; LND is asked for its channels at most this often.
var LiquidityTTL = 30 * time.Second

// ChannelLiquidity is one channel's row.
type ChannelLiquidity struct {
	Peer           string `json:"peer"`   // the peer's alias, "" when LND knows none
	Pubkey         string `json:"pubkey"` // the peer's node key, hex
	Active         bool   `json:"active"`
	Unannounced    bool   `json:"unannounced"`
	CanSendMsat    int64  `json:"can_send_msat"`
	CanReceiveMsat int64  `json:"can_receive_msat"`
}

// Liquidity is the summary. The totals count active channels only: a
// channel whose peer is offline can carry nothing until it is back.
type Liquidity struct {
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`

	Channels int `json:"channels"`
	Active   int `json:"active"`

	CanSendMsat    int64 `json:"can_send_msat"`
	CanReceiveMsat int64 `json:"can_receive_msat"`
	// The best single channel in each direction: the most one payment can
	// be when it cannot be split across channels.
	LargestSendMsat    int64 `json:"largest_send_msat"`
	LargestReceiveMsat int64 `json:"largest_receive_msat"`
	// What the offline channels would add to CanSendMsat.
	OfflineSendMsat int64 `json:"offline_send_msat"`
	// In payments that are in flight on the channels right now.
	UnsettledMsat int64 `json:"unsettled_msat"`

	List []ChannelLiquidity `json:"list,omitempty"`
}

// Summarize boils LND's channel list down. What a side can move is its
// balance less the reserve it must always keep; routing fees and the
// per-payment limits a peer sets are not accounted for, so these are upper
// bounds and the dashboard says "about".
func Summarize(chs []lnd.Channel, now time.Time) *Liquidity {
	l := &Liquidity{At: now.UTC(), Channels: len(chs)}
	for _, c := range chs {
		send := spendable(c.LocalBalance, c.LocalConstraints)
		recv := spendable(c.RemoteBalance, c.RemoteConstraints)
		l.List = append(l.List, ChannelLiquidity{Peer: cleanAlias(c.PeerAlias), Pubkey: c.RemotePubkey, Active: c.Active, Unannounced: c.Private, CanSendMsat: send, CanReceiveMsat: recv})
		l.UnsettledMsat = addMsat(l.UnsettledMsat, satToMsat(int64(c.UnsettledBalance)))
		if !c.Active {
			l.OfflineSendMsat = addMsat(l.OfflineSendMsat, send)
			continue
		}
		l.Active++
		l.CanSendMsat = addMsat(l.CanSendMsat, send)
		l.CanReceiveMsat = addMsat(l.CanReceiveMsat, recv)
		if send > l.LargestSendMsat {
			l.LargestSendMsat = send
		}
		if recv > l.LargestReceiveMsat {
			l.LargestReceiveMsat = recv
		}
	}
	// Online first, then the fullest; a stable order for the page.
	sort.SliceStable(l.List, func(i, j int) bool {
		a, b := l.List[i], l.List[j]
		if a.Active != b.Active {
			return a.Active
		}
		return a.CanSendMsat+a.CanReceiveMsat > b.CanSendMsat+b.CanReceiveMsat
	})
	return l
}

// cleanAlias makes a peer's alias fit to show. An alias is whatever the
// other node's operator typed (up to 32 bytes, any UTF-8), so it is cut to
// that length and stripped of control characters; the page escapes the rest.
// When LND cannot find one (a peer that is not in the public graph) it puts
// an error sentence in the field instead, which is not an alias.
func cleanAlias(a string) string {
	if strings.HasPrefix(a, "unable to lookup") {
		return ""
	}
	a = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, a)
	a = strings.TrimSpace(a)
	if r := []rune(a); len(r) > 32 {
		a = string(r[:32])
	}
	return a
}

func spendable(balance lnd.Int64, c *lnd.ChannelConstraints) int64 {
	v := int64(balance)
	if c != nil {
		v -= int64(c.ChanReserveSat)
	}
	if v < 0 {
		v = 0
	}
	return satToMsat(v)
}

// satToMsat converts without wrapping: no real channel comes near the
// limit, but the number is from outside this process.
func satToMsat(sat int64) int64 {
	if sat <= 0 {
		return 0
	}
	if sat > maxMsat/1000 {
		return maxMsat
	}
	return sat * 1000
}

// addMsat adds two amounts, stopping at the largest amount there can be.
func addMsat(a, b int64) int64 {
	if a > maxMsat-b {
		return maxMsat
	}
	return a + b
}

// liquidity returns the current reading, asking LND only when the last one
// is older than LiquidityTTL. A failed read is kept for the same time, so a
// node that is down is not asked on every status request. The lock is held
// across the call: concurrent requests share one answer.
func (g *Guard) liquidity(ctx context.Context, st Status) *Liquidity {
	g.liqMu.Lock()
	defer g.liqMu.Unlock()
	if g.liq != nil && time.Since(g.liq.At) < LiquidityTTL {
		return g.liq
	}
	now := time.Now()
	fail := func(msg string) *Liquidity {
		g.liq = &Liquidity{At: now.UTC(), Error: msg}
		return g.liq
	}
	if st.LNDState != "RPC_ACTIVE" && st.LNDState != "SERVER_ACTIVE" {
		return fail("LND is not ready")
	}
	adminHex, err := g.adminMacaroon()
	if err != nil {
		return fail("admin macaroon unavailable")
	}
	cli, err := lnd.New(g.cfg.LNDRestURL, g.cfg.LNDCAFile, "")
	if err != nil {
		return fail(err.Error())
	}
	cli.SetMacaroonHex(adminHex)
	// Not the caller's context alone: bound it, so a slow node cannot hold
	// the status socket (and the dashboard) for long.
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	chs, err := cli.ListChannels(cctx)
	if err != nil {
		g.log.Warn("guard: could not read channels for the liquidity view", "err", err)
		return fail("could not read channels from LND")
	}
	g.liq = Summarize(chs, now)
	return g.liq
}
