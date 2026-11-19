package guard

import (
	"testing"
	"time"

	"github.com/lundog/lightning-identity-startos/service/internal/lnd"
)

func ch(alias string, active bool, local, remote, localReserve, remoteReserve int64) lnd.Channel {
	return lnd.Channel{
		Active: active, PeerAlias: alias, RemotePubkey: "02aabbccddeeff00112233445566778899",
		LocalBalance: lnd.Int64(local), RemoteBalance: lnd.Int64(remote),
		LocalConstraints:  &lnd.ChannelConstraints{ChanReserveSat: lnd.Int64(localReserve)},
		RemoteConstraints: &lnd.ChannelConstraints{ChanReserveSat: lnd.Int64(remoteReserve)},
	}
}

func TestSummarizeLiquidity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)

	// One unannounced channel, the shape of a small node.
	one := ch("LSP", true, 300_000, 700_000, 10_000, 10_000)
	one.Private = true
	one.UnsettledBalance = 1_500
	l := Summarize([]lnd.Channel{one}, now)
	if l.Channels != 1 || l.Active != 1 || l.CanSendMsat != 290_000_000 || l.CanReceiveMsat != 690_000_000 ||
		l.LargestSendMsat != 290_000_000 || l.LargestReceiveMsat != 690_000_000 || l.UnsettledMsat != 1_500_000 || l.OfflineSendMsat != 0 {
		t.Fatalf("one channel: %+v", l)
	}
	if len(l.List) != 1 || l.List[0].Peer != "LSP" || l.List[0].Pubkey != "02aabbccddeeff00112233445566778899" || !l.List[0].Unannounced || !l.List[0].Active {
		t.Fatalf("row: %+v", l.List)
	}

	// Two online and one offline. The offline one counts for nothing but is
	// listed, last, with what it would add.
	l = Summarize([]lnd.Channel{
		ch("offline", false, 500_000, 500_000, 10_000, 10_000),
		ch("small", true, 50_000, 20_000, 1_000, 1_000),
		ch("big", true, 400_000, 900_000, 13_000, 13_000),
	}, now)
	if l.Channels != 3 || l.Active != 2 {
		t.Fatalf("counts: %+v", l)
	}
	if l.CanSendMsat != (49_000+387_000)*1000 || l.CanReceiveMsat != (19_000+887_000)*1000 {
		t.Fatalf("totals: send %d receive %d", l.CanSendMsat, l.CanReceiveMsat)
	}
	if l.LargestSendMsat != 387_000_000 || l.LargestReceiveMsat != 887_000_000 {
		t.Fatalf("largest: %+v", l)
	}
	if l.OfflineSendMsat != 490_000_000 {
		t.Fatalf("offline: %d", l.OfflineSendMsat)
	}
	if got := []string{l.List[0].Peer, l.List[1].Peer, l.List[2].Peer}; got[0] != "big" || got[1] != "small" || got[2] != "offline" {
		t.Fatalf("order: %v", got)
	}

	// A side below its reserve can move nothing, not a negative amount; a
	// channel with no constraints reported is taken at face value; a peer
	// with no alias has an empty name and is known by its key.
	under := ch("", true, 500, 0, 1_000, 1_000)
	bare := lnd.Channel{Active: true, PeerAlias: "bare", LocalBalance: 2_000, RemoteBalance: 3_000}
	l = Summarize([]lnd.Channel{under, bare}, now)
	if l.CanSendMsat != 2_000_000 || l.CanReceiveMsat != 3_000_000 {
		t.Fatalf("floor and missing constraints: %+v", l)
	}
	for _, row := range l.List {
		if row.CanSendMsat < 0 || row.CanReceiveMsat < 0 {
			t.Fatalf("negative row: %+v", row)
		}
		if row.Peer != "bare" && !(row.Peer == "" && row.Pubkey == "02aabbccddeeff00112233445566778899") {
			t.Fatalf("peer name: %+v", row)
		}
	}

	// None at all.
	if l = Summarize(nil, now); l.Channels != 0 || l.CanSendMsat != 0 || l.CanReceiveMsat != 0 || len(l.List) != 0 {
		t.Fatalf("empty: %+v", l)
	}

	// Absurd numbers do not wrap.
	huge := ch("huge", true, 1<<62, 1<<62, 0, 0)
	if l = Summarize([]lnd.Channel{huge, huge, huge, huge, huge, huge}, now); l.CanSendMsat != maxMsat || l.CanReceiveMsat != maxMsat || l.CanSendMsat < 0 {
		t.Fatalf("overflow: %+v", l)
	}
}

// An alias is free text chosen by the other node's operator, or an error
// sentence from LND when it has none on record.
func TestCleanAlias(t *testing.T) {
	for in, want := range map[string]string{
		"ACINQ":          "ACINQ",
		"  spaced out  ": "spaced out",
		"":               "",
		"unable to lookup peer alias: unable to find node": "",
		"line\nbreak\x00null\x1b[31m":                      "linebreaknull[31m",
		"⚡ zap ⚡":                                          "⚡ zap ⚡",
		"0123456789012345678901234567890123456789":         "01234567890123456789012345678901",
	} {
		if got := cleanAlias(in); got != want {
			t.Errorf("cleanAlias(%q) = %q, want %q", in, got, want)
		}
	}
}
