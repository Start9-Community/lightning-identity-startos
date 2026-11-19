package core

import (
	"math"
	"testing"

	"github.com/lundog/lightning-identity-startos/service/internal/store"
)

func TestFeeLimit(t *testing.T) {
	def := store.Settings{FeeLimitPPM: DefaultFeeLimitPPM, FeeLimitMinMsat: DefaultFeeLimitMinMsat}
	for _, tc := range []struct {
		name   string
		amount int64
		st     store.Settings
		want   int64
	}{
		// The zaps that failed with "no route" under the old 1-sat floor.
		{"1-sat zap gets the floor", 1_000, def, 10_000},
		{"3-sat zap gets the floor", 3_000, def, 10_000},
		{"just under where 1% takes over", 999_000, def, 10_000},
		{"exactly where 1% equals the floor", 1_000_000, def, 10_000},
		{"1% above the floor", 40_000_000, def, 400_000},
		{"sub-sat remainders are not lost", 1_234_567, def, 12_345},
		{"percentage only", 3_000, store.Settings{FeeLimitPPM: 10_000}, 30},
		{"floor only", 40_000_000, store.Settings{FeeLimitMinMsat: 5_000}, 5_000},
		{"highest percentage", 2_000_000, store.Settings{FeeLimitPPM: MaxFeeLimitPPM}, 200_000},
		// 21M BTC in msat at the highest percentage must not wrap.
		{"largest amount does not overflow", 2_100_000_000_000_000_000, store.Settings{FeeLimitPPM: MaxFeeLimitPPM}, 210_000_000_000_000_000},
	} {
		if got := FeeLimit(tc.amount, tc.st); got != tc.want {
			t.Errorf("%s: FeeLimit(%d) = %d, want %d", tc.name, tc.amount, got, tc.want)
		}
	}
	if got := FeeLimit(math.MaxInt64/MaxFeeLimitPPM, store.Settings{FeeLimitPPM: MaxFeeLimitPPM}); got < 0 {
		t.Errorf("FeeLimit wrapped negative: %d", got)
	}
}
