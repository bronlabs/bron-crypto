package primegen //nolint:testpackage // to access unexported identifiers

import (
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

// TestGenerate_SafeUniformityChiSquared is a statistical regression test for
// the exact-uniformity claim: it enumerates every 20-bit safe prime as ground
// truth, draws 20k samples, and runs a chi-squared goodness-of-fit against
// the uniform distribution. It exists because a subtle non-uniformity slipped
// in once before: a first-past-the-post race between workers favoured primes
// whose BPSW/Lucas verification ran faster (value-dependent via the Lucas
// D-parameter search), skewing residue classes mod 5 by ±4% — about +2.5σ on
// this statistic per run. Resolving successes in canonical sampling order
// (see run) fixed it; this test keeps it fixed. The 5σ gate keeps the
// false-failure rate below 1 in 10^6.
func TestGenerate_SafeUniformityChiSquared(t *testing.T) {
	if testing.Short() {
		t.Skip("statistical test, ~20s")
	}
	t.Parallel()

	const bits = 20
	const samples = 20000
	counts := map[uint64]int{}
	for q := uint64(1)<<(bits-1) | 3; q < 1<<bits; q += 4 {
		qb := new(big.Int).SetUint64(q)
		// ProbablyPrime is exact below 2^64, so this enumeration is ground truth.
		if qb.ProbablyPrime(1) && new(big.Int).Rsh(qb, 1).ProbablyPrime(1) {
			counts[q] = 0
		}
	}
	rounds := Rounds{Q: 40, Half: 40}
	for range samples {
		q, err := Generate(Safe, bits, nil, rounds, pcg.NewRandomised())
		require.NoError(t, err)
		v := q.Uint64()
		_, ok := counts[v]
		require.True(t, ok, "output %d is not a 20-bit safe prime", v)
		counts[v]++
	}
	k := len(counts)
	e := float64(samples) / float64(k)
	chi := 0.0
	for _, c := range counts {
		d := float64(c) - e
		chi += d * d / e
	}
	df := float64(k - 1)
	z := (chi - df) / math.Sqrt(2*df)
	require.Less(t, math.Abs(z), 5.0, "chi-squared rejects uniformity: chi2=%.1f df=%.0f z=%+.2f", chi, df, z)
}
