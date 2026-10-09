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
// the per-prime statistic per run. Resolving successes in canonical sampling
// order (see run) fixed it. A separate mod-5 statistic below targets that
// residue bias, which the per-prime 5σ gate alone has little power to detect.
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

	// Safe primes here occupy residues 2, 3 and 4 modulo 5. Their finite
	// population sizes differ, so derive expectations from the enumeration.
	var population, observed [5]int
	for q, count := range counts {
		population[q%5]++
		observed[q%5] += count
	}
	residueChi := 0.0
	for residue := 2; residue < 5; residue++ {
		expected := float64(samples) * float64(population[residue]) / float64(k)
		d := float64(observed[residue]) - expected
		residueChi += d * d / expected
	}
	// For three bins (two degrees of freedom), the chi-squared upper tail
	// is exp(-x/2). Use its 1e-7 upper-tail cutoff, not a normal z-score.
	cutoff := -2 * math.Log(1e-7)
	require.Less(t, residueChi, cutoff, "mod-5 residue bias: chi2=%.2f counts=%v", residueChi, observed)
}
