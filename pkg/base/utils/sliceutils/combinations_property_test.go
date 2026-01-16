package sliceutils_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func TestCombinations_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.SliceOfDistinct(rapid.IntMax(10), func(i int) int { return i }).Draw(t, "s")
		k := rapid.UintMax(uint(len(s))).Draw(t, "k")

		count := 0
		for c := range sliceutils.Combinations(s, k) {
			require.Len(t, c, int(k), "Combination length should be equal to k")
			for _, ct := range c {
				require.Contains(t, s, ct, "Combination element should be in the original slice")
			}
			count++
		}
		expectedCount := utils.Binomial(len(s), int(k))
		require.Equal(t, expectedCount, count, "Number of combinations should match Binomial coefficient")
	})
}

func TestKCoveringCombinations_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.SliceOfNDistinct(rapid.IntMax(12), 0, 12, func(i int) int { return i }).Draw(t, "s")
		k := rapid.UintRange(0, uint(len(s))).Draw(t, "k")

		count := 0
		for c := range sliceutils.KCoveringCombinations(s, k) {
			require.GreaterOrEqual(t, len(c), int(k), "Combination length should be at least k")
			for _, ct := range c {
				require.Contains(t, s, ct, "Combination element should be in the original slice")
			}
			count++
		}

		expectedCount := 0
		for i := k; i <= uint(len(s)); i++ {
			expectedCount += utils.Binomial(len(s), int(i))
		}
		require.Equal(t, expectedCount, count, "Number of k-covering combinations should match sum of Binomial coefficients")
	})
}
