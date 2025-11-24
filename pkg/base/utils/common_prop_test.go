package utils_test

import (
	"testing"

	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

func TestBinomial_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 10).Draw(t, "n")
		k := rapid.IntRange(0, n).Draw(t, "k")

		// C(n, k) == C(n, n-k)
		binom1 := utils.Binomial(n, k)
		binom2 := utils.Binomial(n, n-k)
		if binom1 != binom2 {
			t.Fatalf("Binomial(%d, %d) = %d != Binomial(%d, %d) = %d", n, k, binom1, n, n-k, binom2)
		}

		// C(n, 0) == 1
		if k == 0 {
			binom := utils.Binomial(n, k)
			if binom != 1 {
				t.Fatalf("Binomial(%d, 0) = %d != 1", n, binom)
			}
		}

		// C(n, n) == 1
		if k == n {
			binom := utils.Binomial(n, k)
			if binom != 1 {
				t.Fatalf("Binomial(%d, %d) = %d != 1", n, k, binom)
			}
		}
	})
}
