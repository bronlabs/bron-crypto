package additive_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/curves/k256"
	"github.com/copperexchange/krypton/pkg/base/curves/p256"
	"github.com/copperexchange/krypton/pkg/threshold/sharing/additive"
	"github.com/copperexchange/krypton/pkg/threshold/sharing/shamir"
)

func TestSplitAndCombine(t *testing.T) {
	t.Parallel()
	curve := k256.New()
	dealer, err := additive.NewDealer(5, curve)
	require.Nil(t, err)
	require.NotNil(t, dealer)

	secret := curve.Scalar().Hash([]byte("test"))

	shares, err := dealer.Split(secret, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shares)
	require.Len(t, shares, 5)

	recomputedSecret, err := dealer.Combine(shares)
	require.NoError(t, err)
	require.NotNil(t, recomputedSecret)
	require.Zero(t, secret.Cmp(recomputedSecret))
}

func TestShamirAdditiveRoundTrip(t *testing.T) {
	t.Parallel()
	total := 5
	threshold := 3
	for _, curve := range []curves.Curve{edwards25519.New(), k256.New(), p256.New()} {
		boundedCurve := curve
		t.Run(fmt.Sprintf("running the round trip for curve %s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			shamirDealer, err := shamir.NewDealer(threshold, total, boundedCurve)
			require.Nil(t, err)
			require.NotNil(t, shamirDealer)

			secret := boundedCurve.Scalar().Hash([]byte("2+2=5"))

			shamirShares, err := shamirDealer.Split(secret, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, shamirShares)

			allValidSetsOfShamirIndices := [][]int{}
			for i := 0; i <= total-threshold; i++ {
				allValidSetsOfShamirIndices = append(
					allValidSetsOfShamirIndices,
					combin.Combinations(total, threshold+i)...,
				)
			}
			for _, indices := range allValidSetsOfShamirIndices {
				identities := make([]int, len(indices))
				for i, index := range indices {
					identities[i] = index + 1
				}
				t.Run(fmt.Sprintf("testing round trip for identities %v", identities), func(t *testing.T) {
					t.Parallel()

					additiveDealer, err := additive.NewDealer(len(identities), boundedCurve)
					require.NoError(t, err)
					require.NotNil(t, additiveDealer)

					additiveShares := make([]*additive.Share, len(identities))
					for i, id := range identities {
						value, err := shamirShares[id-1].ToAdditive(identities)
						require.NoError(t, err)
						additiveShares[i] = &additive.Share{Value: value}
					}

					combinedAdditiveShares, err := additiveDealer.Combine(additiveShares)
					require.NoError(t, err)
					require.Zero(t, secret.Cmp(combinedAdditiveShares))

					recomputedShamirShares := make([]*shamir.Share, len(identities))
					for i, additiveShare := range additiveShares {
						recomputedShare, err := additiveShare.ConvertToShamir(identities[i], threshold, total, identities)
						require.NoError(t, err)
						recomputedShamirShares[i] = recomputedShare
					}

					recomputedSecret, err := shamirDealer.Combine(recomputedShamirShares...)
					require.NoError(t, err)
					require.NotNil(t, recomputedSecret)
					require.Zero(t, secret.Cmp(recomputedSecret))
				})
			}
		})
	}
}
