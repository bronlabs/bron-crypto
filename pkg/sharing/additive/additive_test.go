package additive_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/additive"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/shamir"
	"github.com/stretchr/testify/require"
	"gonum.org/v1/gonum/stat/combin"
)

func TestSplitAndCombine(t *testing.T) {
	t.Parallel()
	curve := curves.K256()
	dealer, err := additive.NewDealer(5, curve)
	require.Nil(t, err)
	require.NotNil(t, dealer)

	secret := curve.Scalar.Hash([]byte("test"))

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
	curve := curves.ED25519()
	shamirDealer, err := shamir.NewDealer(threshold, total, curve)
	require.Nil(t, err)
	require.NotNil(t, shamirDealer)

	secret := curve.Scalar.Hash([]byte("2+2=5"))

	shamirShares, err := shamirDealer.Split(secret, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shamirShares)

	allValidSetsOfShamirIndices := [][]int{}
	for i := 0; i <= total-threshold; i++ {
		for _, c := range combin.Combinations(total, threshold+i) {
			allValidSetsOfShamirIndices = append(allValidSetsOfShamirIndices, c)
		}
	}
	for _, indices := range allValidSetsOfShamirIndices {
		identities := make([]int, len(indices))
		for i, index := range indices {
			identities[i] = index + 1
		}
		t.Run(fmt.Sprintf("testing round trip for identities %v", identities), func(t *testing.T) {
			t.Parallel()

			additiveDealer, err := additive.NewDealer(len(identities), curve)
			require.NoError(t, err)
			require.NotNil(t, additiveDealer)

			additiveShares := make([]*additive.Share, len(identities))
			for i, id := range identities {
				value, err := shamirShares[id-1].ToAdditive(identities)
				require.NoError(t, err)
				additiveShares[i] = &additive.Share{value}
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
}
