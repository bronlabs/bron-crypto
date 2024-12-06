package ecpedersen_vss_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	ecpedersen_comm "github.com/copperexchange/krypton-primitives/pkg/commitments/ecpedersen"
	ecpedersen_vss "github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/ecpedersen"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
	"github.com/stretchr/testify/require"
	"maps"
	"slices"
	"testing"
)

var supportedCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pallas.NewCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

var accessStructures = []struct {
	threshold uint
	total     uint
}{
	{threshold: 2, total: 3},
	{threshold: 5, total: 5},
	{threshold: 3, total: 11},
	{threshold: 8, total: 12},
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	for _, curve := range supportedCurves {
		for _, as := range accessStructures {
			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.threshold, as.total), func(t *testing.T) {
				t.Parallel()

				h, err := curve.Random(prng)
				require.NoError(t, err)
				ck := ecpedersen_comm.NewCommittingKey(curve.Generator(), h)
				pedersenDealer := ecpedersen_vss.NewDealer(ck, as.threshold, as.total)

				secret, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				shares, commitments, err := pedersenDealer.Deal(secret, prng)
				require.NoError(t, err)

				for _, share := range shares {
					err = pedersenDealer.VerifyShare(share, commitments)
					require.NoError(t, err)
				}
				sharingIds := slices.Collect(maps.Keys(shares))
				sharingIdCombinations, err := combinatorics.Combinations(sharingIds, as.threshold)

				// reveal with shamir dealer
				shamirDealer, err := shamir.NewDealer(as.threshold, as.total, curve)
				require.NoError(t, err)
				for _, sharingIdCombination := range sharingIdCombinations {
					var shamirShares []*shamir.Share
					for _, sharingId := range sharingIdCombination {
						shamirShares = append(shamirShares, shares[sharingId].AsShamir())
					}
					recovered, err := shamirDealer.Combine(shamirShares...)
					require.NoError(t, err)
					require.True(t, recovered.Equal(secret))
				}

				// reveal with pedersen dealer
				for _, sharingIdCombination := range sharingIdCombinations {
					var pedersenShares []*ecpedersen_vss.Share
					for _, sharingId := range sharingIdCombination {
						pedersenShares = append(pedersenShares, shares[sharingId])
					}
					recovered, err := pedersenDealer.VerifyReveal(commitments, pedersenShares...)
					require.NoError(t, err)
					require.True(t, recovered.Equal(secret))
				}
			})
		}
	}
}
