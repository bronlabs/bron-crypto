package noninteractive_signing_test

import (
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr/frost/testutils"
)

func pregenHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n, tau int) {
	t.Helper()

	cipherSuite, err := ttu.MakeSigningSuite(curve, h)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, threshold)
	require.NoError(t, err)

	participants, err := testutils.MakePreGenParticipants(protocol, tau)
	require.NoError(t, err)
	require.NotNil(t, participants)

	r1Outs, err := testutils.DoPreGenRound1(participants)
	require.NoError(t, err)
	for _, out := range r1Outs {
		require.NotNil(t, out)
	}
	r2Ins := ttu.MapBroadcastO2I(t, participants, r1Outs)
	preSignatureBatches, privateNoncePairsOfAllParties, err := testutils.DoPreGenRound2(participants, r2Ins)
	require.NoError(t, err)

	// all preSignatureBatches are the same
	for i, batch := range preSignatureBatches {
		for j, otherBatch := range preSignatureBatches {
			if i != j {
				require.Len(t, batch, len(otherBatch))
				for k := range batch {
					ps1 := batch[k]
					ps2 := otherBatch[k]
					for l := range ps1 {
						require.True(t, ps1[l].Equal(ps2[l]))
					}
				}
			}
		}
	}

	// all private nonce pairs are different
	scalarHashSet := map[curves.Scalar]bool{}
	for _, privateNoncePairsOfThisParty := range privateNoncePairsOfAllParties {
		for _, privateNoncePairs := range privateNoncePairsOfThisParty {
			require.NotContains(t, scalarHashSet, privateNoncePairs.SmallD)
			require.NotContains(t, scalarHashSet, privateNoncePairs.SmallE)
			scalarHashSet[privateNoncePairs.SmallD] = true
			scalarHashSet[privateNoncePairs.SmallE] = true
		}
	}

	require.Len(t, scalarHashSet, n*tau*2)
}

func Test_PregenHappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
		for i, h := range []func() hash.Hash{sha512.New, sha3.New256} {
			for _, thresholdConfig := range []struct {
				t int
				n int
			}{
				{2, 3}, {3, 3},
			} {
				for _, tau := range []int{1, 5, 10} {
					boundedCurve := curve
					boundedH := h
					boundedI := i
					boundedThresholdConfig := thresholdConfig
					boundedTau := tau
					t.Run(
						fmt.Sprintf("running pregen for curve=%s and h_%d and t=%d and n=%d and tau=%d",
							boundedCurve.Name(), boundedI, boundedThresholdConfig.t, boundedThresholdConfig.n, boundedTau),
						func(t *testing.T) {
							t.Parallel()
							pregenHappyPath(t, boundedCurve, boundedH, boundedThresholdConfig.t, boundedThresholdConfig.n, boundedTau)
						})
				}
			}
		}
	}
}
