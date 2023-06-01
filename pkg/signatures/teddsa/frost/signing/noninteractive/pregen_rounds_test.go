package noninteractive_test

import (
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/teddsa/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

func pregenHappyPath(t *testing.T, curve *curves.Curve, h func() hash.Hash, threshold, n, tau int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol.FROST, identities, threshold, identities)
	require.NoError(t, err)

	participants, err := test_utils.MakePreGenParticipants(cohortConfig, tau)
	require.NoError(t, err)
	require.NotNil(t, participants)

	r1Outs, err := test_utils.DoPreGenRound1(participants)
	require.NoError(t, err)
	for _, out := range r1Outs {
		require.NotNil(t, out)
	}

	r2Ins := test_utils.MapPreGenRound1OutputsToRound2Inputs(participants, r1Outs)
	preSignatureBatches, privateNoncePairsOfAllParties, err := test_utils.DoPreGenRound2(participants, r2Ins)
	require.NoError(t, err)

	// all preSignatureBatches are the same
	for i, batch := range preSignatureBatches {
		for j, otherBatch := range preSignatureBatches {
			if i != j {
				require.Equal(t, batch, otherBatch)
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
	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
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
							boundedCurve.Name, boundedI, boundedThresholdConfig.t, boundedThresholdConfig.n, boundedTau),
						func(t *testing.T) {
							t.Parallel()
							pregenHappyPath(t, boundedCurve, boundedH, boundedThresholdConfig.t, boundedThresholdConfig.n, boundedTau)
						})
				}
			}
		}
	}
}
