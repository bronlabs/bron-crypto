package frost_test

import (
	"crypto/sha512"
	"fmt"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/base/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/base/protocols"
	"github.com/copperexchange/knox-primitives/pkg/threshold/tsignatures/tschnorr/frost/test_utils"
)

func pregenHappyPath(t *testing.T, curve curves.Curve, h func() hash.Hash, threshold, n, tau int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig, err := test_utils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, threshold, identities)
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
	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
