package setup_test

import (
	"fmt"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
)

var h = sha3.New256

func testHappyPath(t *testing.T, curve *curves.Curve, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  h,
	}

	identities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	participants, err := test_utils.MakeSetupParticipants(curve, identities)
	require.NoError(t, err)

	r1Outs, err := test_utils.DoSetupRound1(participants)
	require.NoError(t, err)
	for _, out := range r1Outs {
		require.NotNil(t, out)
	}

	r2Ins := test_utils.MapSetupRound1OutputsToRound2Inputs(participants, r1Outs)
	r2OutsU, err := test_utils.DoSetupRound2(participants, r2Ins)
	require.NoError(t, err)
	for _, out := range r2OutsU {
		require.Len(t, out, len(identities)-1)
	}

	r3InsU := test_utils.MapSetupRound2OutputsToRound3Inputs(participants, r2OutsU)
	r3OutsU, err := test_utils.DoSetupRound3(participants, r3InsU)
	require.NoError(t, err)
	for _, out := range r3OutsU {
		require.Len(t, out, len(identities)-1)
	}

	r4InsU := test_utils.MapSetupRound3OutputsToRound4Inputs(participants, r3OutsU)
	allPairwiseSeeds, err := test_utils.DoSetupRound4(participants, r4InsU)
	require.NoError(t, err)

	// we have the right number of pairs
	for i := range participants {
		require.Len(t, allPairwiseSeeds[i], len(identities)-1)
	}

	// each pair of seeds for all parties match
	for i := range participants {
		for j := range participants {
			if i == j {
				continue
			}
			seedOfIFromJ := allPairwiseSeeds[i][participants[j].MyIdentityKey]
			seedOfJFromI := allPairwiseSeeds[j][participants[i].MyIdentityKey]
			require.EqualValues(t, seedOfIFromJ, seedOfJFromI)
		}
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, n := range []int{2, 10} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Happy path with curve=%s and n=%d", boundedCurve.Name, boundedN), func(t *testing.T) {
				t.Parallel()
				testHappyPath(t, boundedCurve, boundedN)
			})
		}
	}
}
