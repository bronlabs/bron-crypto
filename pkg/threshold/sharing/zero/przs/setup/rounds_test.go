package setup_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/testutils"
)

func testHappyPath(t *testing.T, curve curves.Curve, n int) {
	t.Helper()

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  base.CommitmentHashFunction,
	}

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	participants, err := testutils.MakeSetupParticipants(curve, identities, crand.Reader)
	require.NoError(t, err)

	r1OutsU, err := testutils.DoSetupRound1(participants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, len(identities)-1)
	}

	r2InsU := integration_testutils.MapUnicastO2I(participants, r1OutsU)
	r2OutsU, err := testutils.DoSetupRound2(participants, r2InsU)
	require.NoError(t, err)
	for _, out := range r2OutsU {
		require.Len(t, out, len(identities)-1)
	}

	r3InsU := integration_testutils.MapUnicastO2I(participants, r2OutsU)
	allPairwiseSeeds, err := testutils.DoSetupRound3(participants, r3InsU)
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
			seedOfIFromJ := allPairwiseSeeds[i][participants[j].MyAuthKey.Hash()]
			seedOfJFromI := allPairwiseSeeds[j][participants[i].MyAuthKey.Hash()]
			require.EqualValues(t, seedOfIFromJ, seedOfJFromI)
		}
	}
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
		for _, n := range []int{2, 10} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Happy path with curve=%s and n=%d", boundedCurve.Name(), boundedN), func(t *testing.T) {
				t.Parallel()
				testHappyPath(t, boundedCurve, boundedN)
			})
		}
	}
}
