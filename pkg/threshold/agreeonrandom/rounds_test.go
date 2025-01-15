package agreeonrandom_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/bronlabs/krypton-primitives/pkg/base/combinatorics"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/agreeonrandom"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
)

func doRoundsWithMockR1Output(t *testing.T, curve curves.Curve, identities []types.IdentityKey) []byte {
	t.Helper()
	var participants []*agreeonrandom.Participant
	protocol, err := ttu.MakeProtocol(curve, identities)
	require.NoError(t, err)
	for _, identity := range identities {
		var participant *agreeonrandom.Participant
		participant, _ = agreeonrandom.NewParticipant(identity.(types.AuthKey), protocol, nil, crand.Reader)
		participants = append(participants, participant)
	}

	r1Out, err := testutils.DoRound1(participants)
	require.NoError(t, err)
	r2In := ttu.MapBroadcastO2I(t, participants, r1Out)
	r2Out, err := testutils.DoRound2(participants, r2In)
	require.NoError(t, err)
	r3In := ttu.MapBroadcastO2I(t, participants, r2Out)
	agreeOnRandoms, err := testutils.DoRound3(participants, r3In)
	require.NoError(t, err)
	require.Len(t, agreeOnRandoms, len(identities))

	// check all values in agreeOnRandoms the same
	for i := 1; i < len(agreeOnRandoms); i++ {
		require.Equal(t, agreeOnRandoms[0], agreeOnRandoms[i])
	}

	return agreeOnRandoms[0]
}

func testHappyPath(t *testing.T, curve curves.Curve, n int) []byte {
	t.Helper()
	cipherSuite, err := ttu.MakeSigningSuite(curve, sha3.New256)
	require.NoError(t, err)
	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	N := make([]int, n)
	for i := range n {
		N[i] = i
	}
	var random []byte
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations, err := combinatorics.Combinations(N, uint(subsetSize))
		require.NoError(t, err)
		for _, combinationIndices := range combinations {
			identities := make([]types.IdentityKey, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
			}
			random, err = testutils.RunAgreeOnRandom(t, curve, identities, crand.Reader)
			require.NoError(t, err)
		}
	}
	return random
}

func testWithMockR1Output(t *testing.T, curve curves.Curve, n int) []byte {
	t.Helper()
	cipherSuite, err := ttu.MakeSigningSuite(curve, sha3.New256)
	require.NoError(t, err)
	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	N := make([]int, n)
	for i := range n {
		N[i] = i
	}
	var random []byte
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations, err := combinatorics.Combinations(N, uint(subsetSize))
		require.NoError(t, err)
		for _, combinationIndices := range combinations {
			identities := make([]types.IdentityKey, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
			}
			random = doRoundsWithMockR1Output(t, curve, identities)
		}
	}
	return random
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
		for _, n := range []int{2, 5} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Happy path with curve=%s and n=%d", boundedCurve.Name(), boundedN), func(t *testing.T) {
				t.Parallel()
				testHappyPath(t, boundedCurve, boundedN)
			})
		}
	}
}

func TestTwoSeparateExecutions(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
		for _, n := range []int{2, 5} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Happy path with curve=%s and n=%d", boundedCurve.Name(), boundedN), func(t *testing.T) {
				t.Parallel()
				random1 := testHappyPath(t, boundedCurve, boundedN)
				random2 := testHappyPath(t, boundedCurve, boundedN)
				require.NotEqual(t, random1, random2)
			})
		}
	}
}

func TestWithAttackerInput(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
		for _, n := range []int{2, 5} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Attacker input curve=%s and n=%d", boundedCurve.Name(), boundedN), func(t *testing.T) {
				t.Parallel()
				random1 := testWithMockR1Output(t, boundedCurve, boundedN)
				random2 := testWithMockR1Output(t, boundedCurve, boundedN)
				require.NotEqual(t, random1, random2)
			})
		}
	}
}
