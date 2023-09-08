package agreeonrandom_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/base/integration"
	test_utils_integration "github.com/copperexchange/knox-primitives/pkg/base/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/threshold/agreeonrandom"
	"github.com/copperexchange/knox-primitives/pkg/threshold/agreeonrandom/test_utils"
)

func doRoundsWithMockR1Output(t *testing.T, curve curves.Curve, identities []integration.IdentityKey) []byte {
	t.Helper()
	var participants []*agreeonrandom.Participant
	for _, identity := range identities {
		var participant *agreeonrandom.Participant
		participant, _ = agreeonrandom.NewParticipant(curve, identity, hashset.NewHashSet(identities), nil, crand.Reader)
		participants = append(participants, participant)
	}

	r1Out, err := test_utils.DoRound1(participants)
	require.NoError(t, err)
	r2In := test_utils.MapRound1OutputsToRound2Inputs(participants, r1Out)
	r2Out, err := test_utils.DoRound2(participants, r2In)
	require.NoError(t, err)
	r3In := test_utils.MapRound2OutputsToRound3Inputs(participants, r2Out)
	agreeOnRandoms, err := test_utils.DoRound3(participants, r3In)
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
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	var random []byte
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations := combin.Combinations(n, subsetSize)
		for _, combinationIndices := range combinations {
			identities := make([]integration.IdentityKey, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
			}
			random, err = test_utils.ProduceSharedRandomValue(curve, identities, crand.Reader)
			require.NoError(t, err)
		}
	}
	return random
}

func testWithMockR1Output(t *testing.T, curve curves.Curve, n int) []byte {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	var random []byte
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations := combin.Combinations(n, subsetSize)
		for _, combinationIndices := range combinations {
			identities := make([]integration.IdentityKey, subsetSize)
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
	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
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
