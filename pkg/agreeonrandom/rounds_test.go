package agreeonrandom_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom"
	"github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	integration_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat/combin"
)

type AttackerRandomReader struct {
}

func (a *AttackerRandomReader) Read(p []byte) (n int, err error) {
	return 0, nil
}

func doRoundsWithMockR1Output(t *testing.T, curve *curves.Curve, identities []integration.IdentityKey, n int) []byte {
	t.Helper()
	attackerReader := &AttackerRandomReader{}
	var participants []*agreeonrandom.Participant
	attackerIndex := 0
	for i, identity := range identities {
		var participant *agreeonrandom.Participant
		if i == attackerIndex {
			participant, _ = agreeonrandom.NewParticipant(curve, identity, identities, nil, attackerReader)
		} else {
			participant, _ = agreeonrandom.NewParticipant(curve, identity, identities, nil, crand.Reader)
		}
		participants = append(participants, participant)
	}

	r1Out, err := test_utils.DoRound1(participants)
	require.NoError(t, err)
	r2In := test_utils.MapRound1OutputsToRound2Inputs(participants, r1Out)
	agreeOnRandoms, err := test_utils.DoRound2(participants, r2In)
	require.NoError(t, err)
	require.Len(t, agreeOnRandoms, len(identities))

	// check all values in agreeOnRandoms the same
	for i := 1; i < len(agreeOnRandoms); i++ {
		require.Equal(t, agreeOnRandoms[0], agreeOnRandoms[i])
	}

	return agreeOnRandoms[0]
}

func testHappyPath(t *testing.T, curve *curves.Curve, n int) []byte {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := integration_test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	var random []byte
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations := combin.Combinations(n, subsetSize)
		for _, combinationIndices := range combinations {
			identities := make([]integration.IdentityKey, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
			}
			random = test_utils.DoRounds(t, curve, identities, n)
		}
	}
	return random
}

func testWithMockR1Output(t *testing.T, curve *curves.Curve, n int) []byte {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := integration_test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	var random []byte
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations := combin.Combinations(n, subsetSize)
		for _, combinationIndices := range combinations {
			identities := make([]integration.IdentityKey, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
			}
			random = doRoundsWithMockR1Output(t, curve, identities, n)
		}
	}
	return random
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, n := range []int{2, 5} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Happy path with curve=%s and n=%d", boundedCurve.Name, boundedN), func(t *testing.T) {
				t.Parallel()
				testHappyPath(t, boundedCurve, boundedN)
			})
		}
	}
}

func TestTwoSeparateExecutions(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, n := range []int{2, 5} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Happy path with curve=%s and n=%d", boundedCurve.Name, boundedN), func(t *testing.T) {
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
	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, n := range []int{2, 5} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Attacker input curve=%s and n=%d", boundedCurve.Name, boundedN), func(t *testing.T) {
				t.Parallel()
				random1 := testWithMockR1Output(t, boundedCurve, boundedN)
				random2 := testWithMockR1Output(t, boundedCurve, boundedN)
				require.NotEqual(t, random1, random2)
			})
		}
	}
}
