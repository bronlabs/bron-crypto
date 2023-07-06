package sample_test

import (
	"fmt"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat/combin"
)

var h = sha3.New256

func doSetup(curve *curves.Curve, identities []integration.IdentityKey) (allPairwiseSeeds []zero.PairwiseSeeds, err error) {
	participants, err := test_utils.MakeSetupParticipants(curve, identities)
	if err != nil {
		return nil, err
	}
	r1Outs, err := test_utils.DoSetupRound1(participants)
	if err != nil {
		return nil, err
	}

	r2Ins := test_utils.MapSetupRound1OutputsToRound2Inputs(participants, r1Outs)
	r2OutsU, err := test_utils.DoSetupRound2(participants, r2Ins)
	if err != nil {
		return nil, err
	}

	r3InsU := test_utils.MapSetupRound2OutputsToRound3Inputs(participants, r2OutsU)
	r3OutsU, err := test_utils.DoSetupRound3(participants, r3InsU)
	if err != nil {
		return nil, err
	}

	r4InsU := test_utils.MapSetupRound3OutputsToRound4Inputs(participants, r3OutsU)
	allPairwiseSeeds, err = test_utils.DoSetupRound4(participants, r4InsU)
	if err != nil {
		return nil, err
	}
	return allPairwiseSeeds, nil
}

func doSample(t *testing.T, curve *curves.Curve, identities []integration.IdentityKey, seeds []zero.PairwiseSeeds) {
	t.Helper()
	participants, err := test_utils.MakeSampleParticipants(curve, identities, seeds)
	require.NoError(t, err)
	for _, participant := range participants {
		require.NotNil(t, participant)
	}
	r1Out, err := test_utils.DoSampleRound1(participants)
	require.NoError(t, err)
	r2In := test_utils.MapSampleRound2OutputsToRound3Inputs(participants, r1Out)
	samples, err := test_utils.DoSampleRound2(participants, r2In)
	require.NoError(t, err)
	require.Len(t, samples, len(identities))

	sum := curve.Scalar.Zero()
	for _, sample := range samples {
		require.False(t, sample.IsZero())
		sum = sum.Add(sample)
	}
	require.True(t, sum.IsZero())
}

func testHappyPath(t *testing.T, curve *curves.Curve, n int) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	allPairwiseSeeds, err := doSetup(curve, allIdentities)
	require.NoError(t, err)
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations := combin.Combinations(n, subsetSize)
		for _, combinationIndices := range combinations {
			identities := make([]integration.IdentityKey, subsetSize)
			seeds := make([]zero.PairwiseSeeds, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
				seeds[i] = allPairwiseSeeds[index]
			}
			doSample(t, curve, identities, seeds)
		}
	}
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
