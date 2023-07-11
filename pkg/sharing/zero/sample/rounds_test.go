package sample_test

import (
	"fmt"
	"testing"

	agreeonrandom_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/agreeonrandom/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	test_utils_integration "github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/sample"
	"github.com/copperexchange/crypto-primitives-go/pkg/sharing/zero/test_utils"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat/combin"
)

func doSetup(t *testing.T, curve *curves.Curve, identities []integration.IdentityKey) (allPairwiseSeeds []zero.PairwiseSeeds, err error) {
	participants, err := test_utils.MakeSetupParticipants(t, curve, identities)
	if err != nil {
		return nil, err
	}

	r1OutsU, err := test_utils.DoSetupRound1(participants)
	if err != nil {
		return nil, err
	}

	r2InsU := test_utils.MapSetupRound1OutputsToRound2Inputs(participants, r1OutsU)
	r2OutsU, err := test_utils.DoSetupRound2(participants, r2InsU)
	if err != nil {
		return nil, err
	}

	r3InsU := test_utils.MapSetupRound2OutputsToRound3Inputs(participants, r2OutsU)
	allPairwiseSeeds, err = test_utils.DoSetupRound3(participants, r3InsU)
	if err != nil {
		return nil, err
	}
	return allPairwiseSeeds, nil
}

func doSample(t *testing.T, curve *curves.Curve, identities []integration.IdentityKey, seeds []zero.PairwiseSeeds, InvalidSidParticipantIndex int) {
	t.Helper()
	participants, err := test_utils.MakeSampleParticipants(t, curve, identities, seeds, InvalidSidParticipantIndex)
	require.NoError(t, err)
	for _, participant := range participants {
		require.NotNil(t, participant)
	}
	samples, err := test_utils.DoSample(participants)
	require.NoError(t, err)
	require.Len(t, samples, len(identities))

	sum := curve.Scalar.Zero()
	for _, sample := range samples {
		require.False(t, sample.IsZero())
		sum = sum.Add(sample)
	}
	if InvalidSidParticipantIndex >= 0 {
		require.False(t, sum.IsZero())
	} else {
		require.True(t, sum.IsZero())

		// test sum of all the shares but one doesn't add up to zero
		for i := range samples {
			sum = curve.Scalar.Zero()
			for j, sample := range samples {
				if i != j {
					sum = sum.Add(sample)
				}
			}
			require.False(t, sum.IsZero())
		}
	}
}

func testHappyPath(t *testing.T, curve *curves.Curve, n int) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	allPairwiseSeeds, err := doSetup(t, curve, allIdentities)
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
			doSample(t, curve, identities, seeds, -1)
		}
	}
}

func testInvalidSid(t *testing.T, curve *curves.Curve, n int) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	allPairwiseSeeds, err := doSetup(t, curve, allIdentities)
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
			doSample(t, curve, identities, seeds, 0)
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

func Test_UnmatchedSid(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		for _, n := range []int{2, 5} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Happy path with curve=%s and n=%d", boundedCurve.Name, boundedN), func(t *testing.T) {
				t.Parallel()
				testInvalidSid(t, boundedCurve, boundedN)
			})
		}
	}
}

func Test_InvalidParticipants(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.ED25519(), curves.K256()} {
		boundedCurve := curve
		t.Run(fmt.Sprintf("InvalidParticipants path with curve=%s", boundedCurve.Name), func(t *testing.T) {
			t.Parallel()
			testInvalidParticipants(t, boundedCurve)
		})
	}
}

func testInvalidParticipants(t *testing.T, curve *curves.Curve) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, _ := test_utils_integration.MakeIdentities(cipherSuite, 3)
	aliceIdentity := allIdentities[0]
	bobIdentity := allIdentities[1]
	charlieIdentity := allIdentities[2]

	allPairwiseSeeds, _ := doSetup(t, curve, allIdentities)
	aliceSeed := allPairwiseSeeds[0]
	bobSeed := allPairwiseSeeds[1]
	charlieSeed := allPairwiseSeeds[2]

	uniqueSessionId := agreeonrandom_test_utils.ProduceSharedRandomValue(t, curve, allIdentities, len(allIdentities))

	aliceParticipant, _ := sample.NewParticipant(curve, uniqueSessionId, aliceIdentity, aliceSeed, []integration.IdentityKey{aliceIdentity, bobIdentity})
	bobParticipant, _ := sample.NewParticipant(curve, uniqueSessionId, bobIdentity, bobSeed, []integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity})
	charlieParticipant, _ := sample.NewParticipant(curve, uniqueSessionId, charlieIdentity, charlieSeed, []integration.IdentityKey{bobIdentity, charlieIdentity})

	aliceSample, err := aliceParticipant.Sample()
	require.NoError(t, err)
	require.False(t, aliceSample.IsZero())
	bobSample, err := bobParticipant.Sample()
	require.NoError(t, err)
	require.False(t, bobSample.IsZero())
	charlieSample, err := charlieParticipant.Sample()
	require.NoError(t, err)
	require.False(t, charlieSample.IsZero())

	sum := curve.Scalar.Zero()
	sum = sum.Add(aliceSample)
	sum = sum.Add(bobSample)
	sum = sum.Add(charlieSample)

	require.False(t, sum.IsZero())
}
