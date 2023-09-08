package sample_test

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
	agreeonrandom_test_utils "github.com/copperexchange/knox-primitives/pkg/threshold/agreeonrandom/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/knox-primitives/pkg/threshold/sharing/zero/przs/test_utils"
)

func doSetup(curve curves.Curve, identities []integration.IdentityKey) (allPairwiseSeeds []przs.PairwiseSeeds, err error) {
	participants, err := test_utils.MakeSetupParticipants(curve, identities, crand.Reader)
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

func doSample(t *testing.T, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, seeds []przs.PairwiseSeeds) {
	t.Helper()
	participants, err := test_utils.MakeSampleParticipants(cohortConfig, identities, seeds)
	require.NoError(t, err)
	for _, participant := range participants {
		require.NotNil(t, participant)
	}
	samples, err := test_utils.DoSample(participants)
	require.NoError(t, err)
	require.Len(t, samples, len(identities))

	sum := cohortConfig.CipherSuite.Curve.Scalar().Zero()
	for _, sample := range samples {
		require.False(t, sample.IsZero())
		sum = sum.Add(sample)
	}
	require.True(t, sum.IsZero())

	// test sum of all the shares but one doesn't add up to zero
	for i := range samples {
		sum = cohortConfig.CipherSuite.Curve.Scalar().Zero()
		for j, sample := range samples {
			if i != j {
				sum = sum.Add(sample)
			}
		}
		require.False(t, sum.IsZero())
	}
}

func doSampleInvalidSid(t *testing.T, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, seeds []przs.PairwiseSeeds) {
	t.Helper()
	participants, err := test_utils.MakeSampleParticipants(cohortConfig, identities, seeds)
	participants[0].UniqueSessionId = []byte("invalid sid")
	require.NoError(t, err)
	for _, participant := range participants {
		require.NotNil(t, participant)
	}
	samples, err := test_utils.DoSample(participants)
	require.NoError(t, err)
	require.Len(t, samples, len(identities))

	sum := cohortConfig.CipherSuite.Curve.Scalar().Zero()
	for _, sample := range samples {
		require.False(t, sample.IsZero())
		sum = sum.Add(sample)
	}
	require.False(t, sum.IsZero())
}

func testHappyPath(t *testing.T, curve curves.Curve, n int) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(allIdentities),
	}

	allPairwiseSeeds, err := doSetup(curve, allIdentities)
	require.NoError(t, err)
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations := combin.Combinations(n, subsetSize)
		for _, combinationIndices := range combinations {
			identities := make([]integration.IdentityKey, subsetSize)
			seeds := make([]przs.PairwiseSeeds, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
				seeds[i] = allPairwiseSeeds[index]
			}
			doSample(t, cohortConfig, identities, seeds)
		}
	}
}

func testInvalidSid(t *testing.T, curve curves.Curve, n int) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := test_utils_integration.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	allPairwiseSeeds, err := doSetup(curve, allIdentities)
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(allIdentities),
	}
	require.NoError(t, err)
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations := combin.Combinations(n, subsetSize)
		for _, combinationIndices := range combinations {
			identities := make([]integration.IdentityKey, subsetSize)
			seeds := make([]przs.PairwiseSeeds, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
				seeds[i] = allPairwiseSeeds[index]
			}
			doSampleInvalidSid(t, cohortConfig, identities, seeds)
		}
	}
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

func TestInvalidSid(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
		for _, n := range []int{2, 5} {
			boundedCurve := curve
			boundedN := n
			t.Run(fmt.Sprintf("Happy path with curve=%s and n=%d", boundedCurve.Name(), boundedN), func(t *testing.T) {
				t.Parallel()
				testInvalidSid(t, boundedCurve, boundedN)
			})
		}
	}
}

func Test_InvalidParticipants(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
		boundedCurve := curve
		t.Run(fmt.Sprintf("InvalidParticipants path with curve=%s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			testInvalidParticipants(t, boundedCurve)
		})
	}
}

func testInvalidParticipants(t *testing.T, curve curves.Curve) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, _ := test_utils_integration.MakeIdentities(cipherSuite, 3)
	aliceIdentity := allIdentities[0]
	bobIdentity := allIdentities[1]
	charlieIdentity := allIdentities[2]

	allPairwiseSeeds, _ := doSetup(curve, allIdentities)
	aliceSeed := allPairwiseSeeds[0]
	bobSeed := allPairwiseSeeds[1]
	charlieSeed := allPairwiseSeeds[2]

	uniqueSessionId, err := agreeonrandom_test_utils.ProduceSharedRandomValue(curve, allIdentities, crand.Reader)
	require.NoError(t, err)

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet([]integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}),
	}
	aliceParticipant, _ := sample.NewParticipant(cohortConfig, uniqueSessionId, aliceIdentity, aliceSeed, hashset.NewHashSet([]integration.IdentityKey{aliceIdentity, bobIdentity}))
	bobParticipant, _ := sample.NewParticipant(cohortConfig, uniqueSessionId, bobIdentity, bobSeed, hashset.NewHashSet([]integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}))
	charlieParticipant, _ := sample.NewParticipant(cohortConfig, uniqueSessionId, charlieIdentity, charlieSeed, hashset.NewHashSet([]integration.IdentityKey{bobIdentity, charlieIdentity}))

	aliceSample, err := aliceParticipant.Sample()
	require.NoError(t, err)
	require.False(t, aliceSample.IsZero())
	bobSample, err := bobParticipant.Sample()
	require.NoError(t, err)
	require.False(t, bobSample.IsZero())
	charlieSample, err := charlieParticipant.Sample()
	require.NoError(t, err)
	require.False(t, charlieSample.IsZero())

	sum := curve.Scalar().Zero()
	sum = sum.Add(aliceSample)
	sum = sum.Add(bobSample)
	sum = sum.Add(charlieSample)

	require.False(t, sum.IsZero())
}
