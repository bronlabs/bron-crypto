package sample_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"
	"gonum.org/v1/gonum/stat/combin"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/testutils"
)

func doSetup(curve curves.Curve, identities []integration.IdentityKey) (allPairwiseSeeds []przs.PairwiseSeeds, err error) {
	participants, err := testutils.MakeSetupParticipants(curve, identities, crand.Reader)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make setup participants")
	}

	r1OutsU, err := testutils.DoSetupRound1(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run setup round 1")
	}

	r2InsU := integration_testutils.MapUnicastO2I(participants, r1OutsU)
	r2OutsU, err := testutils.DoSetupRound2(participants, r2InsU)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run setup round 2")
	}

	r3InsU := integration_testutils.MapUnicastO2I(participants, r2OutsU)
	allPairwiseSeeds, err = testutils.DoSetupRound3(participants, r3InsU)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run setup round 3")
	}
	return allPairwiseSeeds, nil
}

func doSample(t *testing.T, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, seeds []przs.PairwiseSeeds, seededPrng csprng.CSPRNG) {
	t.Helper()
	participants, err := testutils.MakeSampleParticipants(cohortConfig, identities, seeds, seededPrng, nil)
	require.NoError(t, err)

	zeroShares, err := testutils.DoSample(participants)
	require.NoError(t, err)
	require.Len(t, zeroShares, len(identities))

	zeroSum := cohortConfig.CipherSuite.Curve.Scalar().Zero()
	for _, zeroShare := range zeroShares {
		require.False(t, zeroShare.IsZero())
		zeroSum = zeroSum.Add(zeroShare)
	}
	require.True(t, zeroSum.IsZero())

	// test sum of all the shares but one doesn't add up to zero
	for i := range zeroShares {
		zeroSum = cohortConfig.CipherSuite.Curve.Scalar().Zero()
		for j, zeroShare := range zeroShares {
			if i != j {
				zeroSum = zeroSum.Add(zeroShare)
			}
		}
		require.False(t, zeroSum.IsZero())
	}
}

func doSampleInvalidSid(t *testing.T, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, seeds []przs.PairwiseSeeds, seededPrng csprng.CSPRNG) {
	t.Helper()
	wrongUniqueSessionId := []byte("This is an invalid sid")
	participants, err := testutils.MakeSampleParticipants(cohortConfig, identities, seeds, seededPrng, wrongUniqueSessionId)
	require.NoError(t, err)
	for _, participant := range participants {
		require.NotNil(t, participant)
	}
	zeroShares, err := testutils.DoSample(participants)
	require.NoError(t, err)
	require.Len(t, zeroShares, len(identities))

	sum := cohortConfig.CipherSuite.Curve.Scalar().Zero()
	for _, share := range zeroShares {
		require.False(t, share.IsZero())
		sum = sum.Add(share)
	}
	require.False(t, sum.IsZero())
}

func testInvalidSid(t *testing.T, curve curves.Curve, n int) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	allPairwiseSeeds, err := doSetup(curve, allIdentities)
	require.NoError(t, err)
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(allIdentities),
	}
	seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
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
			doSampleInvalidSid(t, cohortConfig, identities, seeds, seededPrng)
		}
	}
}

func testHappyPath(t *testing.T, curve curves.Curve, n int) {
	t.Helper()
	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  sha3.New256,
	}
	allIdentities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet(allIdentities),
	}

	allPairwiseSeeds, err := doSetup(curve, allIdentities)
	require.NoError(t, err)
	seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
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
			doSample(t, cohortConfig, identities, seeds, seededPrng)
		}
	}
}
func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.New(), k256.New()} {
		for _, n := range []int{5} {
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
	allIdentities, _ := integration_testutils.MakeTestIdentities(cipherSuite, 3)
	aliceIdentity := allIdentities[0]
	bobIdentity := allIdentities[1]
	charlieIdentity := allIdentities[2]

	allPairwiseSeeds, _ := doSetup(curve, allIdentities)
	aliceSeed := allPairwiseSeeds[0]
	bobSeed := allPairwiseSeeds[1]
	charlieSeed := allPairwiseSeeds[2]

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, allIdentities, crand.Reader)
	require.NoError(t, err)

	cohortConfig := &integration.CohortConfig{
		CipherSuite:  cipherSuite,
		Participants: hashset.NewHashSet([]integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}),
	}
	prng, err := chacha20.NewChachaPRNG(nil, nil)
	require.NoError(t, err)
	aliceParticipant, _ := sample.NewParticipant(cohortConfig, uniqueSessionId, aliceIdentity.(integration.AuthKey), aliceSeed, hashset.NewHashSet([]integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}), prng)
	bobParticipant, _ := sample.NewParticipant(cohortConfig, uniqueSessionId, bobIdentity.(integration.AuthKey), bobSeed, hashset.NewHashSet([]integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}), prng)
	charlieParticipant, _ := sample.NewParticipant(cohortConfig, uniqueSessionId, charlieIdentity.(integration.AuthKey), charlieSeed, hashset.NewHashSet([]integration.IdentityKey{bobIdentity, charlieIdentity}), prng)

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
