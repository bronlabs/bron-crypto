package sample_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/combinatorics"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/fkechacha20"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/sample"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/testutils"
)

func doSetup(curve curves.Curve, identities []types.IdentityKey) (allPairwiseSeeds []przs.PairWiseSeeds, err error) {
	participants, err := testutils.MakeSetupParticipants(curve, identities, crand.Reader)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not make setup participants")
	}

	r1OutsU, err := testutils.DoSetupRound1(participants)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run setup round 1")
	}

	r2InsU := ttu.MapUnicastO2I(participants, r1OutsU)
	r2OutsU, err := testutils.DoSetupRound2(participants, r2InsU)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run setup round 2")
	}

	r3InsU := ttu.MapUnicastO2I(participants, r2OutsU)
	allPairwiseSeeds, err = testutils.DoSetupRound3(participants, r3InsU)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not run setup round 3")
	}
	return allPairwiseSeeds, nil
}

func doSample(t *testing.T, protocol types.MPCProtocol, identities []types.IdentityKey, seeds []przs.PairWiseSeeds, seededPrng csprng.CSPRNG) {
	t.Helper()
	participants, err := testutils.MakeSampleParticipants(protocol, identities, seeds, seededPrng, nil)
	require.NoError(t, err)

	zeroShares, err := testutils.DoSample(participants)
	require.NoError(t, err)
	require.Len(t, zeroShares, len(identities))

	zeroSum := protocol.Curve().ScalarField().Zero()
	for _, zeroShare := range zeroShares {
		require.False(t, zeroShare.IsZero())
		zeroSum = zeroSum.Add(zeroShare)
	}
	require.True(t, zeroSum.IsZero())

	// test sum of all the shares but one doesn't add up to zero
	for i := range zeroShares {
		zeroSum = protocol.Curve().ScalarField().Zero()
		for j, zeroShare := range zeroShares {
			if i != j {
				zeroSum = zeroSum.Add(zeroShare)
			}
		}
		require.False(t, zeroSum.IsZero())
	}
}

func doSampleInvalidSid(t *testing.T, protocol types.MPCProtocol, identities []types.IdentityKey, seeds []przs.PairWiseSeeds, seededPrng csprng.CSPRNG) {
	t.Helper()
	wrongUniqueSessionId := []byte("This is an invalid sid")
	participants, err := testutils.MakeSampleParticipants(protocol, identities, seeds, seededPrng, wrongUniqueSessionId)
	require.NoError(t, err)
	for _, participant := range participants {
		require.NotNil(t, participant)
	}
	zeroShares, err := testutils.DoSample(participants)
	require.NoError(t, err)
	require.Len(t, zeroShares, len(identities))

	sum := protocol.Curve().ScalarField().Zero()
	for _, share := range zeroShares {
		require.False(t, share.IsZero())
		sum = sum.Add(share)
	}
	require.False(t, sum.IsZero())
}

func testInvalidSid(t *testing.T, curve curves.Curve, n int) {
	t.Helper()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)
	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	allPairwiseSeeds, err := doSetup(curve, allIdentities)
	require.NoError(t, err)
	protocol, err := ttu.MakeMPCProtocol(curve, allIdentities)
	require.NoError(t, err)
	seededPrng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)
	N := make([]int, n)
	for i := range n {
		N[i] = i
	}
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations, err := combinatorics.Combinations(N, uint(subsetSize))
		require.NoError(t, err)
		for _, combinationIndices := range combinations {
			identities := make([]types.IdentityKey, subsetSize)
			seeds := make([]przs.PairWiseSeeds, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
				seeds[i] = allPairwiseSeeds[index]
			}
			doSampleInvalidSid(t, protocol, identities, seeds, seededPrng)
		}
	}
}

func testHappyPath(t *testing.T, curve curves.Curve, n int) {
	t.Helper()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)
	allIdentities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)
	protocol, err := ttu.MakeMPCProtocol(curve, allIdentities)
	require.NoError(t, err)

	allPairwiseSeeds, err := doSetup(curve, allIdentities)
	require.NoError(t, err)
	seededPrng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)
	N := make([]int, n)
	for i := range n {
		N[i] = i
	}
	for subsetSize := 2; subsetSize <= n; subsetSize++ {
		combinations, err := combinatorics.Combinations(N, uint(subsetSize))
		require.NoError(t, err)
		for _, combinationIndices := range combinations {
			identities := make([]types.IdentityKey, subsetSize)
			seeds := make([]przs.PairWiseSeeds, subsetSize)
			for i, index := range combinationIndices {
				identities[i] = allIdentities[index]
				seeds[i] = allPairwiseSeeds[index]
			}
			doSample(t, protocol, identities, seeds, seededPrng)
		}
	}
}
func Test_HappyPath(t *testing.T) {
	t.Parallel()
	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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
	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
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
	for _, curve := range []curves.Curve{edwards25519.NewCurve(), k256.NewCurve()} {
		boundedCurve := curve
		t.Run(fmt.Sprintf("InvalidParticipants path with curve=%s", boundedCurve.Name()), func(t *testing.T) {
			t.Parallel()
			testInvalidParticipants(t, boundedCurve)
		})
	}
}

func testInvalidParticipants(t *testing.T, curve curves.Curve) {
	t.Helper()
	h := sha3.New256
	cipherSuite, err := ttu.MakeSignatureProtocol(curve, h)
	require.NoError(t, err)
	allIdentities, _ := ttu.MakeTestIdentities(cipherSuite, 3)
	aliceIdentity := allIdentities[0]
	bobIdentity := allIdentities[1]
	charlieIdentity := allIdentities[2]

	allPairwiseSeeds, _ := doSetup(curve, allIdentities)
	aliceSeed := allPairwiseSeeds[0]
	bobSeed := allPairwiseSeeds[1]
	charlieSeed := allPairwiseSeeds[2]

	uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, allIdentities, crand.Reader)
	require.NoError(t, err)
	protocol, err := ttu.MakeMPCProtocol(curve, allIdentities)
	require.NoError(t, err)

	prng, err := fkechacha20.NewPrng(nil, nil)
	require.NoError(t, err)
	aliceParticipant, err := sample.NewParticipant(uniqueSessionId, aliceIdentity.(types.AuthKey), aliceSeed, protocol, hashset.NewHashableHashSet(aliceIdentity, bobIdentity, charlieIdentity), prng)
	require.NoError(t, err)
	bobParticipant, err := sample.NewParticipant(uniqueSessionId, bobIdentity.(types.AuthKey), bobSeed, protocol, hashset.NewHashableHashSet(aliceIdentity, bobIdentity, charlieIdentity), prng)
	require.NoError(t, err)
	charlieParticipant, err := sample.NewParticipant(uniqueSessionId, charlieIdentity.(types.AuthKey), charlieSeed, protocol, hashset.NewHashableHashSet(bobIdentity, charlieIdentity), prng)
	require.NoError(t, err)

	aliceSample, err := aliceParticipant.Sample()
	require.NoError(t, err)
	require.False(t, aliceSample.IsZero())
	bobSample, err := bobParticipant.Sample()
	require.NoError(t, err)
	require.False(t, bobSample.IsZero())
	charlieSample, err := charlieParticipant.Sample()
	require.NoError(t, err)
	require.False(t, charlieSample.IsZero())

	sum := curve.ScalarField().Zero()
	sum = sum.Add(aliceSample)
	sum = sum.Add(bobSample)
	sum = sum.Add(charlieSample)

	require.False(t, sum.IsZero())
}
