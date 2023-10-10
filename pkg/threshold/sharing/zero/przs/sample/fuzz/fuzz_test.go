package fuzz

import (
	"crypto/sha256"
	"hash"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashset"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/csprng/chacha20"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/zero/przs/testutils"
)

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}
var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, randomSeed int64, aliceSecret uint64, bobSecret uint64, charlieSecret uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		prng := rand.New(rand.NewSource(randomSeed))
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}

		aliceIdentity, _ := integration_testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(aliceSecret))
		bobIdentity, _ := integration_testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(bobSecret))
		charlieIdentity, _ := integration_testutils.MakeTestIdentity(cipherSuite, curve.Scalar().New(charlieSecret))
		identities := []integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}

		cohortConfig := &integration.CohortConfig{
			CipherSuite:  cipherSuite,
			Participants: hashset.NewHashSet(identities),
		}

		participants, err := testutils.MakeSetupParticipants(curve, identities, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}

		r1OutsU, err := testutils.DoSetupRound1(participants)
		require.NoError(t, err)

		r2InsU := testutils.MapSetupRound1OutputsToRound2Inputs(participants, r1OutsU)
		r2OutsU, err := testutils.DoSetupRound2(participants, r2InsU)
		require.NoError(t, err)

		r3InsU := testutils.MapSetupRound2OutputsToRound3Inputs(participants, r2OutsU)
		allPairwiseSeeds, err := testutils.DoSetupRound3(participants, r3InsU)
		require.NoError(t, err)

		seededPrng, err := chacha20.NewChachaPRNG(nil, nil)
		require.NoError(t, err)
		sampleParticipants, err := testutils.MakeSampleParticipants(cohortConfig, identities, allPairwiseSeeds, seededPrng, nil)
		require.NoError(t, err)
		for _, participant := range sampleParticipants {
			require.NotNil(t, participant)
		}
		samples, err := testutils.DoSample(sampleParticipants)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}

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
	})
}
