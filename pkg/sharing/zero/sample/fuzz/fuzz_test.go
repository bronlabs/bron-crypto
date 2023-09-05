package fuzz

import (
	"crypto/sha256"
	"hash"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	test_utils2 "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/datastructures/hashset"
	"github.com/copperexchange/knox-primitives/pkg/sharing/zero/przs/test_utils"
)

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}
var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, message []byte, randomSeed int64, aliceSecret uint64, bobSecret uint64, charlieSecret uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		prng := rand.New(rand.NewSource(randomSeed))
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}

		aliceIdentity, _ := test_utils2.MakeIdentity(cipherSuite, curve.Scalar().New(aliceSecret))
		bobIdentity, _ := test_utils2.MakeIdentity(cipherSuite, curve.Scalar().New(bobSecret))
		charlieIdentity, _ := test_utils2.MakeIdentity(cipherSuite, curve.Scalar().New(charlieSecret))
		identities := []integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}

		cohortConfig := &integration.CohortConfig{
			CipherSuite:  cipherSuite,
			Participants: hashset.NewHashSet(identities),
		}

		participants, err := test_utils.MakeSetupParticipants(curve, identities, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip(err.Error())
		}

		r1OutsU, err := test_utils.DoSetupRound1(participants)
		require.NoError(t, err)

		r2InsU := test_utils.MapSetupRound1OutputsToRound2Inputs(participants, r1OutsU)
		r2OutsU, err := test_utils.DoSetupRound2(participants, r2InsU)
		require.NoError(t, err)

		r3InsU := test_utils.MapSetupRound2OutputsToRound3Inputs(participants, r2OutsU)
		allPairwiseSeeds, err := test_utils.DoSetupRound3(participants, r3InsU)
		require.NoError(t, err)

		sampleParticipants, err := test_utils.MakeSampleParticipants(cohortConfig, identities, allPairwiseSeeds)
		require.NoError(t, err)
		for _, participant := range sampleParticipants {
			require.NotNil(t, participant)
		}
		samples, err := test_utils.DoSample(sampleParticipants)
		require.NoError(t, err)

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
