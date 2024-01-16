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
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}
var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test_rounds(f *testing.F) {
	f.Add(uint(0), uint(0), uint64(1), uint64(2), uint64(3), int64(0))
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, aliceSecret uint64, bobSecret uint64, charlieSecret uint64, randSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}
		prng := rand.New(rand.NewSource(randSeed))
		aliceIdentity, _ := integration_testutils.MakeTestIdentity(cipherSuite, curve.ScalarField().New(aliceSecret))
		bobIdentity, _ := integration_testutils.MakeTestIdentity(cipherSuite, curve.ScalarField().New(bobSecret))
		charlieIdentity, _ := integration_testutils.MakeTestIdentity(cipherSuite, curve.ScalarField().New(charlieSecret))
		allIdentities := []integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}
		_, err := testutils.RunAgreeOnRandom(curve, allIdentities, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		var participants []*agreeonrandom.Participant
		set := hashset.NewHashSet(allIdentities)
		for _, identity := range set.Iter() {
			participant, err := agreeonrandom.NewParticipant(curve, identity.(integration.AuthKey), set, nil, prng)
			if err != nil && !errs.IsKnownError(err) {
				require.NoError(t, err)
			}
			if err != nil {
				t.Skip(err.Error())
			}
			participants = append(participants, participant)
		}

		r1Out, err := testutils.DoRound1(participants)
		require.NoError(t, err)
		r2In := integration_testutils.MapBroadcastO2I(participants, r1Out)
		r2Out, err := testutils.DoRound2(participants, r2In)
		require.NoError(t, err)
		r3In := integration_testutils.MapBroadcastO2I(participants, r2Out)
		agreeOnRandoms, err := testutils.DoRound3(participants, r3In)
		require.NoError(t, err)
		require.Equal(t, len(agreeOnRandoms), set.Len())

		// check all values in agreeOnRandoms the same
		for j := 1; j < len(agreeOnRandoms); j++ {
			if len(agreeOnRandoms[0]) != len(agreeOnRandoms[j]) {
				t.Error("slices are not equal")
			}

			for i := range agreeOnRandoms[0] {
				if agreeOnRandoms[0][i] != agreeOnRandoms[j][i] {
					t.Error("slices are not equal")
				}
			}
		}
	})
}

func Fuzz_Test_NewParticipant(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, aliceSecret uint64, bobSecret uint64, charlieSecret uint64, randSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}
		prng := rand.New(rand.NewSource(randSeed))
		aliceIdentity, _ := integration_testutils.MakeTestIdentity(cipherSuite, curve.ScalarField().New(aliceSecret))
		bobIdentity, _ := integration_testutils.MakeTestIdentity(cipherSuite, curve.ScalarField().New(bobSecret))
		charlieIdentity, _ := integration_testutils.MakeTestIdentity(cipherSuite, curve.ScalarField().New(charlieSecret))
		allIdentities := []integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}
		_, err := agreeonrandom.NewParticipant(curve, allIdentities[0].(integration.AuthKey), hashset.NewHashSet(allIdentities), nil, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}
