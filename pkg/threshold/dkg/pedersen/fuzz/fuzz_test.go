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
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	testutils_integration "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

var allCurves = []curves.Curve{k256.New(), p256.New(), edwards25519.New(), pallas.New()}
var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), uint(0), uint64(1), uint64(2), uint64(3), []byte("sid"), int64(0), uint8(2))
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, aliceSecret uint64, bobSecret uint64, charlieSecret uint64, sid []byte, randomSeed int64, th uint8) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		prng := rand.New(rand.NewSource(randomSeed))
		cipherSuite := &integration.CipherSuite{
			Curve: curve,
			Hash:  h,
		}
		aliceIdentity, _ := testutils_integration.MakeTestIdentity(cipherSuite, curve.Scalar().New(aliceSecret))
		bobIdentity, _ := testutils_integration.MakeTestIdentity(cipherSuite, curve.Scalar().New(bobSecret))
		charlieIdentity, _ := testutils_integration.MakeTestIdentity(cipherSuite, curve.Scalar().New(charlieSecret))
		identities := []integration.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}
		set := hashset.NewHashSet(identities)
		th = th % uint8(set.Len())

		cohortConfig, err := testutils_integration.MakeCohortProtocol(cipherSuite, protocols.FROST, identities, int(th), identities)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		uniqueSessionId, err := agreeonrandom_testutils.ProduceSharedRandomValue(curve, identities, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		participants, err := testutils.MakeParticipants(uniqueSessionId, cohortConfig, identities, nil)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		r1OutsB, r1OutsU, err := testutils.DoDkgRound1(participants, nil)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		for _, out := range r1OutsU {
			require.Len(t, out, cohortConfig.Protocol.TotalParties-1)
		}

		r2InsB, r2InsU := testutils.MapDkgRound1OutputsToRound2Inputs(participants, r1OutsB, r1OutsU)
		signingKeyShares, publicKeyShares, err := testutils.DoDkgRound2(participants, r2InsB, r2InsU)
		require.NoError(t, err)

		for _, publicKeyShare := range publicKeyShares {
			require.NotNil(t, publicKeyShare)
		}

		// each signing share is different
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.NotZero(t, signingKeyShares[i].Share.Cmp(signingKeyShares[j].Share))
			}
		}

		// each public key is the same
		for i := 0; i < len(signingKeyShares); i++ {
			for j := i + 1; j < len(signingKeyShares); j++ {
				require.True(t, signingKeyShares[i].PublicKey.Equal(signingKeyShares[i].PublicKey))
			}
		}

		shamirDealer, err := shamir.NewDealer(int(th), set.Len(), curve)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		require.NotNil(t, shamirDealer)
		shamirShares := make([]*shamir.Share, len(participants))
		for i := 0; i < len(participants); i++ {
			shamirShares[i] = &shamir.Share{
				Id:    participants[i].GetSharingId(),
				Value: signingKeyShares[i].Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
	})
}
