package pedersen_test

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
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	agreeonrandom_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/agreeonrandom/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/pedersen/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}
var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func Fuzz_Test(f *testing.F) {
	f.Add(uint(0), uint(0), uint64(1), uint64(2), uint64(3), []byte("sid"), int64(0), uint8(2))
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, aliceSecret uint64, bobSecret uint64, charlieSecret uint64, sid []byte, randomSeed int64, th uint8) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		prng := rand.New(rand.NewSource(randomSeed))
		cipherSuite, _ := ttu.MakeSigningSuite(curve, h)
		aliceIdentity, _ := ttu.MakeTestIdentity(cipherSuite, curve.ScalarField().New(aliceSecret))
		bobIdentity, _ := ttu.MakeTestIdentity(cipherSuite, curve.ScalarField().New(bobSecret))
		charlieIdentity, _ := ttu.MakeTestIdentity(cipherSuite, curve.ScalarField().New(charlieSecret))
		identities := []types.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}
		set := hashset.NewHashableHashSet(identities...)
		th = th % uint8(set.Size())

		protocolConfig, err := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identities, int(th))
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		uniqueSessionId, err := agreeonrandom_testutils.RunAgreeOnRandom(curve, identities, prng)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}

		participants, err := testutils.MakeParticipants(uniqueSessionId, protocolConfig, identities, nil)
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
			require.Equal(t, out.Size(), int(protocolConfig.TotalParties())-1)
		}

		r2InsB, r2InsU := ttu.MapO2I(participants, r1OutsB, r1OutsU)
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

		shamirDealer, err := shamir.NewDealer(uint(th), uint(set.Size()), curve)
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
				Id:    uint(participants[i].SharingId()),
				Value: signingKeyShares[i].Share,
			}
		}

		reconstructedPrivateKey, err := shamirDealer.Combine(shamirShares...)
		require.NoError(t, err)

		derivedPublicKey := curve.ScalarBaseMult(reconstructedPrivateKey)
		require.True(t, signingKeyShares[0].PublicKey.Equal(derivedPublicKey))
	})
}
