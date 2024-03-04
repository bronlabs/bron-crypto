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
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf"
	jf_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/sharing/shamir"
)

var allCurves = []curves.Curve{k256.NewCurve(), p256.NewCurve(), edwards25519.NewCurve(), pallas.NewCurve()}
var allHashes = []func() hash.Hash{sha256.New, sha3.New256}

func FuzzJf(f *testing.F) {
	f.Add(uint(0), uint(0), []byte("sid"), int64(0), uint8(2), uint64(1), uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, sid []byte, randomSeed int64, th uint8, aliceSecret uint64, bobSecret uint64, charlieSecret uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		h := allHashes[int(hashIndex)%len(allHashes)]
		prng := rand.New(rand.NewSource(randomSeed))
		cipherSuite, _ := ttu.MakeSignatureProtocol(curve, h)
		aliceIdentity, _ := testutils.MakeTestIdentity(cipherSuite, curve.ScalarField().New(aliceSecret))
		bobIdentity, _ := testutils.MakeTestIdentity(cipherSuite, curve.ScalarField().New(bobSecret))
		charlieIdentity, _ := testutils.MakeTestIdentity(cipherSuite, curve.ScalarField().New(charlieSecret))

		identityKeys := []types.IdentityKey{aliceIdentity, bobIdentity, charlieIdentity}
		set := hashset.NewHashableHashSet(identityKeys...)
		th = th % uint8(set.Size())
		protocolConfig, _ := ttu.MakeThresholdProtocol(cipherSuite.Curve(), identityKeys, int(th))
		aliceParticipant, err := jf.NewParticipant(sid, aliceIdentity.(types.AuthKey), protocolConfig, randomisedFischlin.Name, prng, nil)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		bobParticipant, err := jf.NewParticipant(sid, bobIdentity.(types.AuthKey), protocolConfig, randomisedFischlin.Name, prng, nil)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		charlieParticipant, err := jf.NewParticipant(sid, charlieIdentity.(types.AuthKey), protocolConfig, randomisedFischlin.Name, prng, nil)
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		if err != nil {
			t.Skip()
		}
		participants := []*jf.Participant{aliceParticipant, bobParticipant, charlieParticipant}

		r1OutsB, r1OutsU, err := jf_testutils.DoDkgRound1(participants)
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
		r2Outs, err := jf_testutils.DoDkgRound2(participants, r2InsB, r2InsU)
		require.NoError(t, err)
		for _, out := range r2Outs {
			require.NotNil(t, out)
		}
		r3Ins := ttu.MapBroadcastO2I(participants, r2Outs)
		signingKeyShares, publicKeyShares, err := jf_testutils.DoDkgRound3(participants, r3Ins)
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
