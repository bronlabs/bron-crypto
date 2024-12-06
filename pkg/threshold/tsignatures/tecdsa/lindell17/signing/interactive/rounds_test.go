package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randfischlin"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	jfTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	lindell17DkgTestutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
	interactiveSigning "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/signing/interactive"
)

var cn = randomisedFischlin.Name

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	hash := sha256.New
	cipherSuite, err := testutils.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)
	alice, bob, charlie := identities[0], identities[1], identities[2]

	protocol, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(t, err)

	message := []byte("Hello World!")

	shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shards)
	require.Equal(t, shards.Size(), int(protocol.TotalParties()))

	aliceShard, exists := shards.Get(alice)
	require.True(t, exists)
	bobShard, exists := shards.Get(bob)
	require.True(t, exists)
	_, exists = shards.Get(charlie)
	require.True(t, exists)

	sessionId := []byte("TestSession")
	primary, err := interactiveSigning.NewPrimaryCosigner(sessionId, alice.(types.AuthKey), bob, aliceShard, protocol, cn, nil, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactiveSigning.NewSecondaryCosigner(sessionId, bob.(types.AuthKey), alice, bobShard, protocol, cn, nil, crand.Reader)
	require.NotNil(t, secondary)
	require.NoError(t, err)

	r1, err := primary.Round1()
	require.NoError(t, err)

	r2, err := secondary.Round2(ttu.GobRoundTripMessage(t, r1))
	require.NoError(t, err)

	r3, err := primary.Round3(ttu.GobRoundTripMessage(t, r2))
	require.NoError(t, err)

	r4, err := secondary.Round4(ttu.GobRoundTripMessage(t, r3), message)
	require.NoError(t, err)

	signature, err := primary.Round5(ttu.GobRoundTripMessage(t, r4), message)
	require.NoError(t, err)

	err = ecdsa.Verify(signature, cipherSuite.Hash(), bobShard.SigningKeyShare.PublicKey, message)
	require.NoError(t, err)
}

func Test_HappyPathWithDkg(t *testing.T) {
	if os.Getenv("DEFLAKE_TIME_TEST") == "1" {
		t.Skip("Skipping this test in deflake mode.")
	}
	if testing.Short() {
		t.Skip("Skipping Lindell 2017 rounds tests.")
	}
	t.Parallel()

	curve := k256.NewCurve()
	hash := sha256.New
	cipherSuite, err := testutils.MakeSigningSuite(curve, hash)
	require.NoError(t, err)
	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)
	protocol, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
	require.NoError(t, err)

	alice := 0
	bob := 1
	sid := []byte("SessionId")
	message := []byte("Hello World!")

	signingKeyShares, publicKeyShares := doJf(t, sid, protocol, identities)
	shards := lindell17DkgTestutils.RunDKG(t, sid, protocol, identities, signingKeyShares, publicKeyShares)
	signature := doLindell17Sign(t, sid, protocol, identities, shards, alice, bob, message)

	err = ecdsa.Verify(signature, cipherSuite.Hash(), shards[bob].SigningKeyShare.PublicKey, message)
	require.NoError(t, err)
}

func Test_RecoveryIdCalculation(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		p256.NewCurve(),
		k256.NewCurve(),
	}

	for _, c := range supportedCurves {
		curve := c
		t.Run(fmt.Sprintf("curve: %s", curve.Name()), func(t *testing.T) {
			t.Parallel()
			cipherSuite, err := testutils.MakeSigningSuite(curve, sha256.New)
			require.NoError(t, err)

			identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
			require.NoError(t, err)
			alice, bob, charlie := identities[0], identities[1], identities[2]

			protocol, err := testutils.MakeThresholdSignatureProtocol(cipherSuite, identities, 2, identities)
			require.NoError(t, err)

			message := []byte("Hello World!")
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(protocol, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, shards)
			require.Equal(t, shards.Size(), int(protocol.TotalParties()))

			aliceShard, exists := shards.Get(alice)
			require.True(t, exists)
			bobShard, exists := shards.Get(bob)
			require.True(t, exists)
			_, exists = shards.Get(charlie)
			require.True(t, exists)

			sessionId := []byte("TestSession")
			primary, err := interactiveSigning.NewPrimaryCosigner(sessionId, alice.(types.AuthKey), bob, aliceShard, protocol, cn, nil, crand.Reader)
			require.NotNil(t, primary)
			require.NoError(t, err)

			secondary, err := interactiveSigning.NewSecondaryCosigner(sessionId, bob.(types.AuthKey), alice, bobShard, protocol, cn, nil, crand.Reader)
			require.NotNil(t, secondary)
			require.NoError(t, err)

			r1, err := primary.Round1()
			require.NoError(t, err)

			r2, err := secondary.Round2(r1)
			require.NoError(t, err)

			r3, err := primary.Round3(ttu.GobRoundTripMessage(t, r2))
			require.NoError(t, err)

			r4, err := secondary.Round4(ttu.GobRoundTripMessage(t, r3), message)
			require.NoError(t, err)

			signature, err := primary.Round5(ttu.GobRoundTripMessage(t, r4), message)
			require.NoError(t, err)

			err = ecdsa.Verify(signature, cipherSuite.Hash(), bobShard.SigningKeyShare.PublicKey, message)
			require.NoError(t, err)

			t.Run("signature should be normalised", func(t *testing.T) {
				t.Parallel()
				signatureCopy := &ecdsa.Signature{
					R: signature.R,
					S: signature.S,
					V: signature.V,
				}
				signatureCopy.Normalise()
				require.Zero(t, signatureCopy.S.Cmp(signature.S))
			})

			t.Run("should recover public key", func(t *testing.T) {
				t.Parallel()
				recoveredPublicKey, err := ecdsa.RecoverPublicKey(signature, cipherSuite.Hash(), message)
				require.NoError(t, err)
				require.True(t, recoveredPublicKey.Equal(aliceShard.SigningKeyShare.PublicKey))
			})
		})
	}
}

func doJf(t *testing.T, sid []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PartialPublicKeys) {
	t.Helper()
	jfParticipants, err := jfTestutils.MakeParticipants(t, sid, protocol, identities, cn, nil)
	require.NoError(t, err)
	r1OutsB, r1OutsU, err := jfTestutils.DoDkgRound1(t, jfParticipants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Equal(t, out.Size(), int(protocol.TotalParties())-1)
	}

	r2InsB, r2InsU := ttu.MapO2I(t, jfParticipants, r1OutsB, r1OutsU)
	r2Outs, err := jfTestutils.DoDkgRound2(t, jfParticipants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}

	r3Ins := ttu.MapBroadcastO2I(t, jfParticipants, r2Outs)
	signingKeyShares, publicKeyShares, err = jfTestutils.DoDkgRound3(t, jfParticipants, r3Ins)
	require.NoError(t, err)

	return signingKeyShares, publicKeyShares
}

func doLindell17Sign(t *testing.T, sid []byte, protocol types.ThresholdSignatureProtocol, identities []types.IdentityKey, shards []*lindell17.Shard, alice, bob int, message []byte) (signature *ecdsa.Signature) {
	t.Helper()

	primary, err := interactiveSigning.NewPrimaryCosigner(sid, identities[alice].(types.AuthKey), identities[bob], shards[alice], protocol, cn, nil, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactiveSigning.NewSecondaryCosigner(sid, identities[bob].(types.AuthKey), identities[alice], shards[bob], protocol, cn, nil, crand.Reader)
	require.NotNil(t, secondary)
	require.NoError(t, err)

	r1, err := primary.Round1()
	require.NoError(t, err)

	r2, err := secondary.Round2(ttu.GobRoundTripMessage(t, r1))
	require.NoError(t, err)

	r3, err := primary.Round3(ttu.GobRoundTripMessage(t, r2))
	require.NoError(t, err)

	r4, err := secondary.Round4(ttu.GobRoundTripMessage(t, r3), message)
	require.NoError(t, err)

	signature, err = primary.Round5(ttu.GobRoundTripMessage(t, r4), message)
	require.NoError(t, err)

	return signature
}
