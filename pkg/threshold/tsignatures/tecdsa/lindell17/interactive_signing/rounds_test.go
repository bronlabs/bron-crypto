package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	randomisedFischlin "github.com/copperexchange/krypton-primitives/pkg/proofs/sigma/compiler/randomised_fischlin"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/ecdsa"
	gennaro_dkg_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/gennaro/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/interactive_signing"
	lindell17_dkg_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/dkg/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tecdsa/lindell17/keygen/trusted_dealer"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	cipherSuite := &integration.CipherSuite{
		Curve: k256.NewCurve(),
		Hash:  sha256.New,
	}

	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)
	alice, bob, charlie := identities[0], identities[1], identities[2]

	cohortConfig, err := testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, lindell17.Threshold, []integration.IdentityKey{alice, bob, charlie})
	require.NoError(t, err)

	message := []byte("Hello World!")
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shards)
	require.Len(t, shards, cohortConfig.Protocol.TotalParties)

	sessionId := []byte("TestSession")
	primary, err := interactive_signing.NewPrimaryCosigner(alice.(integration.AuthKey), bob, shards[alice.Hash()], cohortConfig, sessionId, nil, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactive_signing.NewSecondaryCosigner(bob.(integration.AuthKey), alice, shards[bob.Hash()], cohortConfig, sessionId, nil, crand.Reader)
	require.NotNil(t, secondary)
	require.NoError(t, err)

	r1, err := primary.Round1()
	require.NoError(t, err)

	r2, err := secondary.Round2(r1)
	require.NoError(t, err)

	r3, err := primary.Round3(r2)
	require.NoError(t, err)

	r4, err := secondary.Round4(r3, message)
	require.NoError(t, err)

	signature, err := primary.Round5(r4, message)
	require.NoError(t, err)

	err = ecdsa.Verify(signature, cipherSuite.Hash, shards[bob.Hash()].SigningKeyShare.PublicKey, message)
	require.NoError(t, err)
}

func Test_HappyPathWithDkg(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Lindell 2017 rounds tests.")
	}
	t.Parallel()

	cipherSuite := &integration.CipherSuite{
		Curve: k256.NewCurve(),
		Hash:  sha256.New,
	}
	identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
	require.NoError(t, err)
	cohortConfig, err := testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, lindell17.Threshold, identities)
	require.NoError(t, err)

	alice := 0
	bob := 1
	sid := []byte("SessionId")
	message := []byte("Hello World!")

	signingKeyShares, publicKeyShares := doGennaroDkg(t, sid, cohortConfig, identities)
	shards := doLindell17Dkg(t, sid, cohortConfig, identities, signingKeyShares, publicKeyShares)
	signature := doLindell17Sign(t, sid, cohortConfig, identities, shards, alice, bob, message)

	err = ecdsa.Verify(signature, cipherSuite.Hash, shards[bob].SigningKeyShare.PublicKey, message)
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
			cipherSuite := &integration.CipherSuite{
				Curve: curve,
				Hash:  sha256.New,
			}

			identities, err := testutils.MakeTestIdentities(cipherSuite, 3)
			require.NoError(t, err)
			alice, bob, charlie := identities[0], identities[1], identities[2]

			cohortConfig, err := testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL17, identities, lindell17.Threshold, []integration.IdentityKey{alice, bob, charlie})
			require.NoError(t, err)

			message := []byte("Hello World!")
			require.NoError(t, err)

			shards, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
			require.NoError(t, err)
			require.NotNil(t, shards)
			require.Len(t, shards, cohortConfig.Protocol.TotalParties)

			sessionId := []byte("TestSession")
			primary, err := interactive_signing.NewPrimaryCosigner(alice.(integration.AuthKey), bob, shards[alice.Hash()], cohortConfig, sessionId, nil, crand.Reader)
			require.NotNil(t, primary)
			require.NoError(t, err)

			secondary, err := interactive_signing.NewSecondaryCosigner(bob.(integration.AuthKey), alice, shards[bob.Hash()], cohortConfig, sessionId, nil, crand.Reader)
			require.NotNil(t, secondary)
			require.NoError(t, err)

			r1, err := primary.Round1()
			require.NoError(t, err)

			r2, err := secondary.Round2(r1)
			require.NoError(t, err)

			r3, err := primary.Round3(r2)
			require.NoError(t, err)

			r4, err := secondary.Round4(r3, message)
			require.NoError(t, err)

			signature, err := primary.Round5(r4, message)
			require.NoError(t, err)

			err = ecdsa.Verify(signature, cipherSuite.Hash, shards[bob.Hash()].SigningKeyShare.PublicKey, message)
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
				recoveredPublicKey, err := ecdsa.RecoverPublicKey(signature, cipherSuite.Hash, message)
				require.NoError(t, err)
				require.True(t, recoveredPublicKey.Equal(shards[alice.Hash()].SigningKeyShare.PublicKey))
			})
		})
	}
}

func doGennaroDkg(t *testing.T, sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey) (signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares) {
	t.Helper()

	gennaroParticipants, err := gennaro_dkg_testutils.MakeParticipants(sid, cohortConfig, identities, randomisedFischlin.Name, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := gennaro_dkg_testutils.DoDkgRound1(gennaroParticipants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.Protocol.TotalParties-1)
	}

	r2InsB, r2InsU := integration_testutils.MapO2I(gennaroParticipants, r1OutsB, r1OutsU)
	r2Outs, err := gennaro_dkg_testutils.DoDkgRound2(gennaroParticipants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}
	r3Ins := integration_testutils.MapBroadcastO2I(gennaroParticipants, r2Outs)
	signingKeyShares, publicKeyShares, err = gennaro_dkg_testutils.DoDkgRound3(gennaroParticipants, r3Ins)
	require.NoError(t, err)

	return signingKeyShares, publicKeyShares
}

func doLindell17Dkg(t *testing.T, sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*tsignatures.SigningKeyShare, publicKeyShares []*tsignatures.PublicKeyShares) (shards []*lindell17.Shard) {
	t.Helper()

	lindellParticipants, err := lindell17_dkg_testutils.MakeParticipants(sid, cohortConfig, identities, signingKeyShares, publicKeyShares, nil, nil)
	require.NoError(t, err)

	r1o, err := lindell17_dkg_testutils.DoDkgRound1(lindellParticipants)
	require.NoError(t, err)

	r2i := integration_testutils.MapBroadcastO2I(lindellParticipants, r1o)
	r2o, err := lindell17_dkg_testutils.DoDkgRound2(lindellParticipants, r2i)
	require.NoError(t, err)

	r3i := integration_testutils.MapBroadcastO2I(lindellParticipants, r2o)
	r3o, err := lindell17_dkg_testutils.DoDkgRound3(lindellParticipants, r3i)
	require.NoError(t, err)

	r4i := integration_testutils.MapBroadcastO2I(lindellParticipants, r3o)
	r4o, err := lindell17_dkg_testutils.DoDkgRound4(lindellParticipants, r4i)
	require.NoError(t, err)

	r5i := integration_testutils.MapUnicastO2I(lindellParticipants, r4o)
	r5o, err := lindell17_dkg_testutils.DoDkgRound5(lindellParticipants, r5i)
	require.NoError(t, err)

	r6i := integration_testutils.MapUnicastO2I(lindellParticipants, r5o)
	r6o, err := lindell17_dkg_testutils.DoDkgRound6(lindellParticipants, r6i)
	require.NoError(t, err)

	r7i := integration_testutils.MapUnicastO2I(lindellParticipants, r6o)
	r7o, err := lindell17_dkg_testutils.DoDkgRound7(lindellParticipants, r7i)
	require.NoError(t, err)

	r8i := integration_testutils.MapUnicastO2I(lindellParticipants, r7o)
	shards, err = lindell17_dkg_testutils.DoDkgRound8(lindellParticipants, r8i)
	require.NoError(t, err)
	require.NotNil(t, shards)

	return shards
}

func doLindell17Sign(t *testing.T, sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*lindell17.Shard, alice, bob int, message []byte) (signature *ecdsa.Signature) {
	t.Helper()

	primary, err := interactive_signing.NewPrimaryCosigner(identities[alice].(integration.AuthKey), identities[bob], shards[alice], cohortConfig, sid, nil, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactive_signing.NewSecondaryCosigner(identities[bob].(integration.AuthKey), identities[alice], shards[bob], cohortConfig, sid, nil, crand.Reader)
	require.NotNil(t, secondary)
	require.NoError(t, err)

	r1, err := primary.Round1()
	require.NoError(t, err)

	r2, err := secondary.Round2(r1)
	require.NoError(t, err)

	r3, err := primary.Round3(r2)
	require.NoError(t, err)

	r4, err := secondary.Round4(r3, message)
	require.NoError(t, err)

	signature, err = primary.Round5(r4, message)
	require.NoError(t, err)

	return signature
}
