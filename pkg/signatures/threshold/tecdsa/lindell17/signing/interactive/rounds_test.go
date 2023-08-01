package interactive_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	gennaro_dkg_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/dkg/gennaro/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/ecdsa"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17"
	lindell17_dkg_test_utils "github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/keygen/dkg/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/signing/interactive"
	"github.com/stretchr/testify/require"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	cipherSuite := &integration.CipherSuite{
		Curve: curves.K256(),
		Hash:  sha256.New,
	}

	identities, err := test_utils.MakeIdentities(cipherSuite, 3)
	require.NoError(t, err)
	alice, bob, charlie := identities[0], identities[1], identities[2]

	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol.LINDELL17, identities, 2, []integration.IdentityKey{alice, bob, charlie})
	require.NoError(t, err)

	message := []byte("Hello World!")
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(cohortConfig, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, shards)
	require.Len(t, shards, cohortConfig.TotalParties)

	sessionId := []byte("TestSession")
	primary, err := interactive.NewPrimaryCosigner(alice, bob, shards[alice], cohortConfig, sessionId, nil, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactive.NewSecondaryCosigner(bob, alice, shards[bob], cohortConfig, sessionId, nil, crand.Reader)
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

	ok := signature.VerifyMessage(&ecdsa.PublicKey{Q: shards[bob].SigningKeyShare.PublicKey}, cipherSuite.Hash, message)
	require.True(t, ok)
}

func Test_HappyPathWithDkg(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Lindell 2017 rounds tests.")
	}
	t.Parallel()

	cipherSuite := &integration.CipherSuite{
		Curve: curves.K256(),
		Hash:  sha256.New,
	}
	identities, err := test_utils.MakeIdentities(cipherSuite, 3)
	require.NoError(t, err)
	cohortConfig, err := test_utils.MakeCohort(cipherSuite, protocol.FROST, identities, 2, identities)
	require.NoError(t, err)

	alice := 0
	bob := 1
	sid := []byte("SessionId")
	message := []byte("Hello World!")

	signingKeyShares, publicKeyShares := doGennaroDkg(t, sid, cohortConfig, identities)
	shards := doLindell17Dkg(t, sid, cohortConfig, identities, signingKeyShares, publicKeyShares)
	signature := doLindell17Sign(t, sid, cohortConfig, identities, shards, alice, bob, message)

	ok := signature.VerifyMessage(&ecdsa.PublicKey{Q: shards[alice].SigningKeyShare.PublicKey}, cipherSuite.Hash, message)
	require.True(t, ok)
}

func doGennaroDkg(t *testing.T, sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey) (signingKeyShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares) {
	t.Helper()

	gennaroParticipants, err := gennaro_dkg_test_utils.MakeParticipants(sid, cohortConfig, identities, nil)
	require.NoError(t, err)

	r1OutsB, r1OutsU, err := gennaro_dkg_test_utils.DoDkgRound1(gennaroParticipants)
	require.NoError(t, err)
	for _, out := range r1OutsU {
		require.Len(t, out, cohortConfig.TotalParties-1)
	}

	r2InsB, r2InsU := gennaro_dkg_test_utils.MapDkgRound1OutputsToRound2Inputs(gennaroParticipants, r1OutsB, r1OutsU)
	r2Outs, err := gennaro_dkg_test_utils.DoDkgRound2(gennaroParticipants, r2InsB, r2InsU)
	require.NoError(t, err)
	for _, out := range r2Outs {
		require.NotNil(t, out)
	}
	r3Ins := gennaro_dkg_test_utils.MapDkgRound2OutputsToRound3Inputs(gennaroParticipants, r2Outs)
	signingKeyShares, publicKeyShares, err = gennaro_dkg_test_utils.DoDkgRound3(gennaroParticipants, r3Ins)
	require.NoError(t, err)

	return signingKeyShares, publicKeyShares
}

func doLindell17Dkg(t *testing.T, sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, signingKeyShares []*threshold.SigningKeyShare, publicKeyShares []*threshold.PublicKeyShares) (shards []*lindell17.Shard) {
	t.Helper()

	lindellParticipants, err := lindell17_dkg_test_utils.MakeParticipants(sid, cohortConfig, identities, signingKeyShares, publicKeyShares, nil, nil)
	require.NoError(t, err)

	r1o, err := lindell17_dkg_test_utils.DoDkgRound1(lindellParticipants)
	require.NoError(t, err)

	r2i := lindell17_dkg_test_utils.MapDkgRound1OutputsToRound2Inputs(lindellParticipants, r1o)
	r2o, err := lindell17_dkg_test_utils.DoDkgRound2(lindellParticipants, r2i)
	require.NoError(t, err)

	r3i := lindell17_dkg_test_utils.MapDkgRound2OutputsToRound3Inputs(lindellParticipants, r2o)
	r3o, err := lindell17_dkg_test_utils.DoDkgRound3(lindellParticipants, r3i)
	require.NoError(t, err)

	r4i := lindell17_dkg_test_utils.MapDkgRound3OutputsToRound4Inputs(lindellParticipants, r3o)
	r4o, err := lindell17_dkg_test_utils.DoDkgRound4(lindellParticipants, r4i)
	require.NoError(t, err)

	r5i := lindell17_dkg_test_utils.MapDkgRound4OutputsToRound5Inputs(lindellParticipants, r4o)
	r5o, err := lindell17_dkg_test_utils.DoDkgRound5(lindellParticipants, r5i)
	require.NoError(t, err)

	r6i := lindell17_dkg_test_utils.MapDkgRound5OutputsToRound6Inputs(lindellParticipants, r5o)
	r6o, err := lindell17_dkg_test_utils.DoDkgRound6(lindellParticipants, r6i)
	require.NoError(t, err)

	r7i := lindell17_dkg_test_utils.MapDkgRound6OutputsToRound7Inputs(lindellParticipants, r6o)
	r7o, err := lindell17_dkg_test_utils.DoDkgRound7(lindellParticipants, r7i)
	require.NoError(t, err)

	r8i := lindell17_dkg_test_utils.MapDkgRound7OutputsToRound8Inputs(lindellParticipants, r7o)
	shards, err = lindell17_dkg_test_utils.DoDkgRound8(lindellParticipants, r8i)
	require.NoError(t, err)
	require.NotNil(t, shards)

	return shards
}

func doLindell17Sign(t *testing.T, sid []byte, cohortConfig *integration.CohortConfig, identities []integration.IdentityKey, shards []*lindell17.Shard, alice int, bob int, message []byte) (signature *ecdsa.SignatureExt) {
	t.Helper()

	primary, err := interactive.NewPrimaryCosigner(identities[alice], identities[bob], shards[alice], cohortConfig, sid, nil, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactive.NewSecondaryCosigner(identities[bob], identities[alice], shards[bob], cohortConfig, sid, nil, crand.Reader)
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
