package interactive_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/integration/test_utils"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/protocol"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/ecdsa"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/keygen/trusted_dealer"
	"github.com/copperexchange/crypto-primitives-go/pkg/signatures/threshold/tecdsa/lindell17/signing/interactive"
	"github.com/gtank/merlin"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_HappyPath(t *testing.T) {
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
	transcript := merlin.NewTranscript("DummyTranscriptLabel")

	primary, err := interactive.NewPrimaryCosigner(alice, bob, shards[alice], cohortConfig, sessionId, transcript, crand.Reader)
	require.NotNil(t, primary)
	require.NoError(t, err)

	secondary, err := interactive.NewSecondaryCosigner(bob, alice, shards[bob], cohortConfig, sessionId, transcript, crand.Reader)
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
