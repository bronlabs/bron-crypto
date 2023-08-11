package interactive_test

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/hashing"
	"github.com/copperexchange/knox-primitives/pkg/core/integration"
	integration_test_utils "github.com/copperexchange/knox-primitives/pkg/core/integration/test_utils"
	"github.com/copperexchange/knox-primitives/pkg/core/protocols"
	"github.com/copperexchange/knox-primitives/pkg/signatures/eddsa"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing"
	"github.com/copperexchange/knox-primitives/pkg/signatures/threshold/tschnorr/lindell22/signing/interactive/test_utils"
)

func Test_SanityCheck(t *testing.T) {
	hashFunc := sha512.New
	curve := curves.ED25519()
	prng := crand.Reader

	message := []byte("Hello World!")

	eddsaPrivateKey := curve.NewScalar().Random(prng)
	dHashed, err := hashing.Hash(hashFunc, eddsaPrivateKey.Bytes())
	require.NoError(t, err)

	schnorrPrivateKeyBytes := dHashed[:32]
	schnorrPrivateKey, err := curve.NewScalar().SetBytes(schnorrPrivateKeyBytes)
	require.NoError(t, err)
	publicKey := curve.ScalarBaseMult(schnorrPrivateKey)

	nonce := curve.NewScalar().Random(prng)
	bigR := curve.ScalarBaseMult(nonce)

	eBytes, err := hashing.Hash(hashFunc, bigR.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
	require.NoError(t, err)

	e, err := curve.NewScalar().SetBytesWide(eBytes)
	require.NoError(t, err)

	bigS := nonce.Add(e.Mul(schnorrPrivateKey))

	// verify native
	nativeSignature := append(bigR.ToAffineCompressed()[:], bigS.Bytes()...)
	ok := nativeEddsa.Verify(publicKey.ToAffineCompressed(), message, nativeSignature)
	require.True(t, ok)

	// verify knox
	knoxSignature := &eddsa.Signature{
		R: bigR,
		Z: bigS,
	}
	err = eddsa.Verify(curve, hashFunc, knoxSignature, publicKey, message)
	require.NoError(t, err)
}

func Test_HappyPath(t *testing.T) {
	t.Parallel()

	hashFunc := sha512.New
	curve := curves.ED25519()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}

	identities, err := integration_test_utils.MakeIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohort, err := integration_test_utils.MakeCohort(cipherSuite, protocols.LINDELL22, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(cohort, prng)
	require.NoError(t, err)
	publicKey := shards[identities[0].Hash()].SigningKeyShare.PublicKey

	transcripts := integration_test_utils.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants, err := test_utils.MakeParticipants(sid, cohort, identities[:th], shards, transcripts)
	require.NoError(t, err)

	partialSignatures, err := test_utils.DoInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := signing.Aggregate(partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = eddsa.Verify(curve, hashFunc, signature, publicKey, message)
	require.NoError(t, err)
}
