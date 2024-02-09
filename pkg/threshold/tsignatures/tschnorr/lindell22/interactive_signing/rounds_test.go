package interactive_signing_test

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/protocols"
	"github.com/copperexchange/krypton-primitives/pkg/base/types/integration"
	integration_testutils "github.com/copperexchange/krypton-primitives/pkg/base/types/integration/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	hashing_bip340 "github.com/copperexchange/krypton-primitives/pkg/hashing/bip340"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/bip340"
	schnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/interactive_signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/interactive_signing/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
)

func Test_SanityCheck(t *testing.T) {
	t.Parallel()

	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	suite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}
	prng := crand.Reader

	message := []byte("Hello World!")

	eddsaPrivateKey, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	dHashed, err := hashing.Hash(hashFunc, eddsaPrivateKey.Bytes())
	require.NoError(t, err)

	schnorrPrivateKeyBytes := dHashed[:32]
	schnorrPrivateKey, err := curve.Scalar().SetBytes(schnorrPrivateKeyBytes)
	require.NoError(t, err)
	publicKey := curve.ScalarBaseMult(schnorrPrivateKey)

	nonce, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	bigR := curve.ScalarBaseMult(nonce)

	eBytes, err := hashing.Hash(hashFunc, bigR.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
	require.NoError(t, err)

	e, err := curve.Scalar().SetBytesWide(utils.SliceReverse(eBytes)) // SetBytesWide expects big endian across all curves and it internally reverses it.
	require.NoError(t, err)

	bigS := nonce.Add(e.Mul(schnorrPrivateKey))

	// verify native
	nativeSignature := append(bigR.ToAffineCompressed()[:], utils.SliceReverse(bigS.Bytes())...)
	ok := nativeEddsa.Verify(publicKey.ToAffineCompressed(), message, nativeSignature)
	require.True(t, ok)

	// verify krypton
	kryptonSignature := &schnorr.Signature{
		R: bigR,
		S: bigS,
	}
	kryptonPublicKey := &schnorr.PublicKey{
		A: publicKey,
	}

	err = schnorr.Verify(suite, kryptonPublicKey, message, kryptonSignature)
	require.NoError(t, err)
}

func Test_HappyPathThresholdEdDSA(t *testing.T) {
	t.Parallel()

	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(cohort, prng)
	require.NoError(t, err)
	publicKey := shards[identities[0].Hash()].SigningKeyShare.PublicKey

	transcripts := integration_testutils.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants, err := testutils.MakeParticipants(sid, cohort, identities[:th], shards, transcripts, false)
	require.NoError(t, err)

	partialSignatures, err := testutils.RunInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := interactive_signing.Aggregate(partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = schnorr.Verify(cipherSuite, &schnorr.PublicKey{A: publicKey}, message, signature)
	require.NoError(t, err)
}

func Test_HappyPathThresholdBIP340(t *testing.T) {
	t.Parallel()

	hashFunc := hashing_bip340.NewBip340HashChallenge
	curve := k256.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite := &integration.CipherSuite{
		Curve: curve,
		Hash:  hashFunc,
	}

	identities, err := integration_testutils.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	cohort, err := integration_testutils.MakeCohortProtocol(cipherSuite, protocols.LINDELL22, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(cohort, prng)
	require.NoError(t, err)
	publicKey := shards[identities[0].Hash()].SigningKeyShare.PublicKey

	transcripts := integration_testutils.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants, err := testutils.MakeParticipants(sid, cohort, identities[:th], shards, transcripts, true)
	require.NoError(t, err)

	partialSignatures, err := testutils.RunInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := interactive_signing.Aggregate(partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	bipSignature := &bip340.Signature{
		R: signature.R,
		S: signature.S,
	}

	err = bip340.Verify(&bip340.PublicKey{A: publicKey}, bipSignature, message)
	require.NoError(t, err)
}
