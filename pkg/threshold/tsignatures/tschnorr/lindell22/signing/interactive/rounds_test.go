package interactive_signing_test

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	ttu "github.com/copperexchange/krypton-primitives/pkg/base/types/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/hashing"
	hashing_bip340 "github.com/copperexchange/krypton-primitives/pkg/hashing/bip340"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/bip340"
	vanillaSchnorr "github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/zilliqa"
	jf_testutils "github.com/copperexchange/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/copperexchange/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/interactive/testutils"
)

func Test_SanityCheck(t *testing.T) {
	t.Parallel()

	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	suite, err := ttu.MakeSignatureProtocol(curve, hashFunc)
	require.NoError(t, err)
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

	e, err := curve.Scalar().SetBytesWide(bitstring.ReverseBytes(eBytes)) // SetBytesWide expects big endian across all curves and it internally reverses it.
	require.NoError(t, err)

	bigS := nonce.Add(e.Mul(schnorrPrivateKey))

	// verify native
	nativeSignature := append(bigR.ToAffineCompressed()[:], bitstring.ReverseBytes(bigS.Bytes())...)
	ok := nativeEddsa.Verify(publicKey.ToAffineCompressed(), message, nativeSignature)
	require.True(t, ok)

	// verify krypton
	kryptonSignature := schnorr.NewSignature(schnorr.NewEdDsaCompatibleVariant(), nil, bigR, bigS)
	kryptonPublicKey := &vanillaSchnorr.PublicKey{
		A: publicKey,
	}

	err = vanillaSchnorr.Verify(suite, kryptonPublicKey, message, kryptonSignature)
	require.NoError(t, err)
}

func Test_HappyPathThresholdEdDSA(t *testing.T) {
	t.Parallel()

	variant := schnorr.NewEdDsaCompatibleVariant()
	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	aliceShard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := aliceShard.SigningKeyShare.PublicKey

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants, err := testutils.MakeParticipants(sid, protocol, identities[:th], shards, transcripts, variant)
	require.NoError(t, err)

	partialSignatures, err := testutils.RunInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := signing.Aggregate(variant, partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = vanillaSchnorr.Verify(cipherSuite, &vanillaSchnorr.PublicKey{A: publicKey}, message, signature)
	require.NoError(t, err)
}

func Test_HappyPathThresholdBIP340(t *testing.T) {
	t.Parallel()

	variant := schnorr.NewTaprootVariant()
	hashFunc := hashing_bip340.NewBip340HashChallenge
	curve := k256.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	aliceShard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := aliceShard.SigningKeyShare.PublicKey

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants, err := testutils.MakeParticipants(sid, protocol, identities[:th], shards, transcripts, variant)
	require.NoError(t, err)

	partialSignatures, err := testutils.RunInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := signing.Aggregate(variant, partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = bip340.Verify(&bip340.PublicKey{A: publicKey}, signature, message)
	require.NoError(t, err)
}

func Test_HappyPathThresholdZilliqa(t *testing.T) {
	t.Parallel()

	variant := schnorr.NewZilliqaVariant()
	hashFunc := sha256.New
	curve := k256.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSignatureProtocol(curve, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	aliceShard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := aliceShard.SigningKeyShare.PublicKey

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants, err := testutils.MakeParticipants(sid, protocol, identities[:th], shards, transcripts, variant)
	require.NoError(t, err)

	partialSignatures, err := testutils.RunInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := signing.Aggregate(variant, partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = zilliqa.Verify(&zilliqa.PublicKey{A: publicKey}, signature, message)
	require.NoError(t, err)
}

func Test_HappyPathWithDkg(t *testing.T) {
	t.Parallel()

	variant := schnorr.NewEdDsaCompatibleVariant()
	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("testSessionId")

	signatureProtocol, err := ttu.MakeSignatureProtocol(curve, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(signatureProtocol, n)
	require.NoError(t, err)

	thresholdSignatureProtocol, err := ttu.MakeThresholdSignatureProtocol(signatureProtocol, identities, th, identities)
	require.NoError(t, err)

	signingKeyShares, partialPublicKeys, err := jf_testutils.RunDKG(sid, thresholdSignatureProtocol, identities)
	require.NoError(t, err)

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell22.Shard]()
	for i, id := range identities {
		shard, err := lindell22.NewShard(thresholdSignatureProtocol, signingKeyShares[i], partialPublicKeys[i])
		require.NoError(t, err)
		shards.Put(id, shard)
	}

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants, err := testutils.MakeParticipants(sid, thresholdSignatureProtocol, identities[:th], shards, transcripts, variant)
	require.NoError(t, err)

	partialSignatures, err := testutils.RunInteractiveSigning(participants, message)
	require.NoError(t, err)
	require.NotNil(t, partialSignatures)

	signature, err := signing.Aggregate(variant, partialSignatures...)
	require.NoError(t, err)
	require.NotNil(t, signature)

	publicKey := signingKeyShares[0].PublicKey
	err = vanillaSchnorr.Verify(signatureProtocol, &vanillaSchnorr.PublicKey{A: publicKey}, message, signature)
	require.NoError(t, err)
}
