package interactive_signing_test

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	hashing_bip340 "github.com/bronlabs/bron-crypto/pkg/hashing/bip340"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/bip340"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/mina"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/zilliqa"
	"golang.org/x/crypto/blake2b"
	"hash"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	vanillaSchnorr "github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/vanilla"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/signing/interactive/testutils"
)

func Test_SanityCheck(t *testing.T) {
	t.Parallel()

	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	prng := crand.Reader

	message := []byte("Hello World!")

	eddsaPrivateKey, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	dHashed, err := hashing.Hash(hashFunc, eddsaPrivateKey.Bytes())
	require.NoError(t, err)

	schnorrPrivateKeyBytes := dHashed[:32]
	schnorrPrivateKey, err := curve.ScalarField().FromWideBytes(schnorrPrivateKeyBytes)
	require.NoError(t, err)
	publicKey := curve.Generator().ScalarMul(schnorrPrivateKey)

	nonce, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	bigR := curve.Generator().ScalarMul(nonce)

	eBytes, err := hashing.Hash(hashFunc, bigR.ToAffineCompressed(), publicKey.ToAffineCompressed(), message)
	require.NoError(t, err)

	e, err := curve.ScalarField().FromWideBytes(sliceutils.Reversed(eBytes)) // SetBytesWide expects big endian across all curves and it internally reverses it.
	require.NoError(t, err)

	bigS := nonce.Add(e.Mul(schnorrPrivateKey))

	// verify native
	nativeSignature := append(bigR.ToAffineCompressed()[:], sliceutils.Reverse(bigS.Bytes())...)
	ok := nativeEddsa.Verify(publicKey.ToAffineCompressed(), message, nativeSignature)
	require.True(t, ok)

	// verify krypton
	bronSignature := schnorr.NewSignature(vanillaSchnorr.NewEdDsaCompatibleVariant[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar](), nil, bigR, bigS)
	bronPublicKey := &vanillaSchnorr.PublicKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar]{
		A: publicKey,
	}

	err = vanillaSchnorr.Verify(hashFunc, bronPublicKey, message, bronSignature)
	require.NoError(t, err)
}

func Test_HappyPathThresholdGeneric(t *testing.T) {
	t.Parallel()

	curve := bls12381.NewG1Curve()
	hashFunc := func() hash.Hash { h, err := blake2b.New256(nil); require.NoError(t, err); return h }
	testHappyPathThresholdGeneric(t, 2, 3, curve, hashFunc)
}

func Test_HappyPathThresholdEdDSA(t *testing.T) {
	t.Parallel()

	testHappyPathThresholdEdDSA(t, 2, 3)
}

func Test_HappyPathThresholdBIP340(t *testing.T) {
	t.Parallel()

	testHappyPathThresholdBIP340(t, 2, 3)
}

func Test_HappyPathThresholdMina(t *testing.T) {
	t.Parallel()

	testHappyPathThresholdMina(t, 2, 3)
}

func Test_HappyPathThresholdZilliqa(t *testing.T) {
	t.Parallel()

	testHappyPathThresholdZilliqa(t, 2, 3)
}

func testHappyPathThresholdGeneric[C curves.Curve[P, F, S], P curves.Point[P, F, S], F fields.FiniteFieldElement[F], S fields.PrimeFieldElement[S]](t *testing.T, th, n uint, curve C, hashFunc func() hash.Hash) {
	t.Helper()

	variant := vanillaSchnorr.NewEdDsaCompatibleVariant[P, F, S]()
	prng := crand.Reader
	message := []byte("Hello World!")
	sid := []byte("sessionId")

	identities := ttu.MakeTestIdentities(t, n)
	protocol := ttu.MakeThresholdSignatureProtocol(t, curve, hashFunc, th, identities...)
	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)

	publicKeyShares := hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.PartialPublicKeys[C, P, F, S]]()
	for identity, shard := range shards.Iter() {
		publicKeyShares.Put(identity, shard.PublicKeyShares)
	}
	alicePublicKeyShares, _ := publicKeyShares.Get(identities[0])

	transcripts := ttu.MakeTranscripts(t, "Lindell 2022 Interactive Sign", identities)

	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature[P, F, S]]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, alicePublicKeyShares, &schnorr.PublicKey[P, F, S]{A: alicePublicKeyShares.PublicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = vanillaSchnorr.Verify(hashFunc, &vanillaSchnorr.PublicKey[P, F, S]{A: alicePublicKeyShares.PublicKey}, message, signature)
	require.NoError(t, err)
}

func testHappyPathThresholdEdDSA(t *testing.T, th, n uint) {
	t.Helper()

	variant := vanillaSchnorr.NewEdDsaCompatibleVariant[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar]()
	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	sid := []byte("sessionId")

	identities := ttu.MakeTestIdentities(t, n)
	protocol := ttu.MakeThresholdSignatureProtocol(t, curve, hashFunc, th, identities...)
	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)

	publicKeyShares := hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.PartialPublicKeys[*edwards25519.Curve, *edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar]]()
	for identity, shard := range shards.Iter() {
		publicKeyShares.Put(identity, shard.PublicKeyShares)
	}
	alicePublicKeyShares, _ := publicKeyShares.Get(identities[0])

	transcripts := ttu.MakeTranscripts(t, "Lindell 2022 Interactive Sign", identities)

	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar]]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, alicePublicKeyShares, &schnorr.PublicKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar]{A: alicePublicKeyShares.PublicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = vanillaSchnorr.Verify(hashFunc, &vanillaSchnorr.PublicKey[*edwards25519.Point, *edwards25519.BaseFieldElement, *edwards25519.Scalar]{A: alicePublicKeyShares.PublicKey}, message, signature)
	require.NoError(t, err)
}

func testHappyPathThresholdBIP340(t *testing.T, th, n uint) {
	t.Helper()

	variant := bip340.NewTaprootVariant()
	hashFunc := hashing_bip340.NewBip340HashChallenge
	curve := k256.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	sid := []byte("sessionId")

	identities := ttu.MakeTestIdentities(t, n)
	protocol := ttu.MakeThresholdSignatureProtocol(t, curve, hashFunc, th, identities...)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	aliceShard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := aliceShard.SigningKeyShare.PublicKey
	var publicKeyShares *tsignatures.PartialPublicKeys[*k256.Curve, *k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	for _, shard := range shards.Iter() {
		publicKeyShares = shard.PublicKeyShares
		break
	}

	transcripts := ttu.MakeTranscripts(t, "Lindell 2022 Interactive Sign", identities)
	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, publicKeyShares, &schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]{A: publicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = bip340.Verify(&bip340.PublicKey{A: publicKey}, signature, message)
	require.NoError(t, err)
}

func testHappyPathThresholdMina(t *testing.T, th, n uint) {
	t.Helper()

	networkId := mina.TestNet
	variant := mina.NewMinaVariant(networkId)
	hashFunc := poseidon.NewLegacyHash
	curve := pasta.NewPallasCurve()
	prng := crand.Reader
	message := new(mina.ROInput).Init()
	message.AddString("Hello World!")
	sid := []byte("sessionId")

	identities := ttu.MakeTestIdentities(t, n)
	protocol := ttu.MakeThresholdSignatureProtocol(t, curve, hashFunc, th, identities...)
	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	aliceShard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := aliceShard.SigningKeyShare.PublicKey
	var publicKeyShares *tsignatures.PartialPublicKeys[*pasta.PallasCurve, *pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar]
	for _, shard := range shards.Iter() {
		publicKeyShares = shard.PublicKeyShares
		break
	}

	transcripts := ttu.MakeTranscripts(t, "Lindell 2022 Interactive Sign", identities)
	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature[*pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar]]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, publicKeyShares, &schnorr.PublicKey[*pasta.PallasPoint, *pasta.PallasBaseFieldElement, *pasta.PallasScalar]{A: publicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = mina.Verify(&mina.PublicKey{A: publicKey}, signature, message, networkId)
	require.NoError(t, err)
}

func testHappyPathThresholdZilliqa(t *testing.T, th, n uint) {
	t.Helper()

	variant := zilliqa.NewZilliqaVariant()
	hashFunc := sha256.New
	curve := k256.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	sid := []byte("sessionId")

	identities := ttu.MakeTestIdentities(t, n)
	protocol := ttu.MakeThresholdSignatureProtocol(t, curve, hashFunc, th, identities...)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)

	var publicKeyShares *tsignatures.PartialPublicKeys[*k256.Curve, *k256.Point, *k256.BaseFieldElement, *k256.Scalar]
	for _, shard := range shards.Iter() {
		publicKeyShares = shard.PublicKeyShares
		break
	}

	aliceShard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := aliceShard.SigningKeyShare.PublicKey

	transcripts := ttu.MakeTranscripts(t, "Lindell 2022 Interactive Sign", identities)
	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, publicKeyShares, &schnorr.PublicKey[*k256.Point, *k256.BaseFieldElement, *k256.Scalar]{A: publicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = zilliqa.Verify(&zilliqa.PublicKey{A: publicKey}, signature, message)
	require.NoError(t, err)
}
