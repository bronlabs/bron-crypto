package interactive_signing_test

import (
	nativeEddsa "crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pallas"
	"github.com/bronlabs/krypton-primitives/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	ttu "github.com/bronlabs/krypton-primitives/pkg/base/types/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/hashing"
	hashing_bip340 "github.com/bronlabs/krypton-primitives/pkg/hashing/bip340"
	"github.com/bronlabs/krypton-primitives/pkg/hashing/poseidon"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/bip340"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/mina"
	vanillaSchnorr "github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/vanilla"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/schnorr/zilliqa"
	jf_testutils "github.com/bronlabs/krypton-primitives/pkg/threshold/dkg/jf/testutils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/tsignatures/tschnorr/lindell22/signing/interactive/testutils"
)

func Test_SanityCheck(t *testing.T) {
	t.Parallel()

	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	suite, err := ttu.MakeSigningSuite(curve, hashFunc)
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
	kryptonSignature := schnorr.NewSignature(vanillaSchnorr.NewEdDsaCompatibleVariant(), nil, bigR, bigS)
	kryptonPublicKey := &vanillaSchnorr.PublicKey{
		A: publicKey,
	}

	err = vanillaSchnorr.Verify(suite, kryptonPublicKey, message, kryptonSignature)
	require.NoError(t, err)
}

func Test_HappyPathThresholdEdDSA(t *testing.T) {
	t.Parallel()

	variant := vanillaSchnorr.NewEdDsaCompatibleVariant()
	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)

	publicKeyShares := hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.PartialPublicKeys]()
	for identity, shard := range shards.Iter() {
		publicKeyShares.Put(identity, shard.PublicKeyShares)
	}
	alicePublicKeyShares, _ := publicKeyShares.Get(identities[0])

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, alicePublicKeyShares, &schnorr.PublicKey{A: alicePublicKeyShares.PublicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = vanillaSchnorr.Verify(cipherSuite, &vanillaSchnorr.PublicKey{A: alicePublicKeyShares.PublicKey}, message, signature)
	require.NoError(t, err)
}

func Test_HappyPathThresholdBIP340(t *testing.T) {
	t.Parallel()

	variant := bip340.NewTaprootVariant()
	hashFunc := hashing_bip340.NewBip340HashChallenge
	curve := k256.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
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
	var publicKeyShares *tsignatures.PartialPublicKeys
	for _, shard := range shards.Iter() {
		publicKeyShares = shard.PublicKeyShares
		break
	}

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)
	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, publicKeyShares, &schnorr.PublicKey{A: publicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = bip340.Verify(&bip340.PublicKey{A: publicKey}, signature, message)
	require.NoError(t, err)
}

func Test_HappyPathThresholdMina(t *testing.T) {
	t.Parallel()

	networkId := mina.TestNet
	variant := mina.NewMinaVariant(networkId)
	hashFunc := poseidon.NewLegacyHash
	identitiesHashFunc := sha256.New
	curve := pallas.NewCurve()
	prng := crand.Reader
	message := new(mina.ROInput).Init()
	message.AddString("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	identityCipherSuite, err := ttu.MakeSigningSuite(curve, identitiesHashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(identityCipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	aliceShard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := aliceShard.SigningKeyShare.PublicKey
	var publicKeyShares *tsignatures.PartialPublicKeys
	for _, shard := range shards.Iter() {
		publicKeyShares = shard.PublicKeyShares
		break
	}

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)
	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, publicKeyShares, &schnorr.PublicKey{A: publicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = mina.Verify(&mina.PublicKey{A: publicKey}, signature, message, networkId)
	require.NoError(t, err)

}

func Test_ThresholdMinaAgainstMinaSigner(t *testing.T) {
	t.Parallel()

	msg := "Hello World!"
	networkId := mina.TestNet
	variant := mina.NewMinaVariant(networkId)
	hashFunc := poseidon.NewLegacyHash
	identitiesHashFunc := sha256.New
	curve := pallas.NewCurve()
	prng := crand.Reader
	message := new(mina.ROInput).Init()
	message.AddString(msg)
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	identityCipherSuite, err := ttu.MakeSigningSuite(curve, identitiesHashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(identityCipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	aliceShard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := aliceShard.SigningKeyShare.PublicKey
	var publicKeyShares *tsignatures.PartialPublicKeys
	for _, shard := range shards.Iter() {
		publicKeyShares = shard.PublicKeyShares
		break
	}

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)
	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, publicKeyShares, &schnorr.PublicKey{A: publicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = mina.Verify(&mina.PublicKey{A: publicKey}, signature, message, networkId)
	require.NoError(t, err)

	// spit out data, so it can be verified with mina signer
	println("r", signature.R.AffineX().Nat().Big().Text(10))
	println("s", signature.S.Nat().Big().Text(10))
	println("fields: []")
	bitsStr := "["
	for _, byte := range []byte(msg) {
		for i := 0; i < 8; i++ {
			bit := (byte & (1 << (7 - i))) != 0
			bStr := "false,"
			if bit {
				bStr = "true,"
			}
			bitsStr = bitsStr + bStr
		}
	}
	bitsStr = bitsStr + "]"
	println("bits", bitsStr)
	println("x", publicKey.AffineX().Nat().Big().Text(10))
	println("isOdd", publicKey.AffineY().IsOdd())
}

func Test_HappyPathThresholdZilliqa(t *testing.T) {
	t.Parallel()

	variant := zilliqa.NewZilliqaVariant()
	hashFunc := sha256.New
	curve := k256.NewCurve()
	prng := crand.Reader
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("sessionId")

	cipherSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(cipherSuite, n)
	require.NoError(t, err)

	protocol, err := ttu.MakeThresholdSignatureProtocol(cipherSuite, identities, th, identities)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)

	var publicKeyShares *tsignatures.PartialPublicKeys
	for _, shard := range shards.Iter() {
		publicKeyShares = shard.PublicKeyShares
		break
	}

	aliceShard, exists := shards.Get(identities[0])
	require.True(t, exists)
	publicKey := aliceShard.SigningKeyShare.PublicKey

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)
	participants := testutils.MakeParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, publicKeyShares, &schnorr.PublicKey{A: publicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = zilliqa.Verify(&zilliqa.PublicKey{A: publicKey}, signature, message)
	require.NoError(t, err)
}

func Test_HappyPathWithDkg(t *testing.T) {
	t.Parallel()

	variant := vanillaSchnorr.NewEdDsaCompatibleVariant()
	hashFunc := sha512.New
	curve := edwards25519.NewCurve()
	message := []byte("Hello World!")
	th := 2
	n := 3
	sid := []byte("testSessionId")

	signingSuite, err := ttu.MakeSigningSuite(curve, hashFunc)
	require.NoError(t, err)

	identities, err := ttu.MakeTestIdentities(signingSuite, n)
	require.NoError(t, err)

	thresholdSignatureProtocol, err := ttu.MakeThresholdSignatureProtocol(signingSuite, identities, th, identities)
	require.NoError(t, err)

	signingKeyShares, partialPublicKeys := jf_testutils.DoDkgHappyPath(t, sid, thresholdSignatureProtocol, identities)

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell22.Shard]()
	for i, id := range identities {
		shard, err := lindell22.NewShard(thresholdSignatureProtocol, signingKeyShares[i], partialPublicKeys[i])
		require.NoError(t, err)
		shards.Put(id, shard)
	}

	var publicKeyShares *tsignatures.PartialPublicKeys
	for _, shard := range shards.Iter() {
		publicKeyShares = shard.PublicKeyShares
		break
	}

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)
	participants := testutils.MakeParticipants(t, sid, thresholdSignatureProtocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	publicKey := &vanillaSchnorr.PublicKey{A: signingKeyShares[0].PublicKey}
	signature, err := signing.Aggregate(variant, thresholdSignatureProtocol, message, publicKeyShares, (*schnorr.PublicKey)(publicKey), partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = vanillaSchnorr.Verify(signingSuite, publicKey, message, signature)
	require.NoError(t, err)
}
