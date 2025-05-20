package interactive_signing_test

import (
	crand "crypto/rand"
	"crypto/sha512"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	ttu "github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	hashing_bip340 "github.com/bronlabs/bron-crypto/pkg/hashing/bip340"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/bip340"
	vanillaSchnorr "github.com/bronlabs/bron-crypto/pkg/signatures/schnorr/vanilla"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/keygen/trusted_dealer"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/signing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/tschnorr/lindell22/signing/interactive/testutils"
)

func Test_SignWithDerivedShardBip32(t *testing.T) {
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

	parentShards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell22.ExtendedShard]()
	for id, parentShard := range parentShards.Iter() {
		derivedShard, err := parentShard.Derive(12345)
		require.NoError(t, err)
		require.False(t, derivedShard.PublicKey().Equal(parentShard.PublicKey()))
		shards.Put(id, derivedShard)
	}

	publicKeyShares := hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.PartialPublicKeys]()
	for identity, shard := range shards.Iter() {
		publicKeyShares.Put(identity, shard.Shard.PublicKeyShares)
	}
	alicePublicKeyShares, _ := publicKeyShares.Get(identities[0])

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants := testutils.MakeDerivedParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
	partialSignatures := testutils.RunInteractiveSigning(t, participants, message)
	require.NotNil(t, partialSignatures)

	partialSignaturesMap := hashmap.NewHashableHashMap[types.IdentityKey, *tschnorr.PartialSignature]()
	for i, partialSignature := range partialSignatures {
		partialSignaturesMap.Put(participants[i].IdentityKey(), partialSignature)
	}

	signature, err := signing.Aggregate(variant, protocol, message, alicePublicKeyShares, &schnorr.PublicKey{A: alicePublicKeyShares.PublicKey}, partialSignaturesMap)
	require.NoError(t, err)
	require.NotNil(t, signature)

	err = bip340.Verify(&bip340.PublicKey{A: alicePublicKeyShares.PublicKey}, signature, message)
	require.NoError(t, err)
}

func Test_SignWithDerivedShardGeneric(t *testing.T) {
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

	parentShards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)

	shards := hashmap.NewHashableHashMap[types.IdentityKey, *lindell22.ExtendedShard]()
	for id, parentShard := range parentShards.Iter() {
		derivedShard, err := parentShard.Derive(12345)
		require.NoError(t, err)
		require.False(t, derivedShard.PublicKey().Equal(parentShard.PublicKey()))
		shards.Put(id, derivedShard)
	}

	publicKeyShares := hashmap.NewHashableHashMap[types.IdentityKey, *tsignatures.PartialPublicKeys]()
	for identity, shard := range shards.Iter() {
		publicKeyShares.Put(identity, shard.Shard.PublicKeyShares)
	}
	alicePublicKeyShares, _ := publicKeyShares.Get(identities[0])

	transcripts := ttu.MakeTranscripts("Lindell 2022 Interactive Sign", identities)

	participants := testutils.MakeDerivedParticipants(t, sid, protocol, identities[:th], shards, transcripts, variant)
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
