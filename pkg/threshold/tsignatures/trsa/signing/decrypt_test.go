package signing_test

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/types"
	"github.com/bronlabs/bron-crypto/pkg/base/types/testutils"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/signing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/trusted_dealer"
)

func Test_DecryptPKCS1v15HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, threshold)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	pk := &testutils.JsonRoundTrip(t, shards.Values()[0]).PublicShard

	plaintext := []byte("hello world")
	ciphertext, err := rsa.EncryptPKCS1v15(prng, pk.PublicKey(), plaintext)
	require.NoError(t, err)

	cryptoHash := crypto.SHA256
	cosigners := make([]*signing.Cosigner, total)
	for i, id := range identities {
		shard, exists := shards.Get(id)
		require.True(t, exists)
		shard = testutils.JsonRoundTrip(t, shard)
		cosigners[i], err = signing.NewCosigner(id.(types.AuthKey), shard, protocol, protocol.Participants(), cryptoHash)
		require.NoError(t, err)
	}

	partialDecryptions := make([]*trsa.PartialDecryption, len(cosigners))
	for i, cosigner := range cosigners {
		partialDecryptions[i] = cosigner.ProducePartialDecryption(ciphertext)
	}

	decrypted, err := signing.AggregatePKCS1v15Decryption(pk, partialDecryptions...)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func Test_DecryptOAEPHappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, threshold)
	require.NoError(t, err)

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	pk := &testutils.JsonRoundTrip(t, shards.Values()[0]).PublicShard

	cryptoHash := crypto.SHA256
	plaintext := []byte("hello world")
	label := []byte("test")
	ciphertext, err := rsa.EncryptOAEP(cryptoHash.New(), prng, pk.PublicKey(), plaintext, label)
	require.NoError(t, err)

	cosigners := make([]*signing.Cosigner, total)
	for i, id := range identities {
		shard, exists := shards.Get(id)
		require.True(t, exists)
		shard = testutils.JsonRoundTrip(t, shard)
		cosigners[i], err = signing.NewCosigner(id.(types.AuthKey), shard, protocol, protocol.Participants(), cryptoHash)
		require.NoError(t, err)
	}

	partialDecryptions := make([]*trsa.PartialDecryption, len(cosigners))
	for i, cosigner := range cosigners {
		partialDecryptions[i] = cosigner.ProducePartialDecryption(ciphertext)
	}

	decrypted, err := signing.AggregateOAEPDecryption(pk, cryptoHash, label, partialDecryptions...)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}
