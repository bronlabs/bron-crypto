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
	"github.com/bronlabs/bron-crypto/pkg/hashing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/signing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/tsignatures/trsa/trusted_dealer"
)

const (
	threshold = 2
	total     = 3
)

func Test_SignPSSHappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, threshold)
	require.NoError(t, err)

	publicKey, shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	shardValues := shards.Values()
	shardValues = testutils.JsonRoundTrip(t, shardValues)

	cryptoHash := crypto.SHA256

	cosigners := make([]*signing.Cosigner, total)
	for i, id := range identities {
		shard, exists := shards.Get(id)
		require.True(t, exists)
		shard = testutils.JsonRoundTrip(t, shard)

		cosigners[i], err = signing.NewCosigner(id.(types.AuthKey), shard, protocol, protocol.Participants(), cryptoHash)
		require.NoError(t, err)
	}

	message := []byte("hello world")
	salt := []byte{}
	partialSignatures := make([]*trsa.PartialSignature, len(cosigners))
	for i, cosigner := range cosigners {
		partialSignatures[i], err = cosigner.ProducePSSPartialSignature(message, salt)
		require.NoError(t, err)
	}

	signature, err := signing.AggregateSignature(&shardValues[0].PublicShard, partialSignatures...)
	require.NoError(t, err)

	signatureBytes := make([]byte, (trsa.RsaBitLen+7)/8)
	signature.FillBytes(signatureBytes)
	digest, err := hashing.Hash(cryptoHash.New, message)
	require.NoError(t, err)
	err = rsa.VerifyPSS(publicKey, cryptoHash, digest, signatureBytes, &rsa.PSSOptions{SaltLength: len(salt)})
	require.NoError(t, err)
}

func Test_SignPKCS1v15HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader

	identities, err := testutils.MakeDeterministicTestIdentities(total)
	require.NoError(t, err)

	protocol, err := testutils.MakeThresholdProtocol(k256.NewCurve(), identities, threshold)
	require.NoError(t, err)

	publicKey, shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	shardValues := shards.Values()
	shardValues = testutils.JsonRoundTrip(t, shardValues)

	cryptoHash := crypto.SHA256
	cosigners := make([]*signing.Cosigner, total)
	for i, id := range identities {
		shard, exists := shards.Get(id)
		require.True(t, exists)
		shard = testutils.JsonRoundTrip(t, shard)
		cosigners[i], err = signing.NewCosigner(id.(types.AuthKey), shard, protocol, protocol.Participants(), cryptoHash)
		require.NoError(t, err)
	}

	message := []byte("hello world")
	partialSignatures := make([]*trsa.PartialSignature, len(cosigners))
	for i, cosigner := range cosigners {
		partialSignatures[i], err = cosigner.ProducePKCS1v15PartialSignature(message)
		require.NoError(t, err)
	}

	signature, err := signing.AggregateSignature(&shardValues[0].PublicShard, partialSignatures...)
	require.NoError(t, err)

	signatureBytes := make([]byte, (trsa.RsaBitLen+7)/8)
	signature.FillBytes(signatureBytes)
	digest, err := hashing.Hash(cryptoHash.New, message)
	require.NoError(t, err)
	err = rsa.VerifyPKCS1v15(publicKey, cryptoHash, digest, signatureBytes)
	require.NoError(t, err)
}
