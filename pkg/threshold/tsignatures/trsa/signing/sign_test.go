package signing_test

import (
	"crypto"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
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

	shards, err := trusted_dealer.Keygen(protocol, prng)
	require.NoError(t, err)
	shardValues := shards.Values()

	hashFunc := sha256.New
	message := []byte("hello world")

	partialSignatures := make([]*trsa.PartialSignature, total)
	for i, shard := range shardValues {
		var err error
		partialSignatures[i], err = signing.SignPSS(shard, message, hashFunc, 32)
		require.NoError(t, err)
	}

	signature, err := trsa.Aggregate(&shardValues[0].PublicShard, partialSignatures...)
	require.NoError(t, err)

	signatureBytes := make([]byte, (trsa.RsaBitLen+7)/8)
	signature.FillBytes(signatureBytes)
	digest, err := hashing.Hash(hashFunc, message)
	require.NoError(t, err)
	err = rsa.VerifyPSS(shardValues[0].PublicKey(), crypto.SHA256, digest, signatureBytes, &rsa.PSSOptions{SaltLength: 32})
	require.NoError(t, err)
}
