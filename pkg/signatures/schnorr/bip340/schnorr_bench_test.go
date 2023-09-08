package bip340_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr/bip340"
)

func Benchmark_Verify(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}
	batchSize := 10000
	curve := k256.New()

	aux := make([]byte, 32)
	_, err := crand.Read(aux)
	require.NoError(b, err)

	privateKeys := make([]*bip340.PrivateKey, batchSize)
	messages := make([][]byte, batchSize)
	publicKeys := make([]*bip340.PublicKey, batchSize)
	signatures := make([]*bip340.Signature, batchSize)
	for i := 0; i < batchSize; i++ {

		privateKeys[i], err = bip340.NewPrivateKey(curve.Scalar().Random(crand.Reader))
		require.NoError(b, err)

		signer := bip340.NewSigner(privateKeys[i])

		message := make([]byte, 32)
		_, err = crand.Read(message)
		require.NoError(b, err)

		signature, err := signer.Sign(message, aux, nil)
		require.NoError(b, err)

		messages[i] = message
		publicKeys[i] = &privateKeys[i].PublicKey
		signatures[i] = signature
	}

	b.Run("SingleVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for i := 0; i < batchSize; i++ {
				err := bip340.Verify(publicKeys[i], signatures[i], messages[i])
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("BatchVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err := bip340.VerifyBatch(publicKeys, signatures, messages, crand.Reader)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
