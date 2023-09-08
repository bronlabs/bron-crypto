package bip340_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381"
	"github.com/copperexchange/knox-primitives/pkg/signatures/bls"
	test_utils2 "github.com/copperexchange/knox-primitives/pkg/signatures/bls/test_utils"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/signatures/schnorr/bip340"
)

type (
	G1 = *bls12381.PointG1
	G2 = *bls12381.PointG2
)

func Benchmark_Verify(b *testing.B) {
	//if testing.Short() {
	//	b.Skip("skipping benchmark in short mode.")
	//}
	batchSize := 10000
	curve := k256.New()

	aux := make([]byte, 32)
	_, err := crand.Read(aux)
	require.NoError(b, err)

	message := make([]byte, 32)
	_, err = crand.Read(message)
	privateKeys := make([]*bip340.PrivateKey, batchSize)
	messages := make([][]byte, batchSize)
	publicKeys := make([]*bip340.PublicKey, batchSize)
	signatures := make([]*bip340.Signature, batchSize)
	for i := 0; i < batchSize; i++ {

		privateKeys[i], err = bip340.NewPrivateKey(curve.Scalar().Random(crand.Reader))
		require.NoError(b, err)

		signer := bip340.NewSigner(privateKeys[i])

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

	blsPublicKeys := make([]*bls.PublicKey[G2], batchSize)
	blsSignatures := make([]*bls.Signature[G1], batchSize)
	pops := make([]*bls.ProofOfPossession[G1], batchSize)

	for i := 0; i < batchSize; i++ {
		privateKey, signature, pop, err := test_utils2.RoundTripWithKeysInG2(message, bls.POP)
		require.NoError(b, err)
		blsPublicKeys[i] = privateKey.PublicKey
		blsSignatures[i] = signature
		pops[i] = pop
	}

	b.Run("BLS FastAggregateVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			sigAg, err := bls.AggregateSignatures(blsSignatures...)
			require.NoError(b, err)
			require.NotNil(b, sigAg)
			require.False(b, sigAg.Value.IsIdentity())
			require.True(b, sigAg.Value.IsTorsionFree())
			err = bls.FastAggregateVerify(blsPublicKeys, message, sigAg, pops)
			require.NoError(b, err)
		}
	})
}
