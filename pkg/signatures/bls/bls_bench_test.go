package bls_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/signatures/bls"
)

func Benchmark_TwoPartyManyMessageVerify_ShortKeys(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}
	batchSize := 1000

	alicePrivateKey, err := bls.KeyGen[bls.G1](crand.Reader)
	require.NoError(b, err)
	bobPrivateKey, err := bls.KeyGen[bls.G1](crand.Reader)
	require.NoError(b, err)

	alice, err := bls.NewSigner[bls.G1, bls.G2](alicePrivateKey, bls.Basic)
	require.NoError(b, err)

	bob, err := bls.NewSigner[bls.G1, bls.G2](bobPrivateKey, bls.Basic)
	require.NoError(b, err)

	aliceMessages := make([][]byte, batchSize)
	aliceSignatures := make([]*bls.Signature[bls.G2], batchSize)
	alicePKs := make([]*bls.PublicKey[bls.G1], batchSize)

	bobMessages := make([][]byte, batchSize)
	bobSignatures := make([]*bls.Signature[bls.G2], batchSize)
	bobPKs := make([]*bls.PublicKey[bls.G1], batchSize)

	for i := 0; i < batchSize; i++ {
		aliceMessages[i] = make([]byte, 32)
		_, err = crand.Read(aliceMessages[i])
		require.NoError(b, err)
		aliceSignatures[i], _, err = alice.Sign(aliceMessages[i], nil)
		require.NoError(b, err)

		bobMessages[i] = make([]byte, 32)
		_, err = crand.Read(bobMessages[i])
		require.NoError(b, err)
		bobSignatures[i], _, err = bob.Sign(bobMessages[i], nil)
		require.NoError(b, err)

		alicePKs[i] = alicePrivateKey.PublicKey
		bobPKs[i] = bobPrivateKey.PublicKey
	}

	b.Run("SingleVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for i := 0; i < batchSize; i++ {
				err := bls.Verify(alicePrivateKey.PublicKey, aliceSignatures[i], aliceMessages[i], nil, bls.Basic, nil)
				if err != nil {
					b.Fatal(err)
				}
				err = bls.Verify(bobPrivateKey.PublicKey, bobSignatures[i], bobMessages[i], nil, bls.Basic, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("BatchVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			aliceAggregateSignature, err := bls.AggregateSignatures(aliceSignatures...)
			require.NoError(b, err)

			err = bls.AggregateVerify(alicePKs, aliceMessages, aliceAggregateSignature, nil, bls.Basic, nil)
			if err != nil {
				b.Fatal(err)
			}

			bobAggregateSignature, err := bls.AggregateSignatures(bobSignatures...)
			require.NoError(b, err)

			err = bls.AggregateVerify(bobPKs, bobMessages, bobAggregateSignature, nil, bls.Basic, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

}
