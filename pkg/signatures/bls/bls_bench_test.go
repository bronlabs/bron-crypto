package bls_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/signatures/bls"
)

func Benchmark_TwoPartyManyMessageAggregateVerify_ShortKeys(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}
	batchSize := 1000

	alicePrivateKey, err := bls.KeyGen[bls12381.G1](crand.Reader)
	require.NoError(b, err)
	bobPrivateKey, err := bls.KeyGen[bls12381.G1](crand.Reader)
	require.NoError(b, err)

	alice, err := bls.NewSigner[bls12381.G1, bls12381.G2](alicePrivateKey, bls.Basic)
	require.NoError(b, err)

	bob, err := bls.NewSigner[bls12381.G1, bls12381.G2](bobPrivateKey, bls.Basic)
	require.NoError(b, err)

	aliceMessages := make([][]byte, batchSize)
	aliceSignatures := make([]*bls.Signature[bls12381.G2], batchSize)
	alicePKs := make([]*bls.PublicKey[bls12381.G1], batchSize)

	bobMessages := make([][]byte, batchSize)
	bobSignatures := make([]*bls.Signature[bls12381.G2], batchSize)
	bobPKs := make([]*bls.PublicKey[bls12381.G1], batchSize)

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

	aliceAggregateSignature, err := bls.AggregateSignatures(aliceSignatures...)
	require.NoError(b, err)
	bobAggregateSignature, err := bls.AggregateSignatures(bobSignatures...)
	require.NoError(b, err)

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

	b.Run("AggregateVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err = bls.AggregateVerify(alicePKs, aliceMessages, aliceAggregateSignature, nil, bls.Basic, nil)
			if err != nil {
				b.Fatal(err)
			}

			err = bls.AggregateVerify(bobPKs, bobMessages, bobAggregateSignature, nil, bls.Basic, nil)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

func Benchmark_ManyPartyBatchVerify_ShortKeys(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}
	batchSize := 100
	scheme := bls.Basic

	publicKeys := make([]*bls.PublicKey[bls12381.G1], batchSize)
	people := make([]*bls.Signer[bls12381.G1, bls12381.G2], batchSize)
	messages := make([][]byte, batchSize)
	signatures := make([]*bls.Signature[bls12381.G2], batchSize)
	schemes := make([]bls.RogueKeyPrevention, batchSize)
	for i := 0; i < batchSize; i++ {
		privateKey, err := bls.KeyGen[bls12381.G1](crand.Reader)
		require.NoError(b, err)
		publicKeys[i] = privateKey.PublicKey
		people[i], err = bls.NewSigner[bls12381.G1, bls12381.G2](privateKey, scheme)
		require.NoError(b, err)
		messages[i] = []byte(fmt.Sprintf("%d_%x", i, privateKey.PublicKey.Y.ToAffineCompressed()))
		signatures[i], _, err = people[i].Sign(messages[i], nil)
		require.NoError(b, err)
		schemes[i] = scheme
	}

	b.Run("SingleVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for i := 0; i < batchSize; i++ {
				err := bls.Verify(publicKeys[i], signatures[i], messages[i], nil, bls.Basic, nil)
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("BatchVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err := bls.BatchVerify(publicKeys, messages, signatures, nil, schemes, nil, crand.Reader)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
