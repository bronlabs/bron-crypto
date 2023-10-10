package bip340_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/signatures/schnorr/bip340"
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

func Benchmark_TwoPartyManyMessageVerify(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode.")
	}
	batchSize := 10000
	curve := k256.New()

	aux := make([]byte, 32)
	_, err := crand.Read(aux)
	require.NoError(b, err)

	alicePrivateKey, err := bip340.NewPrivateKey(curve.Scalar().Random(crand.Reader))
	require.NoError(b, err)
	alice := bip340.NewSigner(alicePrivateKey)

	bobPrivateKey, err := bip340.NewPrivateKey(curve.Scalar().Random(crand.Reader))
	require.NoError(b, err)
	bob := bip340.NewSigner(bobPrivateKey)

	aliceMessages := make([][]byte, batchSize)
	aliceSignatures := make([]*bip340.Signature, batchSize)
	alicePKs := make([]*bip340.PublicKey, batchSize)

	bobSignatures := make([]*bip340.Signature, batchSize)
	bobMessages := make([][]byte, batchSize)
	bobPKs := make([]*bip340.PublicKey, batchSize)

	for i := 0; i < batchSize; i++ {
		aliceMessages[i] = make([]byte, 32)
		_, err = crand.Read(aliceMessages[i])
		require.NoError(b, err)
		aliceSignatures[i], err = alice.Sign(aliceMessages[i], aux, nil)
		require.NoError(b, err)

		bobMessages[i] = make([]byte, 32)
		_, err = crand.Read(bobMessages[i])
		require.NoError(b, err)
		bobSignatures[i], err = bob.Sign(bobMessages[i], aux, nil)
		require.NoError(b, err)

		alicePKs[i] = &alicePrivateKey.PublicKey
		bobPKs[i] = &bobPrivateKey.PublicKey
	}

	b.Run("SingleVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			for i := 0; i < batchSize; i++ {
				err := bip340.Verify(&alicePrivateKey.PublicKey, aliceSignatures[i], aliceMessages[i])
				if err != nil {
					b.Fatal(err)
				}
				err = bip340.Verify(&bobPrivateKey.PublicKey, bobSignatures[i], bobMessages[i])
				if err != nil {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("BatchVerify", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			err := bip340.VerifyBatch(alicePKs, aliceSignatures, aliceMessages, crand.Reader)
			if err != nil {
				b.Fatal(err)
			}
			err = bip340.VerifyBatch(bobPKs, bobSignatures, bobMessages, crand.Reader)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
