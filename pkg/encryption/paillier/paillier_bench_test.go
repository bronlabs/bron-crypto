package paillier_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
	"github.com/bronlabs/bron-crypto/pkg/encryption/testutils"
)

func benchmarkEncrypting(b *testing.B, keyLen uint) {
	b.Helper()
	prng := pcg.NewRandomised()
	key, err := paillier.SampleSecretKey(keyLen, prng)
	require.NoError(b, err)
	plaintextValue, err := key.PlaintextGroup().Random(prng)
	require.NoError(b, err)
	plaintext, err := paillier.NewPlaintext(plaintextValue)
	require.NoError(b, err)

	b.Run(
		fmt.Sprintf("with encryption key with bit length %d", keyLen),
		testutils.EncryptingBenchmark(b, key.Public(), plaintext, prng),
	)

	b.Run(
		fmt.Sprintf("with self-encryption key with bit length %d", keyLen),
		testutils.EncryptingBenchmark(b, key, plaintext, prng),
	)
}

func benchmarkDecrypting(b *testing.B, keyLen uint) {
	b.Helper()
	prng := pcg.NewRandomised()
	key, err := paillier.SampleSecretKey(keyLen, prng)
	require.NoError(b, err)
	ciphertextValue, err := key.CiphertextGroup().Random(prng)
	require.NoError(b, err)
	ciphertext, err := paillier.NewCiphertextFromGroupElement(ciphertextValue)
	require.NoError(b, err)

	b.Run(
		fmt.Sprintf("with decryption key with bit length %d", keyLen),
		testutils.DecryptingBenchmark(b, key, ciphertext),
	)
}

func benchmarkManyEncryptions(b *testing.B, keyLen, count uint) {
	b.Helper()
	require.Greater(b, count, uint(1))
	prng := pcg.NewRandomised()

	key, err := paillier.SampleSecretKey(keyLen, prng)
	require.NoError(b, err)

	plaintexts := make([]*paillier.Plaintext, count)
	nonces := make([]*paillier.Nonce, count)

	for i := range count {
		plaintextValue, err := key.PlaintextGroup().Random(prng)
		require.NoError(b, err)
		plaintexts[i], err = paillier.NewPlaintext(plaintextValue)
		require.NoError(b, err)

		nonces[i], err = key.SampleNonce(prng)
		require.NoError(b, err)
	}

	b.Run(
		fmt.Sprintf("with encryption key with bit length %d and %d plaintexts", keyLen, count),
		testutils.ManyEncryptingBenchmark(b, key.Public(), plaintexts, nonces),
	)

	b.Run(
		fmt.Sprintf("with self-encryption key with bit length %d and %d plaintexts", keyLen, count),
		testutils.ManyEncryptingBenchmark(b, key, plaintexts, nonces),
	)
}

func benchmarkManyDecryptions(b *testing.B, keyLen, count uint) {
	b.Helper()
	require.Greater(b, count, uint(1))
	prng := pcg.NewRandomised()

	key, err := paillier.SampleSecretKey(keyLen, prng)
	require.NoError(b, err)

	ciphertexts := make([]*paillier.Ciphertext, count)
	for i := range count {
		ciphertextValue, err := key.CiphertextGroup().Random(prng)
		require.NoError(b, err)
		ciphertexts[i], err = paillier.NewCiphertextFromGroupElement(ciphertextValue)
		require.NoError(b, err)
	}

	b.Run(
		fmt.Sprintf("with decryption key with bit length %d and %d ciphertexts", keyLen, count),
		testutils.ManyDecryptingBenchmark(b, key, ciphertexts),
	)
}

func BenchmarkKeyGeneration(b *testing.B) {
	prng := pcg.NewRandomised()
	for _, keyLen := range []uint{256, 1024, 2048} {
		testutils.KeyLenBasedKeyGen(b, keyLen, "Normal", paillier.SampleSecretKey, "PCG", prng)
		testutils.KeyLenBasedKeyGen(b, keyLen, "PaillierBlum", paillier.SampleBlumSecretKey, "PCG", prng)
		testutils.KeyLenBasedKeyGen(b, keyLen, "Safe", paillier.SampleSafeSecretKey, "PCG", prng)
	}
}

func BenchmarkEncrypting(b *testing.B) {
	for _, keyLen := range []uint{256, 512, 1024, 2048} {
		benchmarkEncrypting(b, keyLen)
	}
}

func BenchmarkDecrypting(b *testing.B) {
	for _, keyLen := range []uint{256, 512, 1024, 2048} {
		benchmarkDecrypting(b, keyLen)
	}
}

func BenchmarkManyEncryptions(b *testing.B) {
	for _, keyLen := range []uint{256, 1024, 2048} {
		for _, count := range []uint{2, 64, 128, 256} {
			benchmarkManyEncryptions(b, keyLen, count)
		}
	}
}

func BenchmarkManyDecryptions(b *testing.B) {
	for _, keyLen := range []uint{256, 1024, 2048} {
		for _, count := range []uint{2, 64, 128, 256} {
			benchmarkManyDecryptions(b, keyLen, count)
		}
	}
}
