package testutils

import (
	"fmt"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/encryption"
	"github.com/stretchr/testify/require"
)

func EncryptingBenchmark[
	P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C],
](b *testing.B, key TypeErasedEncryptionKey[P, N, C], plaintext P, prng io.Reader) func(*testing.B) {
	b.Helper()
	require.NotNil(b, key)
	require.NotNil(b, plaintext)
	require.NotNil(b, prng)
	return func(b *testing.B) {
		b.Helper()
		nonce, err := key.SampleNonce(prng)
		require.NoError(b, err)
		for b.Loop() {
			_, err := key.EncryptWithNonce(plaintext, nonce)
			require.NoError(b, err)
		}
	}
}

func DecryptingBenchmark[
	DK encryption.DecryptionKey[EK, DK, P, N, C], EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C],
](b *testing.B, key DK, ciphertext C) func(*testing.B) {
	b.Helper()
	require.NotNil(b, key)
	require.NotNil(b, ciphertext)
	return func(b *testing.B) {
		b.Helper()
		for b.Loop() {
			_, err := key.Decrypt(ciphertext)
			require.NoError(b, err)
		}
	}
}

func ManyEncryptingBenchmark[
	P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C],
](b *testing.B, key TypeErasedEncryptionKey[P, N, C], plaintexts []P, nonces []N) func(*testing.B) {
	b.Helper()
	require.NotNil(b, key)
	require.NotNil(b, plaintexts)
	require.NotNil(b, nonces)
	return func(b *testing.B) {
		b.Helper()
		b.Run("parallel encryptions", func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				_, err := encryption.EncryptManyWithNonces(plaintexts, key, nonces)
				require.NoError(b, err)
			}
		})
		b.Run("serial encryptions", func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				for i, p := range plaintexts {
					_, err := key.EncryptWithNonce(p, nonces[i])
					require.NoError(b, err)
				}
			}
		})
	}
}

func ManyDecryptingBenchmark[
	DK encryption.DecryptionKey[EK, DK, P, N, C], EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C],
](b *testing.B, key DK, ciphertexts []C) func(*testing.B) {
	b.Helper()
	require.NotNil(b, key)
	require.NotNil(b, ciphertexts)
	return func(b *testing.B) {
		b.Helper()
		b.Run("parallel decryptions", func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				_, err := encryption.DecryptMany(ciphertexts, key)
				require.NoError(b, err)
			}
		})
		b.Run("serial decryptions", func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				for _, c := range ciphertexts {
					_, err := key.Decrypt(c)
					require.NoError(b, err)
				}
			}
		})
	}
}

func KeyLenBasedKeyGen[
	DK encryption.DecryptionKey[EK, DK, P, N, C], EK encryption.EncryptionKey[EK, P, N, C], P encryption.Plaintext, N encryption.Nonce, C encryption.Ciphertext[C],
](b *testing.B, keyLen uint, samplerName string, sampler func(keyLen uint, prng io.Reader) (DK, error), prngName string, prng io.Reader) {
	b.Helper()
	b.Run(
		fmt.Sprintf("with %s sampler and %s PRNG for key length %d", samplerName, prngName, keyLen),
		func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				_, err := sampler(keyLen, prng)
				require.NoError(b, err)
			}
		},
	)
}
