package elgamal_test

import (
	"fmt"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
	"github.com/bronlabs/bron-crypto/pkg/encryption/testutils"
	"github.com/stretchr/testify/require"
)

func benchmarkEncrypting[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](
	b *testing.B, group elgamal.FiniteCyclicGroup[E, S],
) {
	b.Helper()
	require.NotNil(b, group)
	prng := pcg.NewRandomised()
	key, err := elgamal.SampleSecretKey(group, prng)
	require.NoError(b, err)
	plaintextValue, err := key.PlaintextGroup().Random(prng)
	require.NoError(b, err)
	plaintext, err := elgamal.NewPlaintext(plaintextValue)
	require.NoError(b, err)

	b.Run(
		fmt.Sprintf("with encryption key with group %s", group.Name()),
		testutils.EncryptingBenchmark(b, key.Public(), plaintext, prng),
	)
	b.Run(
		fmt.Sprintf("with self-encryption key with group %s", group.Name()),
		testutils.EncryptingBenchmark(b, key, plaintext, prng),
	)
}

func benchmarkDecrypting[E elgamal.FiniteCyclicGroupElement[E, S], S algebra.UintLike[S]](
	b *testing.B, group elgamal.FiniteCyclicGroup[E, S],
) {
	b.Helper()
	require.NotNil(b, group)
	prng := pcg.NewRandomised()
	key, err := elgamal.SampleSecretKey(group, prng)
	require.NoError(b, err)
	ciphertextValue, err := key.CiphertextGroup().Random(prng)
	require.NoError(b, err)
	ciphertext, err := elgamal.NewCiphertextFromGroupElement(ciphertextValue)
	require.NoError(b, err)

	b.Run(
		fmt.Sprintf("with decryption key with group %s", group.Name()),
		testutils.DecryptingBenchmark(b, key, ciphertext),
	)
}

func BenchmarkKeyGeneration(b *testing.B) {
	prng := pcg.NewRandomised()
	b.Run(
		"with k256 curve",
		func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				_, err := elgamal.SampleSecretKey(k256.NewCurve(), prng)
				require.NoError(b, err)
			}
		},
	)
	b.Run(
		"with p256 curve",
		func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				_, err := elgamal.SampleSecretKey(p256.NewCurve(), prng)
				require.NoError(b, err)
			}
		},
	)
	b.Run(
		"with edwards25519 curve",
		func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				_, err := elgamal.SampleSecretKey(edwards25519.NewPrimeSubGroup(), prng)
				require.NoError(b, err)
			}
		},
	)
	b.Run(
		"with bls12381-G1 curve",
		func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				_, err := elgamal.SampleSecretKey(bls12381.NewG1(), prng)
				require.NoError(b, err)
			}
		},
	)
	b.Run(
		"with bls12381-G2 curve",
		func(b *testing.B) {
			b.Helper()
			for b.Loop() {
				_, err := elgamal.SampleSecretKey(bls12381.NewG2(), prng)
				require.NoError(b, err)
			}
		},
	)
}

func BenchmarkEncrypting(b *testing.B) {
	benchmarkEncrypting(b, k256.NewCurve())
	benchmarkEncrypting(b, p256.NewCurve())
	benchmarkEncrypting(b, edwards25519.NewPrimeSubGroup())
	benchmarkEncrypting(b, bls12381.NewG1())
	benchmarkEncrypting(b, bls12381.NewG2())
}

func BenchmarkDecrypting(b *testing.B) {
	benchmarkDecrypting(b, k256.NewCurve())
	benchmarkDecrypting(b, p256.NewCurve())
	benchmarkDecrypting(b, edwards25519.NewPrimeSubGroup())
	benchmarkDecrypting(b, bls12381.NewG1())
	benchmarkDecrypting(b, bls12381.NewG2())
}
