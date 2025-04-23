package paillier_test

import (
	crand "crypto/rand"
	"io"
	"math/big"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/indcpa/paillier"
)

const primeBits = 2048

func Benchmark_Encrypt4k(b *testing.B) {
	prng := crand.Reader
	_, pk := sampleKeys(b, prng)
	plaintext := samplePlaintext(b, pk, prng)
	nonce := sampleNonce(b, pk, prng)

	b.ResetTimer()
	for range b.N {
		_, err := pk.EncryptWithNonce(plaintext, nonce)
		require.NoError(b, err)
	}

}

func Benchmark_ScalarMul4k(b *testing.B) {
	prng := crand.Reader
	_, pk := sampleKeys(b, prng)
	ciphertext := sampleCiphertext(b, pk, prng)
	scalar := sampleScalar(b, pk, prng)

	b.ResetTimer()
	for range b.N {
		_, err := pk.CipherTextMul(ciphertext, scalar)
		require.NoError(b, err)
	}
}

func Benchmark_EncryptWithSecret4k(b *testing.B) {
	prng := crand.Reader
	sk, pk := sampleKeys(b, prng)
	plaintext := samplePlaintext(b, pk, prng)
	nonce := sampleNonce(b, pk, prng)

	b.ResetTimer()
	for range b.N {
		_, err := sk.EncryptWithNonce(plaintext, nonce)
		require.NoError(b, err)
	}
}

func Benchmark_ScalarMulWithSecret4k(b *testing.B) {
	prng := crand.Reader
	sk, pk := sampleKeys(b, prng)
	ciphertext := sampleCiphertext(b, pk, prng)
	scalar := sampleScalar(b, pk, prng)

	b.ResetTimer()
	for range b.N {
		_, err := sk.CipherTextMul(ciphertext, scalar)
		require.NoError(b, err)
	}
}

func Benchmark_Decrypt4k(b *testing.B) {
	prng := crand.Reader
	sk, pk := sampleKeys(b, prng)
	ciphertext := sampleCiphertext(b, pk, prng)

	b.ResetTimer()
	for range b.N {
		_, err := sk.Decrypt(ciphertext)
		require.NoError(b, err)
	}
}

func Benchmark_Open4k(b *testing.B) {
	prng := crand.Reader
	sk, pk := sampleKeys(b, prng)
	ciphertext := sampleCiphertext(b, pk, prng)

	b.ResetTimer()
	for range b.N {
		_, _, err := sk.Open(ciphertext)
		require.NoError(b, err)
	}
}

func sampleKeys(tb testing.TB, prng io.Reader) (sk *paillier.SecretKey, pk *paillier.PublicKey) {
	tb.Helper()

	pInt, err := crand.Prime(prng, primeBits)
	require.NoError(tb, err)
	qInt, err := crand.Prime(prng, primeBits)
	require.NoError(tb, err)

	sk, err = paillier.NewSecretKey(new(saferith.Nat).SetBig(pInt, primeBits), new(saferith.Nat).SetBig(qInt, primeBits))
	require.NoError(tb, err)
	pk, err = sk.ToEncryptionKey()
	require.NoError(tb, err)

	return sk, pk
}

func samplePlaintext(tb testing.TB, pk *paillier.PublicKey, prng io.Reader) (plaintext *paillier.PlainText) {
	tb.Helper()

	bound := new(big.Int)
	bound.SetBit(bound, primeBits+128, 1)

	p, err := crand.Int(prng, bound)
	require.NoError(tb, err)
	plaintext = new(paillier.PlainText)
	plaintext.SetBig(p, p.BitLen())
	plaintext.SetModSymmetric(new(saferith.Nat).SetBig(p, p.BitLen()), pk.N)

	return plaintext
}

func sampleNonce(tb testing.TB, pk *paillier.PublicKey, prng io.Reader) (nonce *paillier.Nonce) {
	tb.Helper()

	bound := new(big.Int)
	bound.SetBit(bound, primeBits+128, 1)

	for nonce == nil || nonce.EqZero() != 0 || nonce.IsUnit(pk.N) == 0 {
		c, err := crand.Int(prng, bound)
		require.NoError(tb, err)
		nonce = new(paillier.Nonce)
		nonce.SetBig(c, c.BitLen())
		nonce.Mod(nonce, pk.N)
	}

	return nonce
}

func sampleScalar(tb testing.TB, pk *paillier.PublicKey, prng io.Reader) (scalar *paillier.Scalar) {
	tb.Helper()

	p := samplePlaintext(tb, pk, prng)
	return p
}

func sampleCiphertext(tb testing.TB, pk *paillier.PublicKey, prng io.Reader) (ciphertext *paillier.CipherText) {
	tb.Helper()

	bound := new(big.Int)
	bound.SetBit(bound, 2*primeBits+128, 1)
	nn := saferith.ModulusFromNat(new(saferith.Nat).Mul(pk.N.Nat(), pk.N.Nat(), 2*primeBits))

	for ciphertext == nil || ciphertext.C.EqZero() != 0 || ciphertext.C.IsUnit(pk.N) == 0 {
		c, err := crand.Int(prng, bound)
		require.NoError(tb, err)
		ciphertext = new(paillier.CipherText)
		ciphertext.C.SetBig(c, c.BitLen())
		ciphertext.C.Mod(&ciphertext.C, nn)
	}

	return ciphertext
}
