package paillier_test

import (
	crand "crypto/rand"
	"io"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	paillier "github.com/bronlabs/bron-crypto/pkg/encryption/paillier_ct"
)

func Test_Sanity(t *testing.T) {
	t.Parallel()
	sk, pk := sampleKeys(t, crand.Reader)
	plaintext := sampleMessage(t, pk.N())

	scheme := paillier.NewScheme()

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	ciphertext, nonce, err := enc.Encrypt(plaintext, pk, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, nonce)

	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	decrypted, err := dec.Decrypt(ciphertext)
	require.NoError(t, err)

	require.True(t, plaintext.Equal(decrypted))
}

func Benchmark_Encrypt4k(b *testing.B) {
	_, pk := sampleKeys(b, crand.Reader)
	plaintext := sampleMessage(b, pk.N())
	nonce, err := pk.NonceSpace().Sample(crand.Reader)
	require.NoError(b, err)
	scheme := paillier.NewScheme()
	enc, err := scheme.Encrypter()
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := enc.EncryptWithNonce(plaintext, pk, nonce)
		require.NoError(b, err)
	}
}

func Benchmark_EncryptWithSecret(b *testing.B) {
	sk, _ := sampleKeys(b, crand.Reader)
	plaintext := sampleMessage(b, sk.PublicKey().N())
	nonce, err := sk.PublicKey().NonceSpace().Sample(crand.Reader)
	require.NoError(b, err)
	scheme := paillier.NewScheme()
	enc, err := scheme.SelfEncrypter(sk)
	require.NoError(b, err)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := enc.SelfEncryptWithNonce(plaintext, nonce)
		require.NoError(b, err)
	}
}

func Benchmark_Decrypt4k(b *testing.B) {
	sk, pk := sampleKeys(b, crand.Reader)
	ciphertext, err := pk.CiphertextSpace().Sample(crand.Reader)
	require.NoError(b, err)
	scheme := paillier.NewScheme()
	dec, err := scheme.Decrypter(sk)
	require.NoError(b, err)
	b.ResetTimer()
	for range b.N {
		_, err := dec.Decrypt(ciphertext)
		require.NoError(b, err)
	}
}

func sampleKeys(tb testing.TB, prng io.Reader) (*paillier.PrivateKey, *paillier.PublicKey) {
	tb.Helper()
	kg := &paillier.KeyGenerator{}
	sk, pk, err := kg.Generate(prng)
	require.NoError(tb, err)
	return sk, pk
}

func sampleMessage(tb testing.TB, n numct.Modulus) *paillier.Plaintext {
	tb.Helper()
	zModN, err := num.NewZModFromModulus(n)
	require.NoError(tb, err)
	pt, err := zModN.FromUint64(rand.Uint64())
	require.NoError(tb, err)
	return (*paillier.Plaintext)(pt.Value())
}
