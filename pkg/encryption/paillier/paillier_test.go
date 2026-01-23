package paillier_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

func Test_Sanity(t *testing.T) {
	t.Parallel()
	sk, pk := sampleKeys(t, pcg.NewRandomised())
	plaintext := sampleMessage(t, pk)

	scheme := paillier.NewScheme()

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	ciphertext, nonce, err := enc.Encrypt(plaintext, pk, pcg.NewRandomised())
	require.NoError(t, err)
	require.NotNil(t, nonce)

	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	decrypted, err := dec.Decrypt(ciphertext)
	require.NoError(t, err)

	require.True(t, plaintext.Equal(decrypted))
}

func Benchmark_Encrypt4k(b *testing.B) {
	_, pk := sampleKeys(b, pcg.NewRandomised())
	plaintext := sampleMessage(b, pk)
	nonce, err := pk.NonceSpace().Sample(pcg.NewRandomised())
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
	sk, _ := sampleKeys(b, pcg.NewRandomised())
	plaintext := sampleMessage(b, sk.PublicKey())
	nonce, err := sk.PublicKey().NonceSpace().Sample(pcg.NewRandomised())
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
	sk, pk := sampleKeys(b, pcg.NewRandomised())
	ciphertext, err := pk.CiphertextSpace().Sample(pcg.NewRandomised())
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
	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(tb, err)
	sk, pk, err := kg.Generate(prng)
	require.NoError(tb, err)
	return sk, pk
}

func sampleMessage(tb testing.TB, pk *paillier.PublicKey) *paillier.Plaintext {
	tb.Helper()
	pts := pk.PlaintextSpace()
	pt, err := pts.Sample(nil, nil, pcg.NewRandomised())
	require.NoError(tb, err)
	return pt
}
