package paillier

// import (
// 	crand "crypto/rand"
// 	"fmt"
// 	"io"
// 	"math/rand"
// 	"testing"

// 	"github.com/bronlabs/bron-crypto/pkg/base/ct"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
// 	"github.com/stretchr/testify/require"
// )

// func Test_SanityVanilla(t *testing.T) {
// 	t.Parallel()
// 	sk, pk := sampleKeys(t, crand.Reader)
// 	plaintext := sampleMessage(t)

// 	enc := &Encrypter{}
// 	ciphertext, nonce, err := enc.Encrypt(plaintext, pk, crand.Reader)
// 	require.NoError(t, err)
// 	require.NotNil(t, nonce)

// 	dec := &Decrypter{
// 		sk: sk,
// 	}

// 	decrypted, err := dec.VanillaDecrypt(ciphertext)
// 	require.NoError(t, err)

// 	require.True(t, plaintext.V.Equal(decrypted.V) == ct.True, fmt.Sprintf("%s != %s", plaintext.V.String(), decrypted.V.String()))
// }

// func Test_SanityFQ(t *testing.T) {
// 	t.Parallel()
// 	sk, pk := sampleKeys(t, crand.Reader)
// 	plaintext := sampleMessage(t)

// 	enc := &Encrypter{}
// 	ciphertext, nonce, err := enc.Encrypt(plaintext, pk, crand.Reader)
// 	require.NoError(t, err)
// 	require.NotNil(t, nonce)

// 	dec := &Decrypter{
// 		sk: sk,
// 	}
// 	fqDecrypted, err := dec.Decrypt(ciphertext)
// 	require.NoError(t, err)

// 	require.True(t, plaintext.V.Equal(fqDecrypted.V) == ct.True, fmt.Sprintf("%s != %s", plaintext.V.String(), fqDecrypted.V.String()))
// }

// func Test_SanityAdic(t *testing.T) {
// 	t.Parallel()
// 	sk, pk := sampleKeys(t, crand.Reader)
// 	plaintext := sampleMessage(t)

// 	enc := &Encrypter{}
// 	ciphertext, nonce, err := enc.EncryptAdic(plaintext, pk, crand.Reader)
// 	require.NoError(t, err)
// 	require.NotNil(t, nonce)

// 	dec := &Decrypter{
// 		sk: sk,
// 	}
// 	fqDecrypted, err := dec.Decrypt(ciphertext)
// 	require.NoError(t, err)

// 	require.True(t, plaintext.V.Equal(fqDecrypted.V) == ct.True, fmt.Sprintf("%s != %s", plaintext.V.String(), fqDecrypted.V.String()))
// }

// func Benchmark_Encrypt4k(b *testing.B) {
// 	_, pk := sampleKeys(b, crand.Reader)
// 	plaintext := sampleMessage(b)
// 	nonce := sampleNonce(b, pk, crand.Reader)
// 	enc := &Encrypter{}
// 	b.ReportAllocs()
// 	b.ResetTimer()
// 	for range b.N {
// 		_, err := enc.EncryptWithNonce(plaintext, pk, nonce)
// 		require.NoError(b, err)
// 	}
// }

// func Benchmark_EncryptWithSecret(b *testing.B) {
// 	sk, _ := sampleKeys(b, crand.Reader)
// 	plaintext := sampleMessage(b)
// 	nonce := sampleNonce(b, sk.PublicKey(), crand.Reader)
// 	enc := &Encrypter{}
// 	b.ReportAllocs()
// 	b.ResetTimer()
// 	for range b.N {
// 		_, err := enc.EncryptWithNonce(plaintext, sk.PublicKey(), nonce)
// 		require.NoError(b, err)
// 	}
// }

// func Benchmark_EncryptAdic(b *testing.B) {
// 	sk, _ := sampleKeys(b, crand.Reader)
// 	pk := sk.PublicKey()
// 	plaintext := sampleMessage(b)
// 	nonce := sampleNonce(b, pk, crand.Reader)
// 	enc := &Encrypter{}
// 	b.ReportAllocs()
// 	b.ResetTimer()
// 	for range b.N {
// 		_, err := enc.EncryptWithNonceAdic(plaintext, pk, nonce)
// 		require.NoError(b, err)
// 	}
// }

// func Benchmark_VanillaDecrypt4k(b *testing.B) {
// 	sk, pk := sampleKeys(b, crand.Reader)
// 	ciphertext := randomCiphertext(b, pk, crand.Reader)
// 	dec := &Decrypter{
// 		sk: sk,
// 	}
// 	b.ResetTimer()
// 	for range b.N {
// 		_, err := dec.VanillaDecrypt(ciphertext)
// 		require.NoError(b, err)
// 	}
// }

// func Benchmark_Decrypt4k(b *testing.B) {
// 	sk, pk := sampleKeys(b, crand.Reader)
// 	ciphertext := randomCiphertext(b, pk, crand.Reader)
// 	dec := &Decrypter{
// 		sk: sk,
// 	}
// 	b.ResetTimer()
// 	for range b.N {
// 		_, err := dec.Decrypt(ciphertext)
// 		require.NoError(b, err)
// 	}
// }

// func sampleKeys(tb testing.TB, prng io.Reader) (*PrivateKey, *PublicKey) {
// 	tb.Helper()
// 	kg := &KeyGenerator{}
// 	sk, pk, err := kg.Generate(prng)
// 	require.NoError(tb, err)
// 	return sk, pk
// }

// func sampleMessage(tb testing.TB) *Plaintext {
// 	tb.Helper()
// 	return &Plaintext{
// 		V: numct.NewNat(rand.Uint64()),
// 	}
// }

// func sampleNonce(tb testing.TB, pk *PublicKey, prng io.Reader) *Nonce {
// 	tb.Helper()
// 	nonceValue, err := pk.N.Random(prng)
// 	require.NoError(tb, err)
// 	return &Nonce{V: nonceValue}
// }

// func randomCiphertext(tb testing.TB, pk *PublicKey, prng io.Reader) *Ciphertext {
// 	tb.Helper()
// 	nonce := sampleNonce(tb, pk, prng)
// 	plaintext := sampleMessage(tb)
// 	enc := &Encrypter{}
// 	ct, err := enc.EncryptWithNonce(plaintext, pk, nonce)
// 	require.NoError(tb, err)
// 	return ct
// }
