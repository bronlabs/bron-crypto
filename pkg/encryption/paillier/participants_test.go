package paillier_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

// --- KeyGenerator Tests ---

func TestKeyGenerator_Generate(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen()
	require.NoError(t, err)

	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.NotNil(t, pk)
}

func TestKeyGenerator_WithKeyLength(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()

	// Test with custom bit length
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)

	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, sk)
	require.NotNil(t, pk)
}

func TestKeyGenerator_KeysMatch(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)

	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	// The public key derived from private key should match
	require.True(t, sk.PublicKey().Equal(pk))
}

// --- Encrypter Tests ---

func TestEncrypter_Encrypt(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	_, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	pt := pk.PlaintextSpace().Zero()
	ct, nonce, err := enc.Encrypt(pt, pk, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, ct)
	require.NotNil(t, nonce)
}

func TestEncrypter_EncryptWithNonce_Deterministic(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	_, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	pt := pk.PlaintextSpace().Zero()
	nonce, err := pk.NonceSpace().Sample(crand.Reader)
	require.NoError(t, err)

	ct1, err := enc.EncryptWithNonce(pt, pk, nonce)
	require.NoError(t, err)
	ct2, err := enc.EncryptWithNonce(pt, pk, nonce)
	require.NoError(t, err)

	require.True(t, ct1.Equal(ct2), "encryption with same nonce should be deterministic")
}

func TestEncrypter_EncryptMany(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	ps := pk.PlaintextSpace()
	plaintexts := make([]*paillier.Plaintext, 5)
	for i := range plaintexts {
		var n numct.Int
		n.SetNat(numct.NewNat(uint64(i * 100)))
		pt, err := ps.FromInt(&n)
		require.NoError(t, err)
		plaintexts[i] = pt
	}

	cts, nonces, err := enc.EncryptMany(plaintexts, pk, crand.Reader)
	require.NoError(t, err)
	require.Len(t, cts, len(plaintexts))
	require.Len(t, nonces, len(plaintexts))

	// Verify all decryptions
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	for i, ct := range cts {
		decrypted, err := dec.Decrypt(ct)
		require.NoError(t, err)
		require.True(t, plaintexts[i].Equal(decrypted), "plaintext %d should match", i)
	}
}

func TestEncrypter_EncryptManyWithNonces(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	_, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	ps := pk.PlaintextSpace()
	plaintexts := make([]*paillier.Plaintext, 3)
	nonces := make([]*paillier.Nonce, 3)
	for i := range plaintexts {
		plaintexts[i] = ps.Zero()
		nonces[i], err = pk.NonceSpace().Sample(crand.Reader)
		require.NoError(t, err)
	}

	cts1, err := enc.EncryptManyWithNonces(plaintexts, pk, nonces)
	require.NoError(t, err)
	cts2, err := enc.EncryptManyWithNonces(plaintexts, pk, nonces)
	require.NoError(t, err)

	// Should be deterministic
	for i := range cts1 {
		require.True(t, cts1[i].Equal(cts2[i]), "ciphertext %d should match", i)
	}
}

// --- SelfEncrypter Tests ---

func TestSelfEncrypter_SelfEncrypt(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, _, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	se, err := scheme.SelfEncrypter(sk)
	require.NoError(t, err)

	pt := sk.PublicKey().PlaintextSpace().Zero()
	ct, nonce, err := se.SelfEncrypt(pt, crand.Reader)
	require.NoError(t, err)
	require.NotNil(t, ct)
	require.NotNil(t, nonce)
}

func TestSelfEncrypter_MatchesRegularEncrypt(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	se, err := scheme.SelfEncrypter(sk)
	require.NoError(t, err)
	enc, err := scheme.Encrypter()
	require.NoError(t, err)

	ps := pk.PlaintextSpace()
	var n numct.Int
	n.SetNat(numct.NewNat(12345))
	pt, err := ps.FromInt(&n)
	require.NoError(t, err)

	// Self-encrypt
	ctSelf, nonce, err := se.SelfEncrypt(pt, crand.Reader)
	require.NoError(t, err)

	// Regular encrypt with same nonce
	ctReg, err := enc.EncryptWithNonce(pt, pk, nonce)
	require.NoError(t, err)

	// Should produce same ciphertext
	require.True(t, ctSelf.Equal(ctReg), "self-encryption should match regular encryption")
}

func TestSelfEncrypter_SelfEncryptWithNonce(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, _, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	se, err := scheme.SelfEncrypter(sk)
	require.NoError(t, err)

	pt := sk.PublicKey().PlaintextSpace().Zero()
	nonce, err := sk.PublicKey().NonceSpace().Sample(crand.Reader)
	require.NoError(t, err)

	ct1, err := se.SelfEncryptWithNonce(pt, nonce)
	require.NoError(t, err)
	ct2, err := se.SelfEncryptWithNonce(pt, nonce)
	require.NoError(t, err)

	require.True(t, ct1.Equal(ct2), "self-encryption with same nonce should be deterministic")
}

func TestSelfEncrypter_SelfEncryptMany(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, _, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	se, err := scheme.SelfEncrypter(sk)
	require.NoError(t, err)

	ps := sk.PublicKey().PlaintextSpace()
	plaintexts := make([]*paillier.Plaintext, 5)
	for i := range plaintexts {
		var n numct.Int
		n.SetNat(numct.NewNat(uint64(i * 100)))
		pt, err := ps.FromInt(&n)
		require.NoError(t, err)
		plaintexts[i] = pt
	}

	cts, nonces, err := se.SelfEncryptMany(plaintexts, crand.Reader)
	require.NoError(t, err)
	require.Len(t, cts, len(plaintexts))
	require.Len(t, nonces, len(plaintexts))

	// Verify all decryptions
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)
	for i, ct := range cts {
		decrypted, err := dec.Decrypt(ct)
		require.NoError(t, err)
		require.True(t, plaintexts[i].Equal(decrypted), "plaintext %d should match", i)
	}
}

func TestSelfEncrypter_PrivateKey(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, _, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	se, err := scheme.SelfEncrypter(sk)
	require.NoError(t, err)

	require.True(t, sk.Equal(se.PrivateKey()))
}

func TestSelfEncrypter_NilPrivateKey(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	_, err := scheme.SelfEncrypter(nil)
	require.Error(t, err)
}

// --- Decrypter Tests ---

func TestDecrypter_Decrypt(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	ps := pk.PlaintextSpace()
	var n numct.Int
	n.SetNat(numct.NewNat(42))
	pt, err := ps.FromInt(&n)
	require.NoError(t, err)

	ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
	require.NoError(t, err)

	decrypted, err := dec.Decrypt(ct)
	require.NoError(t, err)
	require.True(t, pt.Equal(decrypted))
}

func TestDecrypter_NilPrivateKey(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	_, err := scheme.Decrypter(nil)
	require.Error(t, err)
}

func TestDecrypter_RoundTrip_RandomPlaintexts(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	ps := pk.PlaintextSpace()

	for i := range 10 {
		pt, err := ps.Sample(nil, nil, crand.Reader)
		require.NoError(t, err)

		ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
		require.NoError(t, err)

		decrypted, err := dec.Decrypt(ct)
		require.NoError(t, err)

		require.True(t, pt.Equal(decrypted), "round-trip %d failed", i)
	}
}

func TestDecrypter_RoundTrip_NegativePlaintexts(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	ps := pk.PlaintextSpace()

	testCases := []int64{-1, -42, -1000, -999999}
	for _, val := range testCases {
		var n numct.Int
		n.SetNat(numct.NewNat(uint64(-val)))
		n.Neg(&n)
		pt, err := ps.FromInt(&n)
		require.NoError(t, err)

		ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
		require.NoError(t, err)

		decrypted, err := dec.Decrypt(ct)
		require.NoError(t, err)

		require.True(t, pt.Equal(decrypted), "round-trip for %d failed", val)
	}
}

func TestDecrypter_RoundTrip_Zero(t *testing.T) {
	t.Parallel()

	scheme := paillier.NewScheme()
	kg, err := scheme.Keygen(paillier.WithKeyLen(keyLen))
	require.NoError(t, err)
	sk, pk, err := kg.Generate(crand.Reader)
	require.NoError(t, err)

	enc, err := scheme.Encrypter()
	require.NoError(t, err)
	dec, err := scheme.Decrypter(sk)
	require.NoError(t, err)

	pt := pk.PlaintextSpace().Zero()

	ct, _, err := enc.Encrypt(pt, pk, crand.Reader)
	require.NoError(t, err)

	decrypted, err := dec.Decrypt(ct)
	require.NoError(t, err)

	require.True(t, pt.Equal(decrypted))
}
