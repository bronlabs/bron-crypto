package indcpacom_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments/indcpacom"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
)

// Tests use ElGamal over k256 for instantiation, per the package's most
// lightweight homomorphic-encryption backend. indcpacom's constructors are
// thin wrappers around encryption types, so the meaningful adversarial input
// is "nil"; range / membership checks live in the encryption layer.

type (
	testPlaintext  = *elgamal.Plaintext[*k256.Point, *k256.Scalar]
	testNonce      = *elgamal.Nonce[*k256.Scalar]
	testCiphertext = *elgamal.Ciphertext[*k256.Point, *k256.Scalar]
	testPublicKey  = *elgamal.PublicKey[*k256.Point, *k256.Scalar]
	testSecretKey  = *elgamal.SecretKey[*k256.Point, *k256.Scalar]
)

type testFixture struct {
	secretKey  testSecretKey
	publicKey  testPublicKey
	plaintext  testPlaintext
	nonce      testNonce
	ciphertext testCiphertext
}

func newFixture(tb testing.TB) testFixture {
	tb.Helper()
	prng := pcg.NewRandomised()
	sk, err := elgamal.SampleSecretKey(k256.NewCurve(), prng)
	require.NoError(tb, err)

	plaintextValue, err := sk.PlaintextGroup().Random(prng)
	require.NoError(tb, err)
	plaintext, err := elgamal.NewPlaintext(plaintextValue)
	require.NoError(tb, err)

	nonce, err := sk.SampleNonce(prng)
	require.NoError(tb, err)

	ciphertext, err := sk.EncryptWithNonce(plaintext, nonce)
	require.NoError(tb, err)

	return testFixture{
		secretKey:  sk,
		publicKey:  sk.Public(),
		plaintext:  plaintext,
		nonce:      nonce,
		ciphertext: ciphertext,
	}
}

func TestNewCommitment(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	t.Run("returns a commitment for a valid ciphertext", func(t *testing.T) {
		t.Parallel()
		c, err := indcpacom.NewCommitment(f.ciphertext)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.True(t, c.Value().Equal(f.ciphertext))
	})

	t.Run("returns an error for a nil ciphertext", func(t *testing.T) {
		t.Parallel()
		c, err := indcpacom.NewCommitment(testCiphertext(nil))
		require.Error(t, err)
		require.Nil(t, c)
	})
}

func TestNewWitness(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	t.Run("returns a witness for a valid nonce", func(t *testing.T) {
		t.Parallel()
		w, err := indcpacom.NewWitness(f.nonce)
		require.NoError(t, err)
		require.NotNil(t, w)
		require.True(t, w.Value().Equal(f.nonce))
	})

	t.Run("returns an error for a nil nonce", func(t *testing.T) {
		t.Parallel()
		w, err := indcpacom.NewWitness(testNonce(nil))
		require.Error(t, err)
		require.Nil(t, w)
	})
}

func TestNewMessage(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	t.Run("returns a message for a valid plaintext", func(t *testing.T) {
		t.Parallel()
		m, err := indcpacom.NewMessage(f.plaintext)
		require.NoError(t, err)
		require.NotNil(t, m)
		require.True(t, m.Value().Equal(f.plaintext))
	})

	t.Run("returns an error for a nil plaintext", func(t *testing.T) {
		t.Parallel()
		m, err := indcpacom.NewMessage(testPlaintext(nil))
		require.Error(t, err)
		require.Nil(t, m)
	})
}

func TestNewCommitmentKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	t.Run("returns a commitment key for a valid public encryption key", func(t *testing.T) {
		t.Parallel()
		k, err := indcpacom.NewCommitmentKey(f.publicKey)
		require.NoError(t, err)
		require.NotNil(t, k)
		require.True(t, k.EncryptionKey().Equal(f.publicKey))
	})

	t.Run("returns a commitment key for a valid secret encryption key", func(t *testing.T) {
		t.Parallel()
		k, err := indcpacom.NewCommitmentKey(f.secretKey)
		require.NoError(t, err)
		require.NotNil(t, k)
		require.True(t, k.EncryptionKey().Equal(f.secretKey))
	})

	t.Run("returns an error for a nil public encryption key", func(t *testing.T) {
		t.Parallel()
		k, err := indcpacom.NewCommitmentKey(testPublicKey(nil))
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("returns an error for a nil secret encryption key", func(t *testing.T) {
		t.Parallel()
		k, err := indcpacom.NewCommitmentKey(testSecretKey(nil))
		require.Error(t, err)
		require.Nil(t, k)
	})
}

func TestNewHomomorphicCommitmentKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	t.Run("returns a homomorphic commitment key for a valid public encryption key", func(t *testing.T) {
		t.Parallel()
		k, err := indcpacom.NewHomomorphicCommitmentKey(f.publicKey)
		require.NoError(t, err)
		require.NotNil(t, k)
		require.True(t, k.EncryptionKey().Equal(f.publicKey))
	})

	t.Run("returns a homomorphic commitment key for a valid secret encryption key", func(t *testing.T) {
		t.Parallel()
		k, err := indcpacom.NewHomomorphicCommitmentKey(f.secretKey)
		require.NoError(t, err)
		require.NotNil(t, k)
		require.True(t, k.EncryptionKey().Equal(f.secretKey))
	})

	t.Run("returns an error for a nil public encryption key", func(t *testing.T) {
		t.Parallel()
		k, err := indcpacom.NewHomomorphicCommitmentKey(testPublicKey(nil))
		require.Error(t, err)
		require.Nil(t, k)
	})

	t.Run("returns an error for a nil secret encryption key", func(t *testing.T) {
		t.Parallel()
		k, err := indcpacom.NewHomomorphicCommitmentKey(testSecretKey(nil))
		require.Error(t, err)
		require.Nil(t, k)
	})
}

func TestCommitmentKeySampleWitness(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	key, err := indcpacom.NewCommitmentKey(f.publicKey)
	require.NoError(t, err)

	t.Run("returns a witness for a valid prng", func(t *testing.T) {
		t.Parallel()
		w, err := key.SampleWitness(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, w)
		require.False(t, w.Value().Value().IsOpIdentity())
	})

	t.Run("returns an error for a nil prng", func(t *testing.T) {
		t.Parallel()
		// Error propagates from elgamal.PublicKey.SampleNonce, which rejects nil prng.
		w, err := key.SampleWitness(nil)
		require.Error(t, err)
		require.Nil(t, w)
	})
}
