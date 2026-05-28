package elgamal_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/constructions"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/elgamal"
)

// All adversarial tests are run on k256 (prime-order, cofactor 1). Torsion
// adversarial inputs are not exercisable on prime-order curves — every
// non-identity point is torsion-free.

func sampleTestKey(tb testing.TB) *elgamal.SecretKey[*k256.Point, *k256.Scalar] {
	tb.Helper()
	key, err := elgamal.SampleSecretKey(k256.NewCurve(), pcg.NewRandomised())
	require.NoError(tb, err)
	return key
}

func TestSampleSecretKey(t *testing.T) {
	t.Parallel()

	t.Run("returns a key for a valid group and prng", func(t *testing.T) {
		t.Parallel()
		key, err := elgamal.SampleSecretKey(k256.NewCurve(), pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, key)
		require.NotNil(t, key.Public())
	})

	t.Run("returns an error for a nil group", func(t *testing.T) {
		t.Parallel()
		key, err := elgamal.SampleSecretKey[*k256.Point, *k256.Scalar](nil, pcg.NewRandomised())
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("returns an error for a nil prng", func(t *testing.T) {
		t.Parallel()
		key, err := elgamal.SampleSecretKey(k256.NewCurve(), nil)
		require.Error(t, err)
		require.Nil(t, key)
	})
}

func TestPublicKeySampleNonce(t *testing.T) {
	t.Parallel()
	pk := sampleTestKey(t).Public()

	t.Run("returns a nonce for a valid prng", func(t *testing.T) {
		t.Parallel()
		nonce, err := pk.SampleNonce(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, nonce)
		require.False(t, nonce.Value().IsOpIdentity())
	})

	t.Run("returns an error for a nil prng", func(t *testing.T) {
		t.Parallel()
		nonce, err := pk.SampleNonce(nil)
		require.Error(t, err)
		require.Nil(t, nonce)
	})
}

func TestNewPublicKey(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	t.Run("returns a public key for a valid non-identity element", func(t *testing.T) {
		t.Parallel()
		pk, err := elgamal.NewPublicKey(curve.Generator())
		require.NoError(t, err)
		require.NotNil(t, pk)
	})

	t.Run("returns an error for a nil element", func(t *testing.T) {
		t.Parallel()
		pk, err := elgamal.NewPublicKey[*k256.Point, *k256.Scalar](nil)
		require.Error(t, err)
		require.Nil(t, pk)
	})

	t.Run("returns an error for the identity element", func(t *testing.T) {
		t.Parallel()
		// Identity h = g^0 would let any party trivially decrypt: δ · γ^0 = δ leaks m.
		pk, err := elgamal.NewPublicKey(curve.OpIdentity())
		require.Error(t, err)
		require.Nil(t, pk)
	})
}

func TestNewSecretKey(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	scalarField := k256.NewScalarField()

	t.Run("returns a secret key for a valid generator and scalar", func(t *testing.T) {
		t.Parallel()
		two := scalarField.FromUint64(2)
		sk, err := elgamal.NewSecretKey(curve.Generator(), two)
		require.NoError(t, err)
		require.NotNil(t, sk)
		require.True(t, sk.Value().Equal(two))
	})

	t.Run("returns an error for a nil generator", func(t *testing.T) {
		t.Parallel()
		sk, err := elgamal.NewSecretKey[*k256.Point, *k256.Scalar](nil, scalarField.FromUint64(2))
		require.Error(t, err)
		require.Nil(t, sk)
	})

	t.Run("returns an error for a nil scalar", func(t *testing.T) {
		t.Parallel()
		sk, err := elgamal.NewSecretKey(curve.Generator(), nil)
		require.Error(t, err)
		require.Nil(t, sk)
	})

	t.Run("returns an error for the identity generator", func(t *testing.T) {
		t.Parallel()
		// g = O makes h = O^a = O, which collapses ElGamal to a no-op.
		sk, err := elgamal.NewSecretKey(curve.OpIdentity(), scalarField.FromUint64(2))
		require.Error(t, err)
		require.Nil(t, sk)
	})

	t.Run("returns an error for scalar zero", func(t *testing.T) {
		t.Parallel()
		// a = 0 produces h = identity (and is the discrete log of every public key).
		sk, err := elgamal.NewSecretKey(curve.Generator(), scalarField.Zero())
		require.Error(t, err)
		require.Nil(t, sk)
	})

	t.Run("returns an error for scalar one", func(t *testing.T) {
		t.Parallel()
		// a = 1 makes h = g; the "secret" is the public generator.
		sk, err := elgamal.NewSecretKey(curve.Generator(), scalarField.One())
		require.Error(t, err)
		require.Nil(t, sk)
	})
}

func TestNewCiphertext(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	c1, err := curve.Random(prng)
	require.NoError(t, err)
	c2, err := curve.Random(prng)
	require.NoError(t, err)

	t.Run("returns a ciphertext for two valid components", func(t *testing.T) {
		t.Parallel()
		ct, err := elgamal.NewCiphertext(c1, c2)
		require.NoError(t, err)
		require.NotNil(t, ct)
	})

	t.Run("returns a ciphertext for (identity, identity)", func(t *testing.T) {
		t.Parallel()
		// The identity element is torsion-free; the constructor only rejects
		// nil and torsion components, not identity. (NewSecretKey/NewPublicKey
		// reject identity at key construction time, not here.)
		id := curve.OpIdentity()
		ct, err := elgamal.NewCiphertext(id, id)
		require.NoError(t, err)
		require.NotNil(t, ct)
	})

	t.Run("returns an error for a nil first component", func(t *testing.T) {
		t.Parallel()
		ct, err := elgamal.NewCiphertext(nil, c2)
		require.Error(t, err)
		require.Nil(t, ct)
	})

	t.Run("returns an error for a nil second component", func(t *testing.T) {
		t.Parallel()
		ct, err := elgamal.NewCiphertext(c1, nil)
		require.Error(t, err)
		require.Nil(t, ct)
	})

	t.Run("returns an error for both nil components", func(t *testing.T) {
		t.Parallel()
		ct, err := elgamal.NewCiphertext[*k256.Point, *k256.Scalar](nil, nil)
		require.Error(t, err)
		require.Nil(t, ct)
	})
}

func TestNewCiphertextFromGroupElement(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	prng := pcg.NewRandomised()

	t.Run("returns a ciphertext for a valid arity-2 element", func(t *testing.T) {
		t.Parallel()
		mod, err := constructions.NewFiniteDirectPowerModule(curve, 2)
		require.NoError(t, err)
		elem, err := mod.Random(prng)
		require.NoError(t, err)
		ct, err := elgamal.NewCiphertextFromGroupElement(elem)
		require.NoError(t, err)
		require.NotNil(t, ct)
		require.True(t, ct.Value().Equal(elem))
	})

	t.Run("returns an error for a nil group element", func(t *testing.T) {
		t.Parallel()
		ct, err := elgamal.NewCiphertextFromGroupElement[*k256.Point, *k256.Scalar](nil)
		require.Error(t, err)
		require.Nil(t, ct)
	})

	t.Run("returns an error for an arity-1 element", func(t *testing.T) {
		t.Parallel()
		mod, err := constructions.NewFiniteDirectPowerModule(curve, 1)
		require.NoError(t, err)
		elem, err := mod.Random(prng)
		require.NoError(t, err)
		ct, err := elgamal.NewCiphertextFromGroupElement(elem)
		require.Error(t, err)
		require.Nil(t, ct)
	})

	t.Run("returns an error for an arity-3 element", func(t *testing.T) {
		t.Parallel()
		mod, err := constructions.NewFiniteDirectPowerModule(curve, 3)
		require.NoError(t, err)
		elem, err := mod.Random(prng)
		require.NoError(t, err)
		ct, err := elgamal.NewCiphertextFromGroupElement(elem)
		require.Error(t, err)
		require.Nil(t, ct)
	})
}

func TestNewNonce(t *testing.T) {
	t.Parallel()
	scalarField := k256.NewScalarField()

	t.Run("returns a nonce for a non-identity scalar", func(t *testing.T) {
		t.Parallel()
		nonce, err := elgamal.NewNonce(scalarField.FromUint64(2))
		require.NoError(t, err)
		require.NotNil(t, nonce)
	})

	t.Run("returns a nonce for scalar one", func(t *testing.T) {
		t.Parallel()
		// 1 is not the additive identity of Z/nZ, so it is a valid (if dull)
		// nonce — the encryption (g, m·h) it produces is still a ciphertext.
		nonce, err := elgamal.NewNonce(scalarField.One())
		require.NoError(t, err)
		require.NotNil(t, nonce)
	})

	t.Run("returns an error for a nil scalar", func(t *testing.T) {
		t.Parallel()
		nonce, err := elgamal.NewNonce[*k256.Scalar](nil)
		require.Error(t, err)
		require.Nil(t, nonce)
	})
}

func TestNewPlaintext(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()

	t.Run("returns a plaintext for a valid element", func(t *testing.T) {
		t.Parallel()
		v, err := curve.Random(pcg.NewRandomised())
		require.NoError(t, err)
		p, err := elgamal.NewPlaintext(v)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.True(t, p.Value().Equal(v))
	})

	t.Run("returns a plaintext for the identity element", func(t *testing.T) {
		t.Parallel()
		// The message space is G itself; identity is a legal plaintext.
		p, err := elgamal.NewPlaintext(curve.OpIdentity())
		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("returns an error for a nil element", func(t *testing.T) {
		t.Parallel()
		p, err := elgamal.NewPlaintext[*k256.Point, *k256.Scalar](nil)
		require.Error(t, err)
		require.Nil(t, p)
	})
}
