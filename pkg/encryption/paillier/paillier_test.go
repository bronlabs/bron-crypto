package paillier_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/znstar"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/encryption/paillier"
)

const testKeyLen = 64

func sampleTestKey(tb testing.TB) *paillier.SecretKey {
	tb.Helper()
	key, err := paillier.SampleSecretKey(testKeyLen, pcg.NewRandomised())
	require.NoError(tb, err)
	return key
}

func TestSampleSecretKey(t *testing.T) {
	t.Parallel()

	t.Run("returns a key for a valid keyLen and prng", func(t *testing.T) {
		t.Parallel()
		key, err := paillier.SampleSecretKey(testKeyLen, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, key)
		require.NotNil(t, key.CiphertextGroup())
		require.NotNil(t, key.NonceGroup())
		require.NotNil(t, key.PlaintextGroup())
	})

	t.Run("returns an error for a nil prng", func(t *testing.T) {
		t.Parallel()
		key, err := paillier.SampleSecretKey(testKeyLen, nil)
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("returns an error for a zero keyLen", func(t *testing.T) {
		t.Parallel()
		key, err := paillier.SampleSecretKey(0, pcg.NewRandomised())
		require.Error(t, err)
		require.Nil(t, key)
	})
}

func TestSampleBlumSecretKey(t *testing.T) {
	t.Parallel()

	t.Run("returns a key for a valid keyLen and prng", func(t *testing.T) {
		t.Parallel()
		key, err := paillier.SampleBlumSecretKey(testKeyLen, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("returns an error for a nil prng", func(t *testing.T) {
		t.Parallel()
		key, err := paillier.SampleBlumSecretKey(testKeyLen, nil)
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("returns an error for a keyLen below the minimum", func(t *testing.T) {
		t.Parallel()
		// GenerateBlumPrimePair requires keyLen >= 6.
		key, err := paillier.SampleBlumSecretKey(4, pcg.NewRandomised())
		require.Error(t, err)
		require.Nil(t, key)
	})
}

func TestSampleSafeSecretKey(t *testing.T) {
	t.Parallel()

	t.Run("returns a key for a valid keyLen and prng", func(t *testing.T) {
		t.Parallel()
		key, err := paillier.SampleSafeSecretKey(testKeyLen, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, key)
	})

	t.Run("returns an error for a nil prng", func(t *testing.T) {
		t.Parallel()
		key, err := paillier.SampleSafeSecretKey(testKeyLen, nil)
		require.Error(t, err)
		require.Nil(t, key)
	})

	t.Run("returns an error for a keyLen below the minimum", func(t *testing.T) {
		t.Parallel()
		// GenerateSafePrimePair requires keyLen >= 6.
		key, err := paillier.SampleSafeSecretKey(4, pcg.NewRandomised())
		require.Error(t, err)
		require.Nil(t, key)
	})
}

func TestSampleNonce(t *testing.T) {
	t.Parallel()
	key := sampleTestKey(t)

	t.Run("returns a nonce for a valid prng", func(t *testing.T) {
		t.Parallel()
		nonce, err := key.SampleNonce(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, nonce)
		require.True(t, nonce.Group().Modulus().Equal(key.NonceGroup().Modulus()))
	})

	t.Run("returns an error for a nil prng", func(t *testing.T) {
		t.Parallel()
		nonce, err := key.SampleNonce(nil)
		require.Error(t, err)
		require.Nil(t, nonce)
	})
}

func TestNewPublicKey(t *testing.T) {
	t.Parallel()

	t.Run("returns a public key for a valid group", func(t *testing.T) {
		t.Parallel()
		key := sampleTestKey(t)
		pk, err := paillier.NewPublicKey(key.CiphertextGroup())
		require.NoError(t, err)
		require.NotNil(t, pk)
		require.True(t, pk.Equal(key.Public()))
	})

	t.Run("returns an error for a nil group", func(t *testing.T) {
		t.Parallel()
		pk, err := paillier.NewPublicKey(nil)
		require.Error(t, err)
		require.Nil(t, pk)
	})
}

func TestNewSecretKey(t *testing.T) {
	t.Parallel()

	t.Run("returns a secret key for a valid group", func(t *testing.T) {
		t.Parallel()
		group, err := znstar.SamplePaillierGroup(testKeyLen, pcg.NewRandomised())
		require.NoError(t, err)
		sk, err := paillier.NewSecretKey(group)
		require.NoError(t, err)
		require.NotNil(t, sk)
	})

	t.Run("returns an error for a nil group", func(t *testing.T) {
		t.Parallel()
		sk, err := paillier.NewSecretKey(nil)
		require.Error(t, err)
		require.Nil(t, sk)
	})
}

func TestNewCiphertext(t *testing.T) {
	t.Parallel()
	key := sampleTestKey(t)
	group := key.CiphertextGroup()
	n := group.N()
	one, err := num.NPlus().FromUint64(1)
	require.NoError(t, err)

	t.Run("returns a ciphertext for a unit value", func(t *testing.T) {
		t.Parallel()
		// Value 1 is always a unit in (Z/N²Z)*.
		c, err := paillier.NewCiphertext(group, one)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.True(t, c.Group().Modulus().Equal(group.Modulus()))
	})

	t.Run("returns a ciphertext for value N²-1", func(t *testing.T) {
		t.Parallel()
		// N²-1 = (N-1)(N+1); gcd(N²-1, N²) = 1 because gcd(N-1, N) = gcd(N+1, N) = 1.
		n2MinusOne, err := n.Square().Decrement()
		require.NoError(t, err)
		c, err := paillier.NewCiphertext(group, n2MinusOne)
		require.NoError(t, err)
		require.NotNil(t, c)
	})

	t.Run("returns an error for a nil group", func(t *testing.T) {
		t.Parallel()
		c, err := paillier.NewCiphertext((*znstar.PaillierGroupUnknownOrder)(nil), one)
		require.Error(t, err)
		require.Nil(t, c)
	})

	t.Run("returns an error for a nil value", func(t *testing.T) {
		t.Parallel()
		c, err := paillier.NewCiphertext(group, nil)
		require.Error(t, err)
		require.Nil(t, c)
	})

	t.Run("returns an error for value N (shares factor with N²)", func(t *testing.T) {
		t.Parallel()
		// gcd(N, N²) = N ≠ 1, so N is not a unit in (Z/N²Z)*.
		c, err := paillier.NewCiphertext(group, n)
		require.Error(t, err)
		require.Nil(t, c)
	})

	t.Run("returns an error for value N² (reduces to zero)", func(t *testing.T) {
		t.Parallel()
		// N² mod N² = 0, which is not coprime with N².
		c, err := paillier.NewCiphertext(group, n.Square())
		require.Error(t, err)
		require.Nil(t, c)
	})

	t.Run("returns an error for value 2N (shares factor with N²)", func(t *testing.T) {
		t.Parallel()
		c, err := paillier.NewCiphertext(group, n.Double())
		require.Error(t, err)
		require.Nil(t, c)
	})
}

func TestNewCiphertextFromGroupElement(t *testing.T) {
	t.Parallel()
	key := sampleTestKey(t)

	t.Run("returns a ciphertext for a valid group element", func(t *testing.T) {
		t.Parallel()
		elem, err := key.CiphertextGroup().Random(pcg.NewRandomised())
		require.NoError(t, err)
		c, err := paillier.NewCiphertextFromGroupElement(elem)
		require.NoError(t, err)
		require.NotNil(t, c)
		require.True(t, c.Value().Equal(elem))
	})

	t.Run("returns an error for a nil group element", func(t *testing.T) {
		t.Parallel()
		c, err := paillier.NewCiphertextFromGroupElement((*znstar.PaillierGroupElementUnknownOrder)(nil))
		require.Error(t, err)
		require.Nil(t, c)
	})
}

func TestNewNonce(t *testing.T) {
	t.Parallel()
	key := sampleTestKey(t)
	group := key.CiphertextGroup()
	n := group.N()
	one, err := num.NPlus().FromUint64(1)
	require.NoError(t, err)

	t.Run("returns a nonce for a unit value", func(t *testing.T) {
		t.Parallel()
		nonce, err := paillier.NewNonce(group, one)
		require.NoError(t, err)
		require.NotNil(t, nonce)
		require.True(t, nonce.Group().Modulus().Equal(n))
	})

	t.Run("returns a nonce for value N-1", func(t *testing.T) {
		t.Parallel()
		// N-1 is coprime with N.
		nMinusOne, err := n.Decrement()
		require.NoError(t, err)
		nonce, err := paillier.NewNonce(group, nMinusOne)
		require.NoError(t, err)
		require.NotNil(t, nonce)
	})

	t.Run("returns an error for a nil group", func(t *testing.T) {
		t.Parallel()
		nonce, err := paillier.NewNonce((*znstar.PaillierGroupUnknownOrder)(nil), one)
		require.Error(t, err)
		require.Nil(t, nonce)
	})

	t.Run("returns an error for a nil value", func(t *testing.T) {
		t.Parallel()
		nonce, err := paillier.NewNonce(group, nil)
		require.Error(t, err)
		require.Nil(t, nonce)
	})

	t.Run("returns an error for value N (reduces to zero)", func(t *testing.T) {
		t.Parallel()
		// N mod N = 0; 0 is not a unit in (Z/NZ)*.
		nonce, err := paillier.NewNonce(group, n)
		require.Error(t, err)
		require.Nil(t, nonce)
	})

	t.Run("returns an error for value 2N (reduces to zero)", func(t *testing.T) {
		t.Parallel()
		nonce, err := paillier.NewNonce(group, n.Double())
		require.Error(t, err)
		require.Nil(t, nonce)
	})
}

func TestNewNonceFromGroupElement(t *testing.T) {
	t.Parallel()
	key := sampleTestKey(t)

	t.Run("returns a nonce for a valid group element", func(t *testing.T) {
		t.Parallel()
		elem, err := key.NonceGroup().Random(pcg.NewRandomised())
		require.NoError(t, err)
		nonce, err := paillier.NewNonceFromGroupElement(elem)
		require.NoError(t, err)
		require.NotNil(t, nonce)
		require.True(t, nonce.Value().Equal(elem))
	})

	t.Run("returns an error for a nil group element", func(t *testing.T) {
		t.Parallel()
		nonce, err := paillier.NewNonceFromGroupElement((*znstar.RSAGroupElementUnknownOrder)(nil))
		require.Error(t, err)
		require.Nil(t, nonce)
	})
}

func TestNewPlaintext(t *testing.T) {
	t.Parallel()
	key := sampleTestKey(t)

	t.Run("returns a plaintext for a valid Uint", func(t *testing.T) {
		t.Parallel()
		u, err := key.PlaintextGroup().Random(pcg.NewRandomised())
		require.NoError(t, err)
		p, err := paillier.NewPlaintext(u)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.True(t, p.Value().Equal(u))
	})

	t.Run("returns a plaintext for the zero Uint", func(t *testing.T) {
		t.Parallel()
		zero := key.PlaintextGroup().Zero()
		p, err := paillier.NewPlaintext(zero)
		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("returns an error for a nil Uint", func(t *testing.T) {
		t.Parallel()
		p, err := paillier.NewPlaintext(nil)
		require.Error(t, err)
		require.Nil(t, p)
	})
}

func TestNewPlaintextSymmetric(t *testing.T) {
	t.Parallel()
	key := sampleTestKey(t)
	modulus := key.PlaintextGroup().Modulus()
	// N is odd (product of two odd primes), so half = (N-1)/2 and the valid
	// symmetric range is [-half, half] = {x : 2x ∈ (-N, N)}.
	half := modulus.Rsh(1)
	halfInt, err := num.Z().FromNatPlus(half)
	require.NoError(t, err)
	negHalf := halfInt.Neg()

	t.Run("returns a plaintext for zero", func(t *testing.T) {
		t.Parallel()
		p, err := paillier.NewPlaintextSymmetric(num.Z().FromInt64(0), modulus)
		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("returns a plaintext for the upper boundary half", func(t *testing.T) {
		t.Parallel()
		p, err := paillier.NewPlaintextSymmetric(halfInt, modulus)
		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("returns a plaintext for the lower boundary -half", func(t *testing.T) {
		t.Parallel()
		p, err := paillier.NewPlaintextSymmetric(negHalf, modulus)
		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("returns an error for value half + 1 (just out of range)", func(t *testing.T) {
		t.Parallel()
		v := halfInt.Add(num.Z().FromInt64(1))
		p, err := paillier.NewPlaintextSymmetric(v, modulus)
		require.Error(t, err)
		require.Nil(t, p)
	})

	t.Run("returns an error for value -half - 1 (just out of range)", func(t *testing.T) {
		t.Parallel()
		v := negHalf.Sub(num.Z().FromInt64(1))
		p, err := paillier.NewPlaintextSymmetric(v, modulus)
		require.Error(t, err)
		require.Nil(t, p)
	})

	t.Run("returns an error for value modulus", func(t *testing.T) {
		t.Parallel()
		modInt, err := num.Z().FromNatPlus(modulus)
		require.NoError(t, err)
		p, err := paillier.NewPlaintextSymmetric(modInt, modulus)
		require.Error(t, err)
		require.Nil(t, p)
	})

	t.Run("returns an error for a nil plaintext", func(t *testing.T) {
		t.Parallel()
		p, err := paillier.NewPlaintextSymmetric(nil, modulus)
		require.Error(t, err)
		require.Nil(t, p)
	})

	t.Run("returns an error for a nil modulus", func(t *testing.T) {
		t.Parallel()
		p, err := paillier.NewPlaintextSymmetric(num.Z().FromInt64(0), nil)
		require.Error(t, err)
		require.Nil(t, p)
	})
}
