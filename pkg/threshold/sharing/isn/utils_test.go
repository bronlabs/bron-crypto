package isn_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn"
)

func sumToSecret_HappyPaths[E algebra.PrimeFieldElement[E]](t *testing.T, group algebra.PrimeField[E], secret uint64, numberOfShares int) (sum E) {
	t.Helper()
	s := isn.NewSecret(group.FromUint64(secret))
	shares, err := isn.SumToSecret(s, group.Random, pcg.NewRandomised(), numberOfShares)
	require.NoError(t, err)
	require.Len(t, shares, numberOfShares)

	// Sum should equal secret
	sum = group.Zero()
	for _, share := range shares {
		sum = sum.Add(share)
	}
	require.True(t, sum.Equal(s.Value()))
	return sum
}

func TestSumToSecret_ValidCases(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	t.Run("single share (l=1)", func(t *testing.T) {
		t.Parallel()
		sumToSecret_HappyPaths(t, group, 42, 1)
	})

	t.Run("two shares (l=2)", func(t *testing.T) {
		t.Parallel()
		sumToSecret_HappyPaths(t, group, 100, 2)
	})

	t.Run("three shares (l=3)", func(t *testing.T) {
		t.Parallel()
		sumToSecret_HappyPaths(t, group, 1000, 3)
	})

	t.Run("many shares (l=10)", func(t *testing.T) {
		t.Parallel()
		sumToSecret_HappyPaths(t, group, 9999, 10)
	})

	t.Run("zero secret", func(t *testing.T) {
		t.Parallel()
		sum := sumToSecret_HappyPaths(t, group, 0, 5)
		require.True(t, sum.IsZero())
	})

	t.Run("large secret value", func(t *testing.T) {
		t.Parallel()
		sumToSecret_HappyPaths(t, group, 0xFFFFFFFFFFFFFFFF, 7)
	})
}

func TestSumToSecret_Randomness(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()
	secret := isn.NewSecret(group.FromUint64(777))

	t.Run("different outputs for different prng states", func(t *testing.T) {
		t.Parallel()
		// Generate two sets of shares with different randomness
		shares1, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), 5)
		require.NoError(t, err)

		shares2, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), 5)
		require.NoError(t, err)

		// Shares should be different (extremely unlikely to be equal with random prng)
		allEqual := true
		for i := range shares1 {
			if !shares1[i].Equal(shares2[i]) {
				allEqual = false
				break
			}
		}
		require.False(t, allEqual, "shares from different random states should differ")
	})

	t.Run("deterministic with same prng seed", func(t *testing.T) {
		t.Parallel()
		seed1, seed2 := uint64(12345), uint64(67890)

		shares1, err := isn.SumToSecret(secret, group.Random, pcg.New(seed1, seed2), 5)
		require.NoError(t, err)

		shares2, err := isn.SumToSecret(secret, group.Random, pcg.New(seed1, seed2), 5)
		require.NoError(t, err)

		// With same seed, outputs should be identical
		require.Len(t, shares2, len(shares1))
		for i := range shares1 {
			require.True(t, shares1[i].Equal(shares2[i]))
		}
	})

	t.Run("first l-1 shares are random", func(t *testing.T) {
		t.Parallel()
		// For l > 1, the first l-1 shares should be random
		shares, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), 5)
		require.NoError(t, err)

		// Check that not all first 4 shares are zero or identical
		allZero := true
		allSame := true
		for i := range 4 {
			if !shares[i].IsZero() {
				allZero = false
			}
			if i > 0 && !shares[i].Equal(shares[0]) {
				allSame = false
			}
		}
		require.False(t, allZero, "random shares should not all be zero")
		require.False(t, allSame, "random shares should not all be identical")
	})
}

func TestSumToSecret_ErrorCases(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()
	secret := isn.NewSecret(group.FromUint64(42))

	t.Run("nil secret", func(t *testing.T) {
		t.Parallel()
		shares, err := isn.SumToSecret(nil, group.Random, pcg.NewRandomised(), 3)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrIsNil)
		require.Nil(t, shares)
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		shares, err := isn.SumToSecret(secret, group.Random, nil, 3)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrIsNil)
		require.Nil(t, shares)
	})

	t.Run("zero shares (l=0)", func(t *testing.T) {
		t.Parallel()
		shares, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), 0)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrFailed)
		require.Nil(t, shares)
	})

	t.Run("negative shares (l=-1)", func(t *testing.T) {
		t.Parallel()
		shares, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), -1)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrFailed)
		require.Nil(t, shares)
	})

	t.Run("short prng", func(t *testing.T) {
		t.Parallel()
		// For l > 1, we need to sample l-1 random elements
		// A reader with only 1 byte will fail
		shares, err := isn.SumToSecret(secret, group.Random, bytes.NewReader([]byte{1}), 3)
		require.Error(t, err)
		require.Nil(t, shares)
	})
}

func sumToSecret_DifferentGroups[E algebra.PrimeFieldElement[E]](t *testing.T, group algebra.PrimeField[E]) {
	t.Helper()
	secret := isn.NewSecret(group.FromUint64(888))

	shares, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), 6)
	require.NoError(t, err)
	require.Len(t, shares, 6)

	// Sum should equal secret
	sum := group.Zero()
	for _, share := range shares {
		sum = sum.Add(share)
	}
	require.True(t, sum.Equal(secret.Value()))
}

func TestSumToSecret_DifferentGroups(t *testing.T) {
	t.Parallel()

	t.Run("BLS12-381 scalar field", func(t *testing.T) {
		t.Parallel()
		sumToSecret_DifferentGroups(t, bls12381.NewScalarField())
	})

	t.Run("k256 scalar field with group operations", func(t *testing.T) {
		t.Parallel()
		sumToSecret_DifferentGroups(t, k256.NewScalarField())
	})
}

func TestSumToSecret_Properties(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	t.Run("shares sum correctly for multiple secrets", func(t *testing.T) {
		t.Parallel()
		// Test with several different secrets to ensure correctness
		testSecrets := []uint64{0, 1, 42, 100, 999, 0xFFFF}

		for _, val := range testSecrets {
			secret := isn.NewSecret(group.FromUint64(val))
			shares, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), 5)
			require.NoError(t, err)

			sum := group.Zero()
			for _, share := range shares {
				sum = sum.Add(share)
			}
			require.True(t, sum.Equal(secret.Value()),
				"sum of shares should equal secret for value %d", val)
		}
	})

	t.Run("varying l produces valid sharings", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(777))

		// Test various values of l
		for l := 1; l <= 20; l++ {
			shares, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), l)
			require.NoError(t, err)
			require.Len(t, shares, l)

			// Verify sum
			sum := group.Zero()
			for _, share := range shares {
				sum = sum.Add(share)
			}
			require.True(t, sum.Equal(secret.Value()),
				"sum should equal secret for l=%d", l)
		}
	})
}

func TestSumToSecret_AdditiveHomomorphism(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	t.Run("sum of sharings equals sharing of sum", func(t *testing.T) {
		t.Parallel()
		secret1 := isn.NewSecret(group.FromUint64(100))
		secret2 := isn.NewSecret(group.FromUint64(200))

		seed1, seed2 := uint64(42), uint64(1337)

		shares1, err := isn.SumToSecret(secret1, group.Random, pcg.New(seed1, seed2), 5)
		require.NoError(t, err)

		shares2, err := isn.SumToSecret(secret2, group.Random, pcg.New(seed1, seed2), 5)
		require.NoError(t, err)

		// Add the shares component-wise
		combinedShares := make([]*k256.Scalar, 5)
		for i := range shares1 {
			combinedShares[i] = shares1[i].Add(shares2[i])
		}

		// Sum of combined shares
		sum := group.Zero()
		for _, share := range combinedShares {
			sum = sum.Add(share)
		}

		// Should equal secret1 + secret2
		expectedSecret := secret1.Value().Add(secret2.Value())
		require.True(t, sum.Equal(expectedSecret))
	})
}

func TestSumToSecret_EdgeCaseValues(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	t.Run("one element", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.One())
		shares, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), 3)
		require.NoError(t, err)

		sum := group.Zero()
		for _, share := range shares {
			sum = sum.Add(share)
		}
		require.True(t, sum.Equal(group.One()))
	})

	t.Run("field modulus minus one", func(t *testing.T) {
		t.Parallel()
		// -1 in the field
		minusOne := group.Zero().Sub(group.One())
		secret := isn.NewSecret(minusOne)
		shares, err := isn.SumToSecret(secret, group.Random, pcg.NewRandomised(), 4)
		require.NoError(t, err)

		sum := group.Zero()
		for _, share := range shares {
			sum = sum.Add(share)
		}
		require.True(t, sum.Equal(secret.Value()))
	})
}
