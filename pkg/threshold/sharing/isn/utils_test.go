package isn_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/isn"
)

func TestSumToSecret_ValidCases(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()

	t.Run("single share (l=1)", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(42))
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 1)
		require.NoError(t, err)
		require.Len(t, shares, 1)

		// Single share should equal the secret
		require.True(t, shares[0].Equal(secret.Value()))
	})

	t.Run("two shares (l=2)", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(100))
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 2)
		require.NoError(t, err)
		require.Len(t, shares, 2)

		// Sum should equal secret
		sum := shares[0].Add(shares[1])
		require.True(t, sum.Equal(secret.Value()))
	})

	t.Run("three shares (l=3)", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(1000))
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 3)
		require.NoError(t, err)
		require.Len(t, shares, 3)

		// Sum should equal secret
		sum := shares[0].Add(shares[1]).Add(shares[2])
		require.True(t, sum.Equal(secret.Value()))
	})

	t.Run("many shares (l=10)", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(9999))
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 10)
		require.NoError(t, err)
		require.Len(t, shares, 10)

		// Sum should equal secret
		sum := group.Zero()
		for _, share := range shares {
			sum = sum.Add(share)
		}
		require.True(t, sum.Equal(secret.Value()))
	})

	t.Run("zero secret", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.Zero())
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 5)
		require.NoError(t, err)
		require.Len(t, shares, 5)

		// Sum should equal zero
		sum := group.Zero()
		for _, share := range shares {
			sum = sum.Add(share)
		}
		require.True(t, sum.Equal(secret.Value()))
		require.True(t, sum.IsZero())
	})

	t.Run("large secret value", func(t *testing.T) {
		t.Parallel()
		// Use a large value close to field order
		secret := isn.NewSecret(group.FromUint64(0xFFFFFFFFFFFFFFFF))
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 7)
		require.NoError(t, err)
		require.Len(t, shares, 7)

		// Sum should equal secret
		sum := group.Zero()
		for _, share := range shares {
			sum = sum.Add(share)
		}
		require.True(t, sum.Equal(secret.Value()))
	})
}

func TestSumToSecret_Randomness(t *testing.T) {
	t.Parallel()

	group := k256.NewScalarField()
	secret := isn.NewSecret(group.FromUint64(777))

	t.Run("different outputs for different prng states", func(t *testing.T) {
		t.Parallel()
		// Generate two sets of shares with different randomness
		shares1, err := isn.SumToSecret(secret, pcg.NewRandomised(), 5)
		require.NoError(t, err)

		shares2, err := isn.SumToSecret(secret, pcg.NewRandomised(), 5)
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

		shares1, err := isn.SumToSecret(secret, pcg.New(seed1, seed2), 5)
		require.NoError(t, err)

		shares2, err := isn.SumToSecret(secret, pcg.New(seed1, seed2), 5)
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
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 5)
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
		shares, err := isn.SumToSecret[*k256.Scalar](nil, pcg.NewRandomised(), 3)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrIsNil)
		require.Nil(t, shares)
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		shares, err := isn.SumToSecret(secret, nil, 3)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrIsNil)
		require.Nil(t, shares)
	})

	t.Run("zero shares (l=0)", func(t *testing.T) {
		t.Parallel()
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 0)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrFailed)
		require.Nil(t, shares)
	})

	t.Run("negative shares (l=-1)", func(t *testing.T) {
		t.Parallel()
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), -1)
		require.Error(t, err)
		require.ErrorIs(t, err, isn.ErrFailed)
		require.Nil(t, shares)
	})

	t.Run("short prng", func(t *testing.T) {
		t.Parallel()
		// For l > 1, we need to sample l-1 random elements
		// A reader with only 1 byte will fail
		shares, err := isn.SumToSecret(secret, bytes.NewReader([]byte{1}), 3)
		require.Error(t, err)
		require.Nil(t, shares)
	})
}

func TestSumToSecret_DifferentGroups(t *testing.T) {
	t.Parallel()

	t.Run("BLS12-381 scalar field", func(t *testing.T) {
		t.Parallel()
		group := bls12381.NewScalarField()
		secret := isn.NewSecret(group.FromUint64(888))

		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 6)
		require.NoError(t, err)
		require.Len(t, shares, 6)

		// Sum should equal secret
		sum := group.Zero()
		for _, share := range shares {
			sum = sum.Add(share)
		}
		require.True(t, sum.Equal(secret.Value()))
	})

	t.Run("k256 scalar field with group operations", func(t *testing.T) {
		t.Parallel()
		group := k256.NewScalarField()
		secret := isn.NewSecret(group.FromUint64(12345))

		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 4)
		require.NoError(t, err)
		require.Len(t, shares, 4)

		// Verify using Op instead of Add
		sum := shares[0]
		for i := 1; i < len(shares); i++ {
			sum = sum.Op(shares[i])
		}
		require.True(t, sum.Equal(secret.Value()))
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
			shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 5)
			require.NoError(t, err)

			sum := group.Zero()
			for _, share := range shares {
				sum = sum.Add(share)
			}
			require.True(t, sum.Equal(secret.Value()),
				"sum of shares should equal secret for value %d", val)
		}
	})

	t.Run("last share is deterministic given first l-1 shares", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(500))

		// Generate shares with deterministic PRNG
		seed1, seed2 := uint64(111), uint64(222)
		shares1, err := isn.SumToSecret(secret, pcg.New(seed1, seed2), 4)
		require.NoError(t, err)

		// Generate again with same seed
		shares2, err := isn.SumToSecret(secret, pcg.New(seed1, seed2), 4)
		require.NoError(t, err)

		// Last share should be identical (it's computed deterministically)
		require.True(t, shares1[3].Equal(shares2[3]))

		// Verify it's the correct last share
		partialSum := group.Zero()
		for i := range 3 {
			partialSum = partialSum.Add(shares1[i])
		}
		expectedLast := secret.Value().Add(partialSum.Neg())
		require.True(t, shares1[3].Equal(expectedLast))
	})

	t.Run("varying l produces valid sharings", func(t *testing.T) {
		t.Parallel()
		secret := isn.NewSecret(group.FromUint64(777))

		// Test various values of l
		for l := 1; l <= 20; l++ {
			shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), l)
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

		// Use same PRNG seed for both to enable comparison
		seed1, seed2 := uint64(42), uint64(1337)

		shares1, err := isn.SumToSecret(secret1, pcg.New(seed1, seed2), 5)
		require.NoError(t, err)

		shares2, err := isn.SumToSecret(secret2, pcg.New(seed1, seed2), 5)
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
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 3)
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
		secret := isn.NewSecret(group.Zero().Neg())
		shares, err := isn.SumToSecret(secret, pcg.NewRandomised(), 4)
		require.NoError(t, err)

		sum := group.Zero()
		for _, share := range shares {
			sum = sum.Add(share)
		}
		require.True(t, sum.Equal(secret.Value()))
	})
}
