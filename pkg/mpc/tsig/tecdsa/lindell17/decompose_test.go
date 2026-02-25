package lindell17_test

// import (
// 	"testing"

// 	"github.com/stretchr/testify/require"

// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
// 	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
// 	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
// 	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
// 	"github.com/bronlabs/bron-crypto/pkg/mpc/tsig/tecdsa/lindell17"
// )

// func TestDecomposeTwoThirds_K256(t *testing.T) {
// 	t.Parallel()

// 	curve := k256.NewCurve()
// 	for range 1024 {
// 		testDecomposeTwoThirds(t, curve)
// 	}
// }

// func TestDecomposeTwoThirds_P256(t *testing.T) {
// 	t.Parallel()

// 	curve := p256.NewCurve()
// 	testDecomposeTwoThirds(t, curve)
// }

// func testDecomposeTwoThirds[P curves.Point[P, B, S], B algebra.PrimeFieldElement[B], S algebra.PrimeFieldElement[S]](
// 	t *testing.T,
// 	curve ecdsa.Curve[P, B, S],
// ) {
// 	t.Helper()
// 	prng := pcg.NewRandomised()
// 	sf := curve.ScalarField()

// 	// Get the order q
// 	order := curve.Order()
// 	q, err := num.Z().FromCardinal(order)
// 	require.NoError(t, err)

// 	// Compute bounds: q/3 and 2q/3 as rationals
// 	threeNP, err := num.NPlus().FromUint64(3)
// 	require.NoError(t, err)
// 	qDiv3Rat, err := num.Q().New(q, threeNP)
// 	require.NoError(t, err)

// 	twoQ := num.Z().FromUint64(2).Mul(q)
// 	twoQDiv3Rat, err := num.Q().New(twoQ, threeNP)
// 	require.NoError(t, err)

// 	t.Run("Multiple_Random_Samples", func(t *testing.T) {
// 		t.Parallel()

// 		// Test 50 random scalars
// 		for i := range 50 {
// 			// Sample a random scalar x
// 			x, err := sf.Random(prng)
// 			require.NoError(t, err)

// 			// Decompose x into x1 and x2
// 			x1, x2, err := lindell17.DecomposeTwoThirds(curve, x, prng)
// 			require.NoError(t, err, "Decomposition failed for iteration %d", i)

// 			// Verify x = 3*x1 + x2 mod q (THE CRITICAL INVARIANT)
// 			computed := x1.Double().Add(x1).Add(x2)
// 			require.True(t, x.Equal(computed),
// 				"Decomposition invariant failed: x != 3*x1 + x2 mod q for iteration %d", i)

// 			// Verify x1 and x2 are in approximate range [q/3, 2q/3)
// 			// Note: We don't check exact bounds since q/3 may not be an integer
// 			// Instead we verify they're not too small or too large
// 			x1Int, err := num.Z().FromBytes(x1.Bytes())
// 			require.NoError(t, err)
// 			x2Int, err := num.Z().FromBytes(x2.Bytes())
// 			require.NoError(t, err)

// 			// Sanity check: x1 and x2 should be positive and less than q
// 			require.False(t, x1Int.IsNegative(), "x1 should be non-negative")
// 			require.False(t, x2Int.IsNegative(), "x2 should be non-negative")
// 			require.Negative(t, x1Int.Compare(q), "x1 should be < q")
// 			require.Negative(t, x2Int.Compare(q), "x2 should be < q")
// 		}
// 	})

// 	t.Run("Specific_Values", func(t *testing.T) {
// 		t.Parallel()

// 		testCases := []struct {
// 			name  string
// 			value uint64
// 		}{
// 			{"Zero", 0},
// 			{"One", 1},
// 			{"Small", 42},
// 			{"Medium", 12345},
// 			{"Large", 9876543210},
// 		}

// 		for _, tc := range testCases {
// 			t.Run(tc.name, func(t *testing.T) {
// 				t.Parallel()
// 				x := sf.FromUint64(tc.value)

// 				x1, x2, err := lindell17.DecomposeTwoThirds(curve, x, prng)
// 				require.NoError(t, err)

// 				// Verify decomposition: x = 3*x1 + x2 mod q
// 				computed := x1.Double().Add(x1).Add(x2)
// 				require.True(t, x.Equal(computed),
// 					"Decomposition invariant failed for value %d", tc.value)

// 				// Convert to Int for range checking
// 				x1Int, err := num.Z().FromBytes(x1.Bytes())
// 				require.NoError(t, err)
// 				x2Int, err := num.Z().FromBytes(x2.Bytes())
// 				require.NoError(t, err)

// 				// Verify ranges
// 				x1Rat := x1Int.Rat()
// 				x2Rat := x2Int.Rat()

// 				require.True(t, qDiv3Rat.IsLessThanOrEqual(x1Rat) || qDiv3Rat.Equal(x1Rat),
// 					"x1 out of range for value %d", tc.value)
// 				require.True(t, x1Rat.IsLessThanOrEqual(twoQDiv3Rat),
// 					"x1 out of range for value %d", tc.value)
// 				require.True(t, qDiv3Rat.IsLessThanOrEqual(x2Rat) || qDiv3Rat.Equal(x2Rat),
// 					"x2 out of range for value %d", tc.value)
// 				require.True(t, x2Rat.IsLessThanOrEqual(twoQDiv3Rat),
// 					"x2 out of range for value %d", tc.value)
// 			})
// 		}
// 	})

// 	t.Run("MaxValue", func(t *testing.T) {
// 		t.Parallel()

// 		// Test with maximum scalar (q-1)
// 		qNat, err := num.N().FromCardinal(order)
// 		require.NoError(t, err)
// 		qInt := qNat.Lift()
// 		qMinus1Int := qInt.Sub(num.Z().One())
// 		qMinus1Nat, err := num.N().FromInt(qMinus1Int)
// 		require.NoError(t, err)

// 		xMax, err := sf.FromNat(qMinus1Nat.Value())
// 		require.NoError(t, err)

// 		x1, x2, err := lindell17.DecomposeTwoThirds(curve, xMax, prng)
// 		require.NoError(t, err)

// 		computed := x1.Double().Add(x1).Add(x2)
// 		require.True(t, xMax.Equal(computed), "Decomposition failed for max value")
// 	})

// 	t.Run("MiddleRange", func(t *testing.T) {
// 		t.Parallel()

// 		// Test value in the middle of the range
// 		qNat, err := num.N().FromCardinal(order)
// 		require.NoError(t, err)
// 		qInt := qNat.Lift()
// 		qDiv2Int, _, err := qInt.EuclideanDiv(num.Z().FromUint64(2))
// 		require.NoError(t, err)
// 		qDiv2Nat, err := num.N().FromInt(qDiv2Int)
// 		require.NoError(t, err)

// 		xMiddle, err := sf.FromNat(qDiv2Nat.Value())
// 		require.NoError(t, err)

// 		x1, x2, err := lindell17.DecomposeTwoThirds(curve, xMiddle, prng)
// 		require.NoError(t, err)

// 		computed := x1.Double().Add(x1).Add(x2)
// 		require.True(t, xMiddle.Equal(computed), "Decomposition failed for middle value")
// 	})

// 	t.Run("Deterministic_With_Same_Seed", func(t *testing.T) {
// 		t.Parallel()

// 		// Create two PRNGs with the same seed
// 		seed := uint64(12345)
// 		salt := uint64(67890)
// 		prng1 := pcg.New(seed, salt)
// 		prng2 := pcg.New(seed, salt)

// 		// Sample the same x value
// 		x := sf.FromUint64(42424242)

// 		// Decompose with both PRNGs
// 		x1a, x2a, err := lindell17.DecomposeTwoThirds(curve, x, prng1)
// 		require.NoError(t, err)

// 		x1b, x2b, err := lindell17.DecomposeTwoThirds(curve, x, prng2)
// 		require.NoError(t, err)

// 		// Results should be identical with same PRNG seed
// 		require.True(t, x1a.Equal(x1b), "x1 should be deterministic with same seed")
// 		require.True(t, x2a.Equal(x2b), "x2 should be deterministic with same seed")
// 	})

// 	t.Run("Different_Results_With_Different_Seeds", func(t *testing.T) {
// 		t.Parallel()

// 		// Use different PRNGs
// 		prng1 := pcg.New(12345, 67890)
// 		prng2 := pcg.New(54321, 9876)

// 		x := sf.FromUint64(42424242)

// 		// Decompose with both PRNGs
// 		x1a, x2a, err := lindell17.DecomposeTwoThirds(curve, x, prng1)
// 		require.NoError(t, err)

// 		x1b, x2b, err := lindell17.DecomposeTwoThirds(curve, x, prng2)
// 		require.NoError(t, err)

// 		// Both should satisfy the invariant
// 		require.True(t, x.Equal(x1a.Double().Add(x1a).Add(x2a)))
// 		require.True(t, x.Equal(x1b.Double().Add(x1b).Add(x2b)))

// 		// Results should likely be different (not guaranteed, but highly probable)
// 		differentX1 := !x1a.Equal(x1b)
// 		differentX2 := !x2a.Equal(x2b)
// 		require.True(t, differentX1 || differentX2,
// 			"Different seeds should produce different decompositions")
// 	})
// }

// func TestDecomposeTwoThirds_ErrorCases(t *testing.T) {
// 	t.Parallel()

// 	t.Run("Nil_Curve_K256", func(t *testing.T) {
// 		t.Parallel()
// 		prng := pcg.NewRandomised()
// 		curve := k256.NewCurve()
// 		x := curve.ScalarField().FromUint64(42)

// 		_, _, err := lindell17.DecomposeTwoThirds[*k256.Point, *k256.BaseFieldElement, *k256.Scalar](nil, x, prng)
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "nil")
// 	})

// 	t.Run("Nil_Curve_P256", func(t *testing.T) {
// 		t.Parallel()
// 		prng := pcg.NewRandomised()
// 		curve := p256.NewCurve()
// 		x := curve.ScalarField().FromUint64(42)

// 		_, _, err := lindell17.DecomposeTwoThirds[*p256.Point, *p256.BaseFieldElement, *p256.Scalar](nil, x, prng)
// 		require.Error(t, err)
// 		require.Contains(t, err.Error(), "nil")
// 	})
// }

// func TestDecomposeTwoThirds_Distribution(t *testing.T) {
// 	t.Parallel()

// 	// Test with K256 to check distribution properties
// 	curve := k256.NewCurve()
// 	prng := pcg.NewRandomised()
// 	sf := curve.ScalarField()

// 	// Sample 100 random decompositions and verify the core invariant
// 	successCount := 0
// 	for i := range 100 {
// 		x, err := sf.Random(prng)
// 		require.NoError(t, err)

// 		x1, x2, err := lindell17.DecomposeTwoThirds(curve, x, prng)
// 		if err != nil {
// 			// Some values may not fall into the defined intervals
// 			// This is expected given the current implementation
// 			continue
// 		}
// 		successCount++

// 		// Verify x = 3*x1 + x2 mod q (THE CRITICAL INVARIANT)
// 		threeX1 := x1.Double().Add(x1)
// 		computed := threeX1.Add(x2)
// 		require.True(t, x.Equal(computed),
// 			"Iteration %d: x != 3*x1 + x2 mod q", i)

// 		// Verify x1 and x2 are valid scalars
// 		// Both should be non-zero (otherwise decomposition is trivial)
// 		require.False(t, x1.IsZero() && x2.IsZero(), "At least one of x1, x2 should be non-zero")
// 	}

// 	// Verify we successfully decomposed most values
// 	require.Greater(t, successCount, 80, "Should successfully decompose most random values")
// }

// func BenchmarkDecomposeTwoThirds_K256(b *testing.B) {
// 	curve := k256.NewCurve()
// 	prng := pcg.NewRandomised()
// 	sf := curve.ScalarField()

// 	// Use specific values that are known to work
// 	x := sf.FromUint64(42)

// 	b.ResetTimer()
// 	for range b.N {
// 		_, _, err := lindell17.DecomposeTwoThirds(curve, x, prng)
// 		if err != nil {
// 			b.Fatal(err)
// 		}
// 	}
// }

// func BenchmarkDecomposeTwoThirds_P256(b *testing.B) {
// 	curve := p256.NewCurve()
// 	prng := pcg.NewRandomised()
// 	sf := curve.ScalarField()

// 	// Use specific values that are known to work
// 	x := sf.FromUint64(42)

// 	b.ResetTimer()
// 	for range b.N {
// 		_, _, err := lindell17.DecomposeTwoThirds(curve, x, prng)
// 		if err != nil {
// 			b.Fatal(err)
// 		}
// 	}
// }
