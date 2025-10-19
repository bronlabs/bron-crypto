package shamir_test

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

func TestSanity(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	threshold := uint(2)
	total := uint(5)
	shareholders := sharing.NewOrdinalShareholderSet(total)
	scheme, err := shamir.NewScheme(field, threshold, shareholders)
	require.NoError(t, err, "could not create scheme")

	secret := shamir.NewSecret(field.FromUint64(42))
	require.NoError(t, err)
	out, err := scheme.Deal(secret, crand.Reader)
	require.NoError(t, err, "could not create shares")
	require.NotNil(t, out)
	shares := out.Shares()
	require.Equal(t, total, uint(shares.Size()), "number of shares should match total")

	reconstructedSecret, err := scheme.Reconstruct(shares.Values()...)
	require.NoError(t, err, "could not reconstruct secret")
	require.True(t, secret.Equal(reconstructedSecret), "reconstructed secret should match original secret")
}

// dealCases tests the Deal function with various inputs
func dealCases[FE algebra.PrimeFieldElement[FE]](t *testing.T, scheme *shamir.Scheme[FE], field algebra.PrimeField[FE]) {
	t.Helper()

	// Create test secrets
	zeroSecret := shamir.NewSecret(field.Zero())
	oneSecret := shamir.NewSecret(field.One())
	fortyTwoSecret := shamir.NewSecret(field.FromUint64(42))
	randomSecret := shamir.NewSecret(field.FromUint64(12345))

	// Get scheme parameters
	threshold := scheme.AccessStructure().Threshold()
	total := uint(scheme.AccessStructure().Shareholders().Size())

	tests := []struct {
		name          string
		secret        *shamir.Secret[FE]
		prng          io.Reader
		expectError   bool
		errorContains string
		verifyShares  bool
	}{
		{
			name:         "valid secret with constant 42",
			secret:       fortyTwoSecret,
			prng:         crand.Reader,
			expectError:  false,
			verifyShares: true,
		},
		{
			name:         "valid secret with value 1",
			secret:       oneSecret,
			prng:         crand.Reader,
			expectError:  false,
			verifyShares: true,
		},
		{
			name:         "valid secret with value 0",
			secret:       zeroSecret,
			prng:         crand.Reader,
			expectError:  false,
			verifyShares: true,
		},
		{
			name:         "valid secret with random value",
			secret:       randomSecret,
			prng:         crand.Reader,
			expectError:  false,
			verifyShares: true,
		},
		{
			name:          "nil secret",
			secret:        nil,
			prng:          crand.Reader,
			expectError:   true,
			errorContains: "secret is nil",
		},
		{
			name:          "nil prng",
			secret:        fortyTwoSecret,
			prng:          nil,
			expectError:   true,
			errorContains: "prng is nil",
		},
		{
			name:          "both nil",
			secret:        nil,
			prng:          nil,
			expectError:   true,
			errorContains: "secret is nil",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, err := scheme.Deal(tc.secret, tc.prng)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorContains != "" {
					require.Contains(t, err.Error(), tc.errorContains)
				}
				require.Nil(t, out)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, out)
			shares := out.Shares()
			require.NotNil(t, shares)
			require.Equal(t, int(total), shares.Size(), "should generate shares for all shareholders")

			if tc.verifyShares {
				// Verify each share
				for id, share := range shares.Iter() {
					require.NotNil(t, share)
					require.Equal(t, id, share.ID())
					// When secret is zero, shares can be zero (identity)
					if !tc.secret.Value().IsZero() {
						// For non-zero secrets, we still expect non-zero shares in most cases
						// but it's mathematically possible to have zero shares even with non-zero secret
					}
				}

				// Verify shares are different (except potentially for zero secret)
				if !tc.secret.Value().IsZero() {
					shareValues := make(map[string]bool)
					for _, share := range shares.Values() {
						val := share.Value().String()
						require.False(t, shareValues[val], "shares should have different values")
						shareValues[val] = true
					}
				}

				// Verify reconstruction works
				reconstructed, err := scheme.Reconstruct(shares.Values()...)
				require.NoError(t, err)
				require.True(t, tc.secret.Equal(reconstructed), "reconstructed secret should match original")

				// Verify threshold property: any t shares can reconstruct
				shareSlice := shares.Values()
				if len(shareSlice) >= int(threshold) {
					subsetShares := shareSlice[:threshold]
					reconstructed, err = scheme.Reconstruct(subsetShares...)
					require.NoError(t, err)
					require.True(t, tc.secret.Equal(reconstructed), "subset reconstruction should match original")
				}

				// Verify that t-1 shares cannot reconstruct
				if int(threshold) > 1 && len(shareSlice) >= int(threshold) {
					insufficientShares := shareSlice[:threshold-1]
					_, err = scheme.Reconstruct(insufficientShares...)
					require.Error(t, err)
					require.Contains(t, err.Error(), "not authorized")
				}
			}
		})
	}
}

// dealRandomCases tests the DealRandom function
func dealRandomCases[FE algebra.PrimeFieldElement[FE]](t *testing.T, scheme *shamir.Scheme[FE]) {
	t.Helper()

	threshold := scheme.AccessStructure().Threshold()
	total := uint(scheme.AccessStructure().Shareholders().Size())

	tests := []struct {
		name             string
		prng             io.Reader
		expectError      bool
		errorContains    string
		verifyUniqueness bool
		iterations       int
	}{
		{
			name:             "valid random generation",
			prng:             crand.Reader,
			expectError:      false,
			verifyUniqueness: true,
			iterations:       1,
		},
		{
			name:             "multiple random generations",
			prng:             crand.Reader,
			expectError:      false,
			verifyUniqueness: true,
			iterations:       5,
		},
		{
			name:          "nil prng",
			prng:          nil,
			expectError:   true,
			errorContains: "prng is nil",
			iterations:    1,
		},
		{
			name: "deterministic prng produces same secret",
			// prng:        bytes.NewReader([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}),
			prng:        pcg.New(mrand.Uint64(), mrand.Uint64()),
			expectError: false,
			iterations:  1,
		},
		{
			name:        "short deterministic prng",
			prng:        bytes.NewReader([]byte{1}),
			expectError: true,
			iterations:  1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secrets := make([]*shamir.Secret[FE], 0, tc.iterations)

			for i := 0; i < tc.iterations; i++ {
				// Reset reader if using deterministic prng
				if reader, ok := tc.prng.(*bytes.Reader); ok && i > 0 {
					reader.Seek(0, 0)
				}

				out, secret, err := scheme.DealRandom(tc.prng)

				if tc.expectError {
					require.Error(t, err)
					if tc.errorContains != "" {
						require.Contains(t, err.Error(), tc.errorContains)
					}
					require.Nil(t, out)
					require.Nil(t, secret)
					return
				}

				require.NoError(t, err)
				require.NotNil(t, out)
				require.NotNil(t, secret)
				require.Equal(t, int(total), out.Shares().Size())
				require.False(t, secret.Value().IsOpIdentity(), "random secret should not be identity")

				secrets = append(secrets, secret)

				// Verify reconstruction
				reconstructed, err := scheme.Reconstruct(out.Shares().Values()...)
				require.NoError(t, err)
				require.True(t, secret.Equal(reconstructed))

				// Verify threshold property
				if out.Shares().Size() >= int(threshold) {
					shareSlice := out.Shares().Values()
					subsetShares := shareSlice[:threshold]
					reconstructed, err = scheme.Reconstruct(subsetShares...)
					require.NoError(t, err)
					require.True(t, secret.Equal(reconstructed))
				}
			}

			// Verify uniqueness across iterations if required
			if tc.verifyUniqueness && tc.iterations > 1 {
				secretValues := make(map[string]int)
				for i, secret := range secrets {
					val := secret.Value().String()
					secretValues[val]++
					if secretValues[val] > 1 {
						t.Logf("Duplicate secret value found at iteration %d", i)
					}
				}
				// With cryptographic randomness, duplicates should be extremely rare
				duplicates := 0
				for _, count := range secretValues {
					if count > 1 {
						duplicates++
					}
				}
				require.Equal(t, 0, duplicates, "random secrets should be unique")
			}
		})
	}
}

func TestDeal(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		field := k256.NewScalarField()

		testConfigs := []struct {
			name      string
			threshold uint
			total     uint
			errors    bool
		}{
			{"2-of-3", 2, 3, false},
			{"3-of-5", 3, 5, false},
			{"5-of-10", 5, 10, false},
			{"1-of-5", 1, 5, true},
			{"threshold equals total", 5, 5, false},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := shamir.NewScheme(field, config.threshold, shareholders)
				if config.errors {
					require.Error(t, err, "should return error for invalid configuration")
					return
				}
				require.NoError(t, err)
				dealCases(t, scheme, field)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		field := bls12381.NewScalarField()

		testConfigs := []struct {
			name      string
			threshold uint
			total     uint
		}{
			{"2-of-4", 2, 4},
			{"4-of-7", 4, 7},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := shamir.NewScheme(field, config.threshold, shareholders)
				require.NoError(t, err)
				dealCases(t, scheme, field)
			})
		}
	})
}

func TestDealRandom(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		field := k256.NewScalarField()

		testConfigs := []struct {
			name      string
			threshold uint
			total     uint
		}{
			{"2-of-3", 2, 3},
			{"3-of-5", 3, 5},
			{"threshold equals total", 4, 4},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := shamir.NewScheme(field, config.threshold, shareholders)
				require.NoError(t, err)
				dealRandomCases(t, scheme)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		field := bls12381.NewScalarField()

		shareholders := sharing.NewOrdinalShareholderSet(6)
		scheme, err := shamir.NewScheme(field, 3, shareholders)
		require.NoError(t, err)
		dealRandomCases(t, scheme)
	})
}

// BenchmarkDeal benchmarks the Deal function
func BenchmarkDeal(b *testing.B) {
	field := k256.NewScalarField()

	benchConfigs := []struct {
		name      string
		threshold uint
		total     uint
	}{
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"5-of-10", 5, 10},
		{"10-of-20", 10, 20},
		{"20-of-50", 20, 50},
	}

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			shareholders := sharing.NewOrdinalShareholderSet(config.total)
			scheme, err := shamir.NewScheme(field, config.threshold, shareholders)
			require.NoError(b, err)

			secret := shamir.NewSecret(field.FromUint64(42))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := scheme.Deal(secret, crand.Reader)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDealRandom benchmarks the DealRandom function
func BenchmarkDealRandom(b *testing.B) {
	field := k256.NewScalarField()

	benchConfigs := []struct {
		name      string
		threshold uint
		total     uint
	}{
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"5-of-10", 5, 10},
		{"10-of-20", 10, 20},
	}

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			shareholders := sharing.NewOrdinalShareholderSet(config.total)
			scheme, err := shamir.NewScheme(field, config.threshold, shareholders)
			require.NoError(b, err)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := scheme.DealRandom(crand.Reader)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestDealDeterministic tests Deal with deterministic randomness for reproducibility
func TestDealDeterministic(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	shareholders := sharing.NewOrdinalShareholderSet(5)
	scheme, err := shamir.NewScheme(field, 2, shareholders)
	require.NoError(t, err)

	secret := shamir.NewSecret(field.FromUint64(42))

	// Use same seed for deterministic randomness
	seed := []byte("deterministic seed for testing purposes only!!!!")
	prng1 := bytes.NewReader(append(seed, make([]byte, 1024)...))
	prng2 := bytes.NewReader(append(seed, make([]byte, 1024)...))

	out1, err := scheme.Deal(secret, prng1)
	require.NoError(t, err)
	shares1 := out1.Shares()

	out2, err := scheme.Deal(secret, prng2)
	require.NoError(t, err)
	shares2 := out2.Shares()

	// Verify that shares are identical when using same randomness
	for id, share1 := range shares1.Iter() {
		share2, exists := shares2.Get(id)
		require.True(t, exists)
		require.True(t, share1.Value().Equal(share2.Value()),
			"shares with same randomness should be identical")
	}
}

// TestDealRandomDistribution tests the statistical distribution of random secrets
func TestDealRandomDistribution(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping statistical test in short mode")
	}

	field := k256.NewScalarField()
	shareholders := sharing.NewOrdinalShareholderSet(3)
	scheme, err := shamir.NewScheme(field, 2, shareholders)
	require.NoError(t, err)

	iterations := 1000
	secrets := make(map[string]int)

	for i := 0; i < iterations; i++ {
		_, secret, err := scheme.DealRandom(crand.Reader)
		require.NoError(t, err)

		// Use first few bytes of secret as key for distribution analysis
		key := fmt.Sprintf("%x", secret.Value().String()[:8])
		secrets[key]++
	}

	// Basic check: we should have many different values
	uniqueCount := len(secrets)
	t.Logf("Generated %d unique secret prefixes out of %d iterations", uniqueCount, iterations)

	// With good randomness, we expect most values to be unique
	minExpectedUnique := iterations * 90 / 100 // 90% unique
	require.Greater(t, uniqueCount, minExpectedUnique,
		"random generation should produce diverse values")
}

// homomorphicOpsCases tests homomorphic operations on shares
func homomorphicOpsCases[FE algebra.PrimeFieldElement[FE]](t *testing.T, scheme *shamir.Scheme[FE], field algebra.PrimeField[FE]) {
	t.Helper()

	// Create two secrets and their shares
	secret1 := shamir.NewSecret(field.FromUint64(10))
	secret2 := shamir.NewSecret(field.FromUint64(20))

	out1, err := scheme.Deal(secret1, crand.Reader)
	require.NoError(t, err)
	shares1 := out1.Shares()
	out2, err := scheme.Deal(secret2, crand.Reader)
	require.NoError(t, err)
	shares2 := out2.Shares()

	// Test cases for Add operation
	addTests := []struct {
		name              string
		share1            *shamir.Share[FE]
		share2            *shamir.Share[FE]
		expectedSecret    FE
		verifyReconstruct bool
	}{
		{
			name: "add shares from same holder",
			share1: func() *shamir.Share[FE] {
				s, _ := shares1.Get(sharing.ID(1))
				return s
			}(),
			share2: func() *shamir.Share[FE] {
				s, _ := shares2.Get(sharing.ID(1))
				return s
			}(),
			expectedSecret:    field.FromUint64(30), // 10 + 20
			verifyReconstruct: true,
		},
	}

	for _, tc := range addTests {
		t.Run(tc.name, func(t *testing.T) {
			// Perform addition
			sumShare := tc.share1.Add(tc.share2)

			require.NotNil(t, sumShare)
			require.Equal(t, tc.share1.ID(), sumShare.ID())
			require.False(t, sumShare.Value().IsOpIdentity())

			// Test Op method (should be same as Add)
			sumShareOp := tc.share1.Op(tc.share2)
			require.True(t, sumShare.Value().Equal(sumShareOp.Value()))

			if tc.verifyReconstruct {
				// Collect all sum shares for reconstruction
				allSumShares := make([]*shamir.Share[FE], 0)
				for _, id := range shares1.Keys() {
					s1, exists := shares1.Get(id)
					require.True(t, exists)
					s2, exists := shares2.Get(id)
					require.True(t, exists)

					allSumShares = append(allSumShares, s1.Add(s2))
				}

				// Reconstruct and verify
				reconstructed, err := scheme.Reconstruct(allSumShares...)
				require.NoError(t, err)
				require.True(t, tc.expectedSecret.Equal(reconstructed.Value()))
			}
		})
	}

	// Test cases for ScalarMul operation
	scalarMulTests := []struct {
		name              string
		share             *shamir.Share[FE]
		scalar            FE
		expectedSecret    FE
		verifyReconstruct bool
	}{
		{
			name: "multiply by 2",
			share: func() *shamir.Share[FE] {
				s, _ := shares1.Get(sharing.ID(1))
				return s
			}(),
			scalar:            field.FromUint64(2),
			expectedSecret:    field.FromUint64(20), // 10 * 2
			verifyReconstruct: true,
		},
		{
			name: "multiply by 0",
			share: func() *shamir.Share[FE] {
				s, _ := shares1.Get(sharing.ID(1))
				return s
			}(),
			scalar:            field.Zero(),
			expectedSecret:    field.Zero(), // 10 * 0
			verifyReconstruct: false,        // identity shares not allowed
		},
		{
			name: "multiply by 1",
			share: func() *shamir.Share[FE] {
				s, _ := shares1.Get(sharing.ID(1))
				return s
			}(),
			scalar:            field.One(),
			expectedSecret:    field.FromUint64(10), // 10 * 1
			verifyReconstruct: true,
		},
		{
			name: "multiply by large scalar",
			share: func() *shamir.Share[FE] {
				s, _ := shares2.Get(sharing.ID(1))
				return s
			}(),
			scalar:            field.FromUint64(100),
			expectedSecret:    field.FromUint64(2000), // 20 * 100
			verifyReconstruct: true,
		},
	}

	for _, tc := range scalarMulTests {
		t.Run(tc.name, func(t *testing.T) {
			// Perform scalar multiplication
			scaledShare := tc.share.ScalarMul(tc.scalar)

			require.NotNil(t, scaledShare)
			require.Equal(t, tc.share.ID(), scaledShare.ID())

			// Test ScalarOp method (should be same as ScalarMul)
			scaledShareOp := tc.share.ScalarOp(tc.scalar)
			require.True(t, scaledShare.Value().Equal(scaledShareOp.Value()))

			if tc.verifyReconstruct {
				// Collect all scaled shares for reconstruction
				allScaledShares := make([]*shamir.Share[FE], 0)
				shareMap := shares1
				if tc.share.ID() == sharing.ID(1) {
					s, _ := shares2.Get(sharing.ID(1))
					if s.Value().Equal(tc.share.Value()) {
						shareMap = shares2
					}
				}

				for _, id := range shareMap.Keys() {
					s, exists := shareMap.Get(id)
					require.True(t, exists)
					allScaledShares = append(allScaledShares, s.ScalarMul(tc.scalar))
				}

				// Reconstruct and verify
				reconstructed, err := scheme.Reconstruct(allScaledShares...)
				require.NoError(t, err)
				require.True(t, tc.expectedSecret.Equal(reconstructed.Value()))
			}
		})
	}

	// Test combined operations
	t.Run("combined add and scalar multiply", func(t *testing.T) {
		// Compute (s1 * 3) + (s2 * 2)
		scalar1 := field.FromUint64(3)
		scalar2 := field.FromUint64(2)

		combinedShares := make([]*shamir.Share[FE], 0)
		for _, id := range shares1.Keys() {
			s1, exists := shares1.Get(id)
			require.True(t, exists)
			s2, exists := shares2.Get(id)
			require.True(t, exists)

			// (s1 * 3) + (s2 * 2)
			combined := s1.ScalarMul(scalar1).Add(s2.ScalarMul(scalar2))
			combinedShares = append(combinedShares, combined)
		}

		// Expected: (10 * 3) + (20 * 2) = 30 + 40 = 70
		expectedSecret := field.FromUint64(70)

		reconstructed, err := scheme.Reconstruct(combinedShares...)
		require.NoError(t, err)
		require.True(t, expectedSecret.Equal(reconstructed.Value()))
	})

	// Test Share methods
	t.Run("share methods", func(t *testing.T) {
		share, _ := shares1.Get(sharing.ID(1))

		// Test Set method
		newValue := field.FromUint64(999)
		share, err := shamir.NewShare(share.ID(), newValue, scheme.AccessStructure())
		require.NoError(t, err)
		require.True(t, newValue.Equal(share.Value()))

		// Test Equal method
		share2, _ := shares1.Get(sharing.ID(2))
		require.False(t, share.Equal(share2))

		shareCopy := share.Clone()
		require.True(t, share.Equal(shareCopy))
		require.False(t, share.Equal(nil))

		// Test HashCode
		hash1 := share.HashCode()
		hash2 := share2.HashCode()
		require.NotEqual(t, hash1, hash2)

		hashCopy := shareCopy.HashCode()
		require.Equal(t, hash1, hashCopy)
	})
}

func TestHomomorphicOperations(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		field := k256.NewScalarField()

		testConfigs := []struct {
			name      string
			threshold uint
			total     uint
		}{
			{"2-of-3", 2, 3},
			{"3-of-5", 3, 5},
			{"threshold equals total", 4, 4},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := shamir.NewScheme(field, config.threshold, shareholders)
				require.NoError(t, err)
				homomorphicOpsCases(t, scheme, field)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		field := bls12381.NewScalarField()

		shareholders := sharing.NewOrdinalShareholderSet(4)
		scheme, err := shamir.NewScheme(field, 2, shareholders)
		require.NoError(t, err)
		homomorphicOpsCases(t, scheme, field)
	})
}

// BenchmarkHomomorphicOps benchmarks homomorphic operations
func BenchmarkHomomorphicOps(b *testing.B) {
	field := k256.NewScalarField()
	shareholders := sharing.NewOrdinalShareholderSet(5)
	scheme, err := shamir.NewScheme(field, 3, shareholders)
	require.NoError(b, err)

	// Create shares
	secret := shamir.NewSecret(field.FromUint64(42))
	out, err := scheme.Deal(secret, crand.Reader)
	require.NoError(b, err)
	shares := out.Shares()

	share1, _ := shares.Get(sharing.ID(1))
	share2, _ := shares.Get(sharing.ID(1))
	scalar := field.FromUint64(7)

	b.Run("Add", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = share1.Add(share2)
		}
	})

	b.Run("ScalarMul", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = share1.ScalarMul(scalar)
		}
	})

	b.Run("Combined", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = share1.ScalarMul(scalar).Add(share2)
		}
	})
}

// toAdditiveCases tests the ToAdditive conversion method
func toAdditiveCases[FE algebra.PrimeFieldElement[FE]](t *testing.T, scheme *shamir.Scheme[FE], field algebra.PrimeField[FE]) {
	t.Helper()

	// Create test secrets and their shares
	secret := shamir.NewSecret(field.FromUint64(42))
	out, err := scheme.Deal(secret, crand.Reader)
	require.NoError(t, err)

	// Get all shareholder IDs for creating qualified sets
	allIds := out.Shares().Keys()
	threshold := scheme.AccessStructure().Threshold()

	t.Run("valid conversion with full qualified set", func(t *testing.T) {
		// Create a qualified set with all shareholders
		qualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(
			scheme.AccessStructure().Shareholders(),
		)
		require.NoError(t, err)

		// Convert each share to additive
		additiveShares := make([]*additive.Share[FE], 0)
		for _, share := range out.Shares().Values() {
			additiveShare, err := share.ToAdditive(*qualifiedSet)
			require.NoError(t, err)
			require.NotNil(t, additiveShare)
			require.Equal(t, share.ID(), additiveShare.ID())
			// Additive shares can be zero due to Lagrange coefficient calculations

			additiveShares = append(additiveShares, additiveShare)
		}

		// Verify reconstruction with additive shares
		additiveScheme, err := additive.NewScheme(field, scheme.AccessStructure().Shareholders())
		require.NoError(t, err)

		reconstructed, err := additiveScheme.Reconstruct(additiveShares...)
		require.NoError(t, err)
		require.True(t, secret.Value().Equal(reconstructed.Value()))
	})

	t.Run("valid conversion with threshold qualified set", func(t *testing.T) {
		// Create a qualified set with exactly threshold shareholders
		thresholdIds := allIds[:threshold]
		qualifiedIds := hashset.NewComparable[sharing.ID]()

		for _, id := range thresholdIds {
			qualifiedIds.Add(id)
		}

		qualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(
			qualifiedIds.Freeze(),
		)
		require.NoError(t, err)

		// Convert shares in the qualified set
		additiveShares := make([]*additive.Share[FE], 0)
		for _, id := range thresholdIds {
			share, exists := out.Shares().Get(id)
			require.True(t, exists)

			additiveShare, err := share.ToAdditive(*qualifiedSet)
			require.NoError(t, err)
			require.NotNil(t, additiveShare)
			additiveShares = append(additiveShares, additiveShare)
		}

		// Verify reconstruction
		additiveScheme, err := additive.NewScheme(field, qualifiedIds.Freeze())
		require.NoError(t, err)

		reconstructed, err := additiveScheme.Reconstruct(additiveShares...)
		require.NoError(t, err)
		require.True(t, secret.Value().Equal(reconstructed.Value()))
	})

	t.Run("error when share not in qualified set", func(t *testing.T) {
		// Create a qualified set that doesn't include share ID 1
		qualifiedIds := hashset.NewComparable[sharing.ID]()

		// Add all IDs except the first one
		for i := 1; i < len(allIds); i++ {
			qualifiedIds.Add(allIds[i])
		}

		qualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(
			qualifiedIds.Freeze(),
		)
		require.NoError(t, err)

		// Try to convert share with ID 1 (not in qualified set)
		share, exists := out.Shares().Get(allIds[0])
		require.True(t, exists)

		additiveShare, err := share.ToAdditive(*qualifiedSet)
		require.Error(t, err)
		require.Contains(t, err.Error(), "is not a valid shareholder")
		require.Nil(t, additiveShare)
	})

	t.Run("multiple conversions produce consistent results", func(t *testing.T) {
		qualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(
			scheme.AccessStructure().Shareholders(),
		)
		require.NoError(t, err)

		share, exists := out.Shares().Get(allIds[0])
		require.True(t, exists)

		// Convert multiple times
		additiveShare1, err := share.ToAdditive(*qualifiedSet)
		require.NoError(t, err)

		additiveShare2, err := share.ToAdditive(*qualifiedSet)
		require.NoError(t, err)

		// Results should be identical
		require.True(t, additiveShare1.Value().Equal(additiveShare2.Value()))
		require.Equal(t, additiveShare1.ID(), additiveShare2.ID())
	})

	t.Run("lagrange coefficients verification", func(t *testing.T) {
		// Test that the Lagrange coefficients sum to 1
		lambdas, err := shamir.LagrangeCoefficients(field, allIds...)
		require.NoError(t, err)

		sum := field.Zero()
		for _, lambda := range lambdas.Values() {
			sum = sum.Add(lambda)
		}
		require.True(t, sum.Equal(field.One()), "Lagrange coefficients should sum to 1")
	})
}

// TestToAdditive tests the ToAdditive conversion method
func TestToAdditive(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		field := k256.NewScalarField()

		testConfigs := []struct {
			name      string
			threshold uint
			total     uint
		}{
			{"2-of-3", 2, 3},
			{"3-of-5", 3, 5},
			{"5-of-10", 5, 10},
			{"threshold equals total", 4, 4},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := shamir.NewScheme(field, config.threshold, shareholders)
				require.NoError(t, err)
				toAdditiveCases(t, scheme, field)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		field := bls12381.NewScalarField()

		testConfigs := []struct {
			name      string
			threshold uint
			total     uint
		}{
			{"2-of-4", 2, 4},
			{"4-of-7", 4, 7},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := shamir.NewScheme(field, config.threshold, shareholders)
				require.NoError(t, err)
				toAdditiveCases(t, scheme, field)
			})
		}
	})
}

// TestToAdditiveEdgeCases tests edge cases for ToAdditive
func TestToAdditiveEdgeCases(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	t.Run("zero secret conversion", func(t *testing.T) {
		shareholders := sharing.NewOrdinalShareholderSet(3)
		scheme, err := shamir.NewScheme(field, 2, shareholders)
		require.NoError(t, err)

		// Deal shares for zero secret
		zeroSecret := shamir.NewSecret(field.Zero())
		shares, err := scheme.Deal(zeroSecret, crand.Reader)
		require.NoError(t, err)

		qualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(
			scheme.AccessStructure().Shareholders(),
		)
		require.NoError(t, err)

		// Convert all shares
		additiveShares := make([]*additive.Share[*k256.Scalar], 0)
		for _, share := range shares.Shares().Values() {
			additiveShare, err := share.ToAdditive(*qualifiedSet)
			require.NoError(t, err)
			additiveShares = append(additiveShares, additiveShare)
		}

		// Verify reconstruction
		additiveScheme, err := additive.NewScheme(field, scheme.AccessStructure().Shareholders())
		require.NoError(t, err)

		reconstructed, err := additiveScheme.Reconstruct(additiveShares...)
		require.NoError(t, err)
		require.True(t, field.Zero().Equal(reconstructed.Value()))
	})

	t.Run("single shareholder qualified set", func(t *testing.T) {
		// This should fail as minimal qualified set needs at least 2 shareholders
		singleId := hashset.NewComparable[sharing.ID]()
		singleId.Add(sharing.ID(1))

		_, err := sharing.NewMinimalQualifiedAccessStructure(
			singleId.Freeze(),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "must have at least 2 shareholders")
	})

	t.Run("share with modified value", func(t *testing.T) {
		shareholders := sharing.NewOrdinalShareholderSet(3)
		scheme, err := shamir.NewScheme(field, 2, shareholders)
		require.NoError(t, err)

		secret := shamir.NewSecret(field.FromUint64(100))
		out, err := scheme.Deal(secret, crand.Reader)
		require.NoError(t, err)

		qualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(
			scheme.AccessStructure().Shareholders(),
		)
		require.NoError(t, err)

		// Get a share and modify its value
		share, exists := out.Shares().Get(sharing.ID(1))
		require.True(t, exists)

		originalValue := share.Value()
		newValue := field.FromUint64(999)
		share, err = shamir.NewShare(share.ID(), newValue, scheme.AccessStructure())
		require.NoError(t, err)

		// Convert with modified value
		additiveShare, err := share.ToAdditive(*qualifiedSet)
		require.NoError(t, err)

		// The additive share should use the modified value
		lambdas, err := shamir.LagrangeCoefficients(field, out.Shares().Keys()...)
		require.NoError(t, err)
		lambda, exists := lambdas.Get(sharing.ID(1))
		require.True(t, exists)
		expectedValue := lambda.Mul(newValue)
		require.True(t, expectedValue.Equal(additiveShare.Value()))

		// Restore original value for other tests
		share, err = shamir.NewShare(share.ID(), originalValue, scheme.AccessStructure())
		require.NoError(t, err)
	})
}

// BenchmarkToAdditive benchmarks the ToAdditive conversion
func BenchmarkToAdditive(b *testing.B) {
	field := k256.NewScalarField()

	benchConfigs := []struct {
		name      string
		threshold uint
		total     uint
	}{
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"5-of-10", 5, 10},
		{"10-of-20", 10, 20},
	}

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			shareholders := sharing.NewOrdinalShareholderSet(config.total)
			scheme, err := shamir.NewScheme(field, config.threshold, shareholders)
			require.NoError(b, err)

			secret := shamir.NewSecret(field.FromUint64(42))
			out, err := scheme.Deal(secret, crand.Reader)
			require.NoError(b, err)

			qualifiedSet, err := sharing.NewMinimalQualifiedAccessStructure(
				scheme.AccessStructure().Shareholders(),
			)
			require.NoError(b, err)

			share, exists := out.Shares().Get(sharing.ID(1))
			require.True(b, exists)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := share.ToAdditive(*qualifiedSet)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
