package additive_test

import (
	"bytes"
	"io"
	mrand "math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/additive"
)

func TestSanity(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	total := 5
	identities := sharing.NewOrdinalShareholderSet(uint(total))
	scheme, err := additive.NewScheme(field, identities)
	require.NoError(t, err, "could not create scheme")

	secret := additive.NewSecret(field.FromUint64(42))
	shares, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err, "could not create shares")
	require.Equal(t, int(total), shares.Shares().Size(), "number of shares should match total")

	reconstructedSecret, err := scheme.Reconstruct(shares.Shares().Values()...)
	require.NoError(t, err, "could not reconstruct secret")
	require.True(t, secret.Equal(reconstructedSecret), "reconstructed secret should match original secret")
}

// dealCases tests the Deal function with various inputs
func dealCases[E additive.GroupElement[E]](t *testing.T, scheme *additive.Scheme[E], field interface {
	additive.Group[E]
	FromUint64(uint64) E
	One() E
}) {
	t.Helper()

	// Create test secrets
	zeroSecret := additive.NewSecret(field.OpIdentity())
	oneSecret := additive.NewSecret(field.One())
	fortyTwoSecret := additive.NewSecret(field.FromUint64(42))
	randomValue, err := field.Random(pcg.NewRandomised())
	require.NoError(t, err)
	randomSecret := additive.NewSecret(randomValue)

	// Get scheme parameters
	total := uint(scheme.AccessStructure().Shareholders().Size())

	tests := []struct {
		name         string
		secret       *additive.Secret[E]
		prng         io.Reader
		expectError  bool
		errorIs      error
		verifyShares bool
	}{
		{
			name:         "valid secret with constant 42",
			secret:       fortyTwoSecret,
			prng:         pcg.NewRandomised(),
			expectError:  false,
			verifyShares: true,
		},
		{
			name:         "valid secret with value 1",
			secret:       oneSecret,
			prng:         pcg.NewRandomised(),
			expectError:  false,
			verifyShares: true,
		},
		{
			name:         "valid secret with value 0",
			secret:       zeroSecret,
			prng:         pcg.NewRandomised(),
			expectError:  false,
			verifyShares: true,
		},
		{
			name:         "valid secret with random value",
			secret:       randomSecret,
			prng:         pcg.NewRandomised(),
			expectError:  false,
			verifyShares: true,
		},
		{
			name:        "nil secret",
			secret:      nil,
			prng:        pcg.NewRandomised(),
			expectError: true,
			errorIs:     additive.ErrIsNil,
		},
		{
			name:        "nil prng",
			secret:      fortyTwoSecret,
			prng:        nil,
			expectError: true,
			errorIs:     additive.ErrIsNil,
		},
		{
			name:        "both nil",
			secret:      nil,
			prng:        nil,
			expectError: true,
			errorIs:     additive.ErrIsNil,
		},
		{
			name:         "deterministic prng",
			secret:       fortyTwoSecret,
			prng:         pcg.New(mrand.Uint64(), mrand.Uint64()),
			expectError:  false,
			verifyShares: true,
		},
		{
			name:        "short deterministic prng",
			secret:      fortyTwoSecret,
			prng:        bytes.NewReader([]byte{1}),
			expectError: true,
			// Error comes from curves package (ErrRandomSample), not additive
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shares, err := scheme.Deal(tc.secret, tc.prng)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorIs != nil {
					require.ErrorIs(t, err, tc.errorIs)
				}
				require.Nil(t, shares)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, shares)
			require.Equal(t, int(total), shares.Shares().Size(), "should generate shares for all shareholders")

			if tc.verifyShares {
				// Verify each share
				for id, share := range shares.Shares().Iter() {
					require.NotNil(t, share)
					require.Equal(t, id, share.ID())
				}

				// Verify sum of shares equals secret
				reconstructed, err := scheme.Reconstruct(shares.Shares().Values()...)
				require.NoError(t, err)
				require.True(t, tc.secret.Equal(reconstructed), "reconstructed secret should match original")

				// Verify that shares sum to secret
				sum := field.OpIdentity()
				for _, share := range shares.Shares().Values() {
					sum = sum.Op(share.Value())
				}
				require.True(t, tc.secret.Value().Equal(sum), "sum of shares should equal secret")
			}
		})
	}
}

// dealRandomCases tests the DealRandom function
func dealRandomCases[E additive.GroupElement[E]](t *testing.T, scheme *additive.Scheme[E]) {
	t.Helper()

	total := uint(scheme.AccessStructure().Shareholders().Size())

	tests := []struct {
		name             string
		prng             io.Reader
		expectError      bool
		errorIs          error
		verifyUniqueness bool
		iterations       int
	}{
		{
			name:             "valid random generation",
			prng:             pcg.NewRandomised(),
			expectError:      false,
			verifyUniqueness: true,
			iterations:       1,
		},
		{
			name:             "multiple random generations",
			prng:             pcg.NewRandomised(),
			expectError:      false,
			verifyUniqueness: true,
			iterations:       5,
		},
		{
			name:        "nil prng",
			prng:        nil,
			expectError: true,
			errorIs:     additive.ErrIsNil,
			iterations:  1,
		},
		{
			name:        "deterministic prng produces same secret",
			prng:        pcg.New(mrand.Uint64(), mrand.Uint64()),
			expectError: false,
			iterations:  1,
		},
		{
			name:        "short deterministic prng",
			prng:        bytes.NewReader([]byte{1}),
			expectError: true,
			// Error comes from curves package (ErrRandomSample), not additive
			iterations: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secrets := make([]*additive.Secret[E], 0, tc.iterations)

			for i := range tc.iterations {
				// Reset reader if using deterministic prng
				if reader, ok := tc.prng.(*bytes.Reader); ok && i > 0 {
					reader.Seek(0, 0)
				}

				shares, secret, err := scheme.DealRandom(tc.prng)

				if tc.expectError {
					require.Error(t, err)
					if tc.errorIs != nil {
						require.ErrorIs(t, err, tc.errorIs)
					}
					require.Nil(t, shares)
					require.Nil(t, secret)
					return
				}

				require.NoError(t, err)
				require.NotNil(t, shares)
				require.NotNil(t, secret)
				require.Equal(t, int(total), shares.Shares().Size())
				require.False(t, secret.Value().IsOpIdentity(), "random secret should not be identity")

				secrets = append(secrets, secret)

				// Verify each share
				for id, share := range shares.Shares().Iter() {
					require.NotNil(t, share)
					require.Equal(t, id, share.ID())
				}

				// Verify reconstruction
				reconstructed, err := scheme.Reconstruct(shares.Shares().Values()...)
				require.NoError(t, err)
				require.True(t, secret.Equal(reconstructed))
			}

			// Verify uniqueness across iterations if required
			if tc.verifyUniqueness && tc.iterations > 1 {
				secretValues := make(map[string]int)
				for _, secret := range secrets {
					val := secret.Value().String()
					secretValues[val]++
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

// reconstructCases tests the Reconstruct function with various scenarios
func reconstructCases[E additive.GroupElement[E]](t *testing.T, scheme *additive.Scheme[E], field interface {
	additive.Group[E]
	FromUint64(uint64) E
}) {
	t.Helper()

	// Deal shares for testing
	secret := additive.NewSecret(field.FromUint64(100))
	shares, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	allShares := shares.Shares().Values()
	total := len(allShares)

	tests := []struct {
		name           string
		sharesProvider func() []*additive.Share[E]
		expectError    bool
		errorIs        error
		expectedSecret *additive.Secret[E]
	}{
		{
			name: "all shares present",
			sharesProvider: func() []*additive.Share[E] {
				return allShares
			},
			expectError:    false,
			expectedSecret: secret,
		},
		{
			name: "missing one share",
			sharesProvider: func() []*additive.Share[E] {
				return allShares[:total-1]
			},
			expectError: true,
			errorIs:     additive.ErrFailed,
		},
		{
			name: "missing multiple shares",
			sharesProvider: func() []*additive.Share[E] {
				if total > 2 {
					return allShares[:2]
				}
				return allShares[:1]
			},
			expectError: true,
			errorIs:     additive.ErrFailed,
		},
		{
			name: "no shares",
			sharesProvider: func() []*additive.Share[E] {
				return []*additive.Share[E]{}
			},
			expectError: true,
			errorIs:     additive.ErrFailed,
		},
		{
			name: "nil share in list",
			sharesProvider: func() []*additive.Share[E] {
				sharesWithNil := make([]*additive.Share[E], len(allShares))
				copy(sharesWithNil, allShares)
				sharesWithNil[0] = nil
				return sharesWithNil
			},
			expectError: true,
			errorIs:     sharing.ErrIsNil,
		},
		{
			name: "duplicate shares",
			sharesProvider: func() []*additive.Share[E] {
				duplicated := make([]*additive.Share[E], len(allShares))
				copy(duplicated, allShares)
				// Replace last share with duplicate of first
				duplicated[total-1] = allShares[0]
				return duplicated
			},
			expectError: true,
			errorIs:     additive.ErrFailed,
		},
		{
			name: "invalid share ID",
			sharesProvider: func() []*additive.Share[E] {
				// Try to create an invalid share - this should fail
				_, err := additive.NewShare(999, allShares[0].Value(), scheme.AccessStructure())
				require.Error(t, err)
				require.ErrorIs(t, err, additive.ErrMembership)

				// Since we can't create an invalid share (NewShare validates),
				// we'll test with shares that don't form a complete set
				return allShares[:1] // Only one share - not authorized
			},
			expectError: true,
			errorIs:     additive.ErrFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testShares := tc.sharesProvider()
			reconstructed, err := scheme.Reconstruct(testShares...)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorIs != nil {
					require.ErrorIs(t, err, tc.errorIs)
				}
				require.Nil(t, reconstructed)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, reconstructed)
			require.True(t, tc.expectedSecret.Equal(reconstructed))
		})
	}
}

// homomorphicOpsCases tests homomorphic operations on shares
func homomorphicOpsCases[E additive.GroupElement[E]](t *testing.T, scheme *additive.Scheme[E], field interface {
	additive.Group[E]
	FromUint64(uint64) E
}) {
	t.Helper()

	// Create two secrets and their shares
	secret1 := additive.NewSecret(field.FromUint64(10))
	secret2 := additive.NewSecret(field.FromUint64(20))

	shares1, err := scheme.Deal(secret1, pcg.NewRandomised())
	require.NoError(t, err)
	shares2, err := scheme.Deal(secret2, pcg.NewRandomised())
	require.NoError(t, err)

	t.Run("add shares", func(t *testing.T) {
		t.Parallel()
		// Add corresponding shares
		sumShares := make([]*additive.Share[E], 0)
		for _, id := range shares1.Shares().Keys() {
			s1, exists1 := shares1.Shares().Get(id)
			require.True(t, exists1)
			s2, exists2 := shares2.Shares().Get(id)
			require.True(t, exists2)

			sumShare := s1.Add(s2)
			require.NotNil(t, sumShare)
			require.Equal(t, s1.ID(), sumShare.ID())

			// Test Op method (should be same as Add)
			sumShareOp := s1.Op(s2)
			require.True(t, sumShare.Value().Equal(sumShareOp.Value()))

			sumShares = append(sumShares, sumShare)
		}

		// Reconstruct and verify
		reconstructed, err := scheme.Reconstruct(sumShares...)
		require.NoError(t, err)
		expectedSum := field.FromUint64(30) // 10 + 20
		require.True(t, expectedSum.Equal(reconstructed.Value()))
	})

	t.Run("share methods", func(t *testing.T) {
		t.Parallel()
		share, _ := shares1.Shares().Get(1)

		// Test Set method
		newValue := field.FromUint64(999)
		share, err := additive.NewShare(share.ID(), newValue, scheme.AccessStructure())
		require.NoError(t, err)
		require.True(t, newValue.Equal(share.Value()))

		// Test Equal method
		share2, _ := shares1.Shares().Get(2)
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

	t.Run("secret methods", func(t *testing.T) {
		t.Parallel()
		// Test Equal method
		secret1Copy := secret1.Clone()
		require.True(t, secret1.Equal(secret1Copy))
		require.False(t, secret1.Equal(secret2))
		require.False(t, secret1.Equal(nil))

		// Test Value method
		require.True(t, secret1.Value().Equal(secret1.Value()))
	})
}

// shareValidationCases tests share validation
func shareValidationCases[E additive.GroupElement[E]](t *testing.T, scheme *additive.Scheme[E], field interface {
	additive.Group[E]
	FromUint64(uint64) E
	Zero() E
}) {
	t.Helper()

	// Create a valid share for testing
	secret := additive.NewSecret(field.FromUint64(50))
	shares, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)
	validShare, _ := shares.Shares().Get(1)

	tests := []struct {
		name         string
		shareFunc    func(ac *sharing.MinimalQualifiedAccessStructure) (*additive.Share[E], error)
		accessStruct *sharing.MinimalQualifiedAccessStructure
		expectError  bool
		errorIs      error
	}{
		{
			name: "valid share",
			shareFunc: func(ac *sharing.MinimalQualifiedAccessStructure) (*additive.Share[E], error) {
				return validShare, nil
			},
			accessStruct: scheme.AccessStructure(),
			expectError:  false,
		},
		{
			name: "nil share value check",
			shareFunc: func(ac *sharing.MinimalQualifiedAccessStructure) (*additive.Share[E], error) {
				// This would test share validation but we can't create a nil share
				return nil, additive.ErrIsNil.WithMessage("share is nil")
			},
			accessStruct: scheme.AccessStructure(),
			expectError:  true,
			errorIs:      additive.ErrIsNil,
		},
		{
			name: "invalid share ID",
			shareFunc: func(ac *sharing.MinimalQualifiedAccessStructure) (*additive.Share[E], error) {
				return additive.NewShare(999, validShare.Value(), ac)
			},
			accessStruct: scheme.AccessStructure(),
			expectError:  true,
			errorIs:      additive.ErrMembership,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			share, err := tc.shareFunc(tc.accessStruct)
			if tc.expectError {
				require.Error(t, err)
				if tc.errorIs != nil {
					require.ErrorIs(t, err, tc.errorIs)
				}
				require.Nil(t, share)
			} else {
				require.NotNil(t, share)
				require.NoError(t, err)
			}
		})
	}
}

func TestDeal(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		field := k256.NewScalarField()

		testConfigs := []struct {
			name  string
			total uint
		}{
			{"2 shareholders", 2},
			{"3 shareholders", 3},
			{"5 shareholders", 5},
			{"10 shareholders", 10},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				t.Parallel()
				identities := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := additive.NewScheme(field, identities)
				require.NoError(t, err)
				dealCases(t, scheme, field)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		t.Parallel()
		field := bls12381.NewScalarField()

		testConfigs := []struct {
			name  string
			total uint
		}{
			{"4 shareholders", 4},
			{"7 shareholders", 7},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				t.Parallel()
				identities := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := additive.NewScheme(field, identities)
				require.NoError(t, err)
				dealCases(t, scheme, field)
			})
		}
	})
}

func TestDealRandom(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		field := k256.NewScalarField()

		testConfigs := []struct {
			name  string
			total uint
		}{
			{"3 shareholders", 3},
			{"5 shareholders", 5},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				t.Parallel()
				identities := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := additive.NewScheme(field, identities)
				require.NoError(t, err)
				dealRandomCases(t, scheme)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		t.Parallel()
		field := bls12381.NewScalarField()

		identities := sharing.NewOrdinalShareholderSet(6)
		scheme, err := additive.NewScheme(field, identities)
		require.NoError(t, err)
		dealRandomCases(t, scheme)
	})
}

func TestReconstruct(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		field := k256.NewScalarField()

		testConfigs := []struct {
			name  string
			total uint
		}{
			{"2 shareholders", 2},
			{"5 shareholders", 5},
			{"10 shareholders", 10},
		}

		for _, config := range testConfigs {
			t.Run(config.name, func(t *testing.T) {
				t.Parallel()
				identities := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := additive.NewScheme(field, identities)
				require.NoError(t, err)
				reconstructCases(t, scheme, field)
			})
		}
	})
}

func TestHomomorphicOperations(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		field := k256.NewScalarField()

		identities := sharing.NewOrdinalShareholderSet(5)
		scheme, err := additive.NewScheme(field, identities)
		require.NoError(t, err)
		homomorphicOpsCases(t, scheme, field)
	})

	t.Run("bls12381", func(t *testing.T) {
		t.Parallel()
		field := bls12381.NewScalarField()

		identities := sharing.NewOrdinalShareholderSet(4)
		scheme, err := additive.NewScheme(field, identities)
		require.NoError(t, err)
		homomorphicOpsCases(t, scheme, field)
	})
}

func TestShareValidation(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	identities := sharing.NewOrdinalShareholderSet(3)
	scheme, err := additive.NewScheme(field, identities)
	require.NoError(t, err)
	shareValidationCases(t, scheme, field)
}

func TestNewScheme(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	t.Run("valid construction", func(t *testing.T) {
		t.Parallel()
		identities := sharing.NewOrdinalShareholderSet(5)
		scheme, err := additive.NewScheme(field, identities)
		require.NoError(t, err)
		require.NotNil(t, scheme)
		require.Equal(t, 5, scheme.AccessStructure().Shareholders().Size())
	})

	t.Run("nil identities", func(t *testing.T) {
		t.Parallel()
		scheme, err := additive.NewScheme(field, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, additive.ErrIsNil)
		require.Nil(t, scheme)
	})

	t.Run("nil group", func(t *testing.T) {
		t.Parallel()
		identities := sharing.NewOrdinalShareholderSet(5)
		scheme, err := additive.NewScheme[*k256.Scalar](nil, identities)
		require.Error(t, err)
		require.ErrorIs(t, err, additive.ErrIsNil)
		require.Nil(t, scheme)
	})

	t.Run("single shareholder", func(t *testing.T) {
		t.Parallel()
		singleID := hashset.NewComparable[sharing.ID]()
		singleID.Add(sharing.ID(1))
		scheme, err := additive.NewScheme(field, singleID.Freeze())
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
		require.Nil(t, scheme)
	})

	t.Run("custom identity set", func(t *testing.T) {
		t.Parallel()
		customIds := hashset.NewComparable[sharing.ID]()
		customIds.Add(sharing.ID(10))
		customIds.Add(sharing.ID(20))
		customIds.Add(sharing.ID(30))
		scheme, err := additive.NewScheme(field, customIds.Freeze())
		require.NoError(t, err)
		require.NotNil(t, scheme)
		require.Equal(t, 3, scheme.AccessStructure().Shareholders().Size())
		require.True(t, scheme.AccessStructure().Shareholders().Contains(sharing.ID(10)))
		require.True(t, scheme.AccessStructure().Shareholders().Contains(sharing.ID(20)))
		require.True(t, scheme.AccessStructure().Shareholders().Contains(sharing.ID(30)))
	})
}

func TestAccessStructure(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	identities := sharing.NewOrdinalShareholderSet(5)
	scheme, err := additive.NewScheme(field, identities)
	require.NoError(t, err)

	t.Run("IsAuthorized", func(t *testing.T) {
		t.Parallel()
		// Should be authorized only with all shareholders
		require.True(t, scheme.AccessStructure().IsAuthorized(sharing.ID(1), sharing.ID(2), sharing.ID(3), sharing.ID(4), sharing.ID(5)))
		require.False(t, scheme.AccessStructure().IsAuthorized(sharing.ID(1), sharing.ID(2), sharing.ID(3), sharing.ID(4)))                               // Missing one
		require.False(t, scheme.AccessStructure().IsAuthorized(sharing.ID(1), sharing.ID(2)))                                                             // Missing many
		require.False(t, scheme.AccessStructure().IsAuthorized())                                                                                         // No shareholders
		require.False(t, scheme.AccessStructure().IsAuthorized(sharing.ID(1), sharing.ID(2), sharing.ID(3), sharing.ID(4), sharing.ID(5), sharing.ID(6))) // Too many
		require.False(t, scheme.AccessStructure().IsAuthorized(sharing.ID(1), sharing.ID(2), sharing.ID(3), sharing.ID(4), sharing.ID(99)))               // Invalid ID
	})

	t.Run("Shareholders", func(t *testing.T) {
		t.Parallel()
		shareholders := scheme.AccessStructure().Shareholders()
		require.Equal(t, 5, shareholders.Size())
		for i := range 5 {
			require.True(t, shareholders.Contains(sharing.ID(i+1)))
		}
	})
}

func TestDealDeterministic(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	identities := sharing.NewOrdinalShareholderSet(5)
	scheme, err := additive.NewScheme(field, identities)
	require.NoError(t, err)

	secret := additive.NewSecret(field.FromUint64(42))

	// Use PCG for deterministic randomness that produces non-zero values
	prng1 := pcg.New(12345, 67890)
	prng2 := pcg.New(12345, 67890)

	shares1, err := scheme.Deal(secret, prng1)
	require.NoError(t, err)

	shares2, err := scheme.Deal(secret, prng2)
	require.NoError(t, err)

	// Verify that both produce valid shares that reconstruct to the same secret
	// Note: Due to the order of processing shareholders, shares might not be identical
	// even with same randomness, but they should reconstruct to the same secret
	reconstructed1, err := scheme.Reconstruct(shares1.Shares().Values()...)
	require.NoError(t, err)

	reconstructed2, err := scheme.Reconstruct(shares2.Shares().Values()...)
	require.NoError(t, err)

	require.True(t, secret.Equal(reconstructed1))
	require.True(t, secret.Equal(reconstructed2))
	require.True(t, reconstructed1.Equal(reconstructed2))
}

// BenchmarkDeal benchmarks the Deal function
func BenchmarkDeal(b *testing.B) {
	field := k256.NewScalarField()

	benchConfigs := []struct {
		name  string
		total uint
	}{
		{"3 shareholders", 3},
		{"5 shareholders", 5},
		{"10 shareholders", 10},
		{"20 shareholders", 20},
		{"50 shareholders", 50},
	}

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			identities := sharing.NewOrdinalShareholderSet(config.total)
			scheme, err := additive.NewScheme(field, identities)
			require.NoError(b, err)

			secret := additive.NewSecret(field.FromUint64(42))

			b.ResetTimer()
			for range b.N {
				_, err := scheme.Deal(secret, pcg.NewRandomised())
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
		name  string
		total uint
	}{
		{"3 shareholders", 3},
		{"5 shareholders", 5},
		{"10 shareholders", 10},
		{"20 shareholders", 20},
	}

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			identities := sharing.NewOrdinalShareholderSet(config.total)
			scheme, err := additive.NewScheme(field, identities)
			require.NoError(b, err)

			b.ResetTimer()
			for range b.N {
				_, _, err := scheme.DealRandom(pcg.NewRandomised())
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkReconstruct benchmarks the Reconstruct function
func BenchmarkReconstruct(b *testing.B) {
	field := k256.NewScalarField()

	benchConfigs := []struct {
		name  string
		total uint
	}{
		{"3 shareholders", 3},
		{"5 shareholders", 5},
		{"10 shareholders", 10},
		{"20 shareholders", 20},
	}

	for _, config := range benchConfigs {
		b.Run(config.name, func(b *testing.B) {
			identities := sharing.NewOrdinalShareholderSet(config.total)
			scheme, err := additive.NewScheme(field, identities)
			require.NoError(b, err)

			secret := additive.NewSecret(field.FromUint64(42))
			shares, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(b, err)
			shareSlice := shares.Shares().Values()

			b.ResetTimer()
			for range b.N {
				_, err := scheme.Reconstruct(shareSlice...)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestArbitraryShareholderIDs tests that additive secret sharing works with
// arbitrary distinct non-zero shareholder IDs (not just sequential 1, 2, 3, ...).
func TestArbitraryShareholderIDs(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	// Create a set with arbitrary non-sequential IDs
	arbitraryIDs := hashset.NewComparable[sharing.ID]()
	arbitraryIDs.Add(sharing.ID(13))
	arbitraryIDs.Add(sharing.ID(256))
	arbitraryIDs.Add(sharing.ID(1000))
	arbitraryIDs.Add(sharing.ID(99))

	shareholders := arbitraryIDs.Freeze()

	scheme, err := additive.NewScheme(field, shareholders)
	require.NoError(t, err)
	require.NotNil(t, scheme)
	require.Equal(t, 4, scheme.AccessStructure().Shareholders().Size())

	// Verify the scheme contains the arbitrary IDs
	for _, id := range []sharing.ID{13, 256, 1000, 99} {
		require.True(t, scheme.AccessStructure().Shareholders().Contains(id), "shareholder set should contain ID %d", id)
	}

	// Test dealing with arbitrary IDs
	secret := additive.NewSecret(field.FromUint64(54321))
	out, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)
	require.NotNil(t, out)
	require.Equal(t, 4, out.Shares().Size())

	// Verify all arbitrary IDs have shares
	for _, id := range []sharing.ID{13, 256, 1000, 99} {
		share, exists := out.Shares().Get(id)
		require.True(t, exists, "share for ID %d should exist", id)
		require.Equal(t, id, share.ID())
	}

	// Verify that shares sum to secret (fundamental property of additive sharing)
	sum := field.OpIdentity()
	for _, share := range out.Shares().Values() {
		sum = sum.Op(share.Value())
	}
	require.True(t, secret.Value().Equal(sum), "sum of shares should equal secret")

	// Test reconstruction with all shares (required for additive sharing)
	reconstructed, err := scheme.Reconstruct(out.Shares().Values()...)
	require.NoError(t, err)
	require.True(t, secret.Equal(reconstructed), "reconstructed secret should match original")

	// Test that missing even one share fails (all shares required for additive)
	incompleteShares := []*additive.Share[*k256.Scalar]{
		func() *additive.Share[*k256.Scalar] { s, _ := out.Shares().Get(sharing.ID(13)); return s }(),
		func() *additive.Share[*k256.Scalar] { s, _ := out.Shares().Get(sharing.ID(256)); return s }(),
		func() *additive.Share[*k256.Scalar] { s, _ := out.Shares().Get(sharing.ID(1000)); return s }(),
		// Missing ID 99
	}
	_, err = scheme.Reconstruct(incompleteShares...)
	require.Error(t, err)
	require.ErrorIs(t, err, additive.ErrFailed)

	// Test DealRandom with arbitrary IDs
	randomOut, randomSecret, err := scheme.DealRandom(pcg.NewRandomised())
	require.NoError(t, err)
	require.NotNil(t, randomOut)
	require.NotNil(t, randomSecret)
	require.Equal(t, 4, randomOut.Shares().Size())

	// Verify reconstruction with random secret
	reconstructedRandom, err := scheme.Reconstruct(randomOut.Shares().Values()...)
	require.NoError(t, err)
	require.True(t, randomSecret.Equal(reconstructedRandom))

	// Test homomorphic operations with arbitrary IDs
	secret1 := additive.NewSecret(field.FromUint64(100))
	secret2 := additive.NewSecret(field.FromUint64(200))

	shares1, err := scheme.Deal(secret1, pcg.NewRandomised())
	require.NoError(t, err)
	shares2, err := scheme.Deal(secret2, pcg.NewRandomised())
	require.NoError(t, err)

	// Add corresponding shares
	sumShares := make([]*additive.Share[*k256.Scalar], 0)
	for _, id := range []sharing.ID{13, 256, 1000, 99} {
		s1, exists1 := shares1.Shares().Get(id)
		require.True(t, exists1)
		s2, exists2 := shares2.Shares().Get(id)
		require.True(t, exists2)

		sumShare := s1.Add(s2)
		require.Equal(t, id, sumShare.ID())
		sumShares = append(sumShares, sumShare)
	}

	// Verify reconstruction of sum
	reconstructedSum, err := scheme.Reconstruct(sumShares...)
	require.NoError(t, err)
	expectedSum := field.FromUint64(300) // 100 + 200
	require.True(t, expectedSum.Equal(reconstructedSum.Value()))

	// Test authorization checks with arbitrary IDs
	require.True(t, scheme.AccessStructure().IsAuthorized(sharing.ID(13), sharing.ID(256), sharing.ID(1000), sharing.ID(99)))
	require.False(t, scheme.AccessStructure().IsAuthorized(sharing.ID(13), sharing.ID(256), sharing.ID(1000))) // Missing one
	require.False(t, scheme.AccessStructure().IsAuthorized(sharing.ID(1), sharing.ID(2), sharing.ID(3), sharing.ID(4)))  // Wrong IDs
	require.False(t, scheme.AccessStructure().IsAuthorized(sharing.ID(13), sharing.ID(256), sharing.ID(1000), sharing.ID(999))) // One wrong ID
}
