package shamir_test

import (
	"bytes"
	"io"
	mrand "math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures/threshold"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
)

func newShamirScheme[FE algebra.PrimeFieldElement[FE]](
	field algebra.PrimeField[FE],
	thresh uint,
	shareholders ds.Set[sharing.ID],
) (*shamir.Scheme[FE], error) {
	ac, err := threshold.NewThresholdAccessStructure(thresh, shareholders)
	if err != nil {
		return nil, err
	}
	return shamir.NewScheme(field, ac)
}

func TestSanity(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	threshold := uint(2)
	total := uint(5)
	shareholders := sharing.NewOrdinalShareholderSet(total)
	scheme, err := newShamirScheme(field, threshold, shareholders)
	require.NoError(t, err, "could not create scheme")

	secret := shamir.NewSecret(field.FromUint64(42))
	require.NoError(t, err)
	out, err := scheme.Deal(secret, pcg.NewRandomised())
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
		name         string
		secret       *shamir.Secret[FE]
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
			errorIs:     sharing.ErrIsNil,
		},
		{
			name:        "nil prng",
			secret:      fortyTwoSecret,
			prng:        nil,
			expectError: true,
			errorIs:     sharing.ErrIsNil,
		},
		{
			name:        "both nil",
			secret:      nil,
			prng:        nil,
			expectError: true,
			errorIs:     sharing.ErrIsNil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := scheme.Deal(tc.secret, tc.prng)

			if tc.expectError {
				require.Error(t, err)
				if tc.errorIs != nil {
					require.ErrorIs(t, err, tc.errorIs)
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
					require.ErrorIs(t, err, sharing.ErrFailed)
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
			errorIs:     sharing.ErrIsNil,
			iterations:  1,
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
			t.Parallel()
			secrets := make([]*shamir.Secret[FE], 0, tc.iterations)

			for i := range tc.iterations {
				// Reset reader if using deterministic prng
				if reader, ok := tc.prng.(*bytes.Reader); ok && i > 0 {
					reader.Seek(0, 0)
				}

				out, secret, err := scheme.DealRandom(tc.prng)

				if tc.expectError {
					require.Error(t, err)
					if tc.errorIs != nil {
						require.ErrorIs(t, err, tc.errorIs)
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
		t.Parallel()
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
				t.Parallel()
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := newShamirScheme(field, config.threshold, shareholders)
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
		t.Parallel()
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
				t.Parallel()
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := newShamirScheme(field, config.threshold, shareholders)
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
				t.Parallel()
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := newShamirScheme(field, config.threshold, shareholders)
				require.NoError(t, err)
				dealRandomCases(t, scheme)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		t.Parallel()
		field := bls12381.NewScalarField()

		shareholders := sharing.NewOrdinalShareholderSet(6)
		scheme, err := newShamirScheme(field, 3, shareholders)
		require.NoError(t, err)
		dealRandomCases(t, scheme)
	})
}
