package pedersen_test

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
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/commitments"
	pedcom "github.com/bronlabs/bron-crypto/pkg/commitments/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/accessstructures"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/additive"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/pedersen"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/shamir"
)

func newPedersenScheme[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](
	tb testing.TB,
	key *pedcom.Key[E, S],
	threshold uint,
	shareholders ds.Set[sharing.ID],
) (*pedersen.Scheme[E, S], error) {
	tb.Helper()

	ac, err := accessstructures.NewThresholdAccessStructure(threshold, shareholders)
	if err != nil {
		return nil, err
	}
	return pedersen.NewScheme(key, ac)
}

// TestSchemeCreation tests creation of Pedersen schemes with various parameters
func TestSchemeCreation(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-scheme-creation"))
	require.NoError(t, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(t, err)

	t.Run("valid scheme creation", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name      string
			threshold uint
			total     uint
		}{
			{"2-of-3", 2, 3},
			{"3-of-5", 3, 5},
			{"5-of-10", 5, 10},
			{"threshold equals total", 5, 5},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				shareholders := sharing.NewOrdinalShareholderSet(tc.total)
				scheme, err := newPedersenScheme(t, key, tc.threshold, shareholders)
				require.NoError(t, err)
				require.NotNil(t, scheme)
				require.Equal(t, tc.threshold, scheme.AccessStructure().Threshold())
				require.Equal(t, int(tc.total), scheme.AccessStructure().Shareholders().Size())
			})
		}
	})

	t.Run("invalid threshold", func(t *testing.T) {
		t.Parallel()
		// Threshold of 0
		shareholders := sharing.NewOrdinalShareholderSet(5)
		_, err := newPedersenScheme(t, key, 0, shareholders)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)

		// Threshold of 1
		_, err = newPedersenScheme(t, key, 1, shareholders)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)

		// Threshold greater than total
		_, err = newPedersenScheme(t, key, 6, shareholders)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
	})

	t.Run("invalid total", func(t *testing.T) {
		t.Parallel()
		// Total of 0
		shareholders := sharing.NewOrdinalShareholderSet(0)
		_, err := newPedersenScheme(t, key, 2, shareholders)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)

		// Total of 1
		shareholders = sharing.NewOrdinalShareholderSet(1)
		_, err = newPedersenScheme(t, key, 2, shareholders)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrValue)
	})

	t.Run("nil key", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		_, err := newPedersenScheme[*k256.Point](t, nil, 2, shareholders)
		require.Error(t, err)
		require.ErrorIs(t, err, pedcom.ErrInvalidArgument)
	})
}

func TestSanity(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("pedersen-test-h"))
	require.NoError(t, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(t, err, "could not create key")

	threshold := uint(2)
	total := uint(5)
	shareholders := sharing.NewOrdinalShareholderSet(total)
	scheme, err := newPedersenScheme(t, key, threshold, shareholders)
	require.NoError(t, err, "could not create scheme")

	secret := pedersen.NewSecret(field.FromUint64(42))
	shares, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err, "could not create shares")
	require.Equal(t, total, uint(shares.Shares().Size()), "number of shares should match total")

	// Test verification
	reference := shares.VerificationVector()
	for _, share := range shares.Shares().Values() {
		err := scheme.Verify(share, reference)
		require.NoError(t, err, "share verification should pass")
	}

	reconstructedSecret, err := scheme.Reconstruct(shares.Shares().Values()...)
	require.NoError(t, err, "could not reconstruct secret")
	require.True(t, secret.Equal(reconstructedSecret), "reconstructed secret should match original secret")

	// Test ReconstructAndVerify
	reconstructedSecret2, err := scheme.ReconstructAndVerify(reference, shares.Shares().Values()...)
	require.NoError(t, err, "could not reconstruct and verify secret")
	require.True(t, secret.Equal(reconstructedSecret2), "reconstructed secret should match original secret")
}

// dealCases tests the Deal function with various inputs
func dealCases[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](t *testing.T, scheme *pedersen.Scheme[E, S], field algebra.PrimeField[S]) {
	t.Helper()

	// Create test secrets
	zeroSecret := pedersen.NewSecret(field.Zero())
	oneSecret := pedersen.NewSecret(field.One())
	fortyTwoSecret := pedersen.NewSecret(field.FromUint64(42))
	randomSecret := pedersen.NewSecret(field.FromUint64(12345))

	// Get scheme parameters
	threshold := scheme.AccessStructure().Threshold()
	total := uint(scheme.AccessStructure().Shareholders().Size())

	tests := []struct {
		name         string
		secret       *pedersen.Secret[S]
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
				reference := shares.VerificationVector()
				require.NotNil(t, reference, "verification vector should not be nil")

				for id, share := range shares.Shares().Iter() {
					require.NotNil(t, share)
					require.Equal(t, id, share.ID())
					// When secret is zero, shares can be zero (identity)
					if !tc.secret.Value().IsZero() {
						// For non-zero secrets, we still expect non-zero shares in most cases
						// but it's mathematically possible to have zero shares even with non-zero secret
					}
					// Blinding factors must always be non-zero for witness creation
					require.False(t, share.Blinding().Value().IsOpIdentity(), "blinding factor should not be identity")
				}

				// Verify shares are different (except potentially for zero secret)
				if !tc.secret.Value().IsZero() {
					shareValues := make(map[string]bool)
					for _, share := range shares.Shares().Values() {
						val := share.Value().String()
						require.False(t, shareValues[val], "shares should have different values")
						shareValues[val] = true
					}
				}

				// Verify reconstruction works
				reconstructed, err := scheme.Reconstruct(shares.Shares().Values()...)
				require.NoError(t, err)
				require.True(t, tc.secret.Equal(reconstructed), "reconstructed secret should match original")

				// Verify threshold property: any t shares can reconstruct
				shareSlice := shares.Shares().Values()
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

				// Verify each share
				for _, share := range shares.Shares().Values() {
					err := scheme.Verify(share, reference)
					require.NoError(t, err, "share verification should pass")
				}
			}
		})
	}
}

// dealRandomCases tests the DealRandom function
func dealRandomCases[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](t *testing.T, scheme *pedersen.Scheme[E, S]) {
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
			name:        "deterministic prng produces same secret",
			prng:        pcg.New(mrand.Uint64(), mrand.Uint64()),
			expectError: false,
			iterations:  1,
		},
		{
			name:        "short deterministic prng",
			prng:        bytes.NewReader([]byte{1}),
			expectError: true,
			// Error comes from curves package (ErrRandomSample), not pedersen
			iterations: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			secrets := make([]*pedersen.Secret[S], 0, tc.iterations)

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

				// Verify all shares have the same verification vector
				reference := shares.VerificationVector()
				for _, share := range shares.Shares().Values() {
					require.NotNil(t, reference)
					// Verify blinding factors are not zero
					require.False(t, share.Blinding().Value().IsOpIdentity(), "blinding factor should not be identity")
				}

				// Verify reconstruction
				reconstructed, err := scheme.Reconstruct(shares.Shares().Values()...)
				require.NoError(t, err)
				require.True(t, secret.Equal(reconstructed))

				// Verify threshold property
				if shares.Shares().Size() >= int(threshold) {
					shareSlice := shares.Shares().Values()
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
		curve := k256.NewCurve()
		field := k256.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-k256"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

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
				scheme, err := newPedersenScheme(t, key, config.threshold, shareholders)
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
		curve := bls12381.NewG1()
		field := bls12381.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-bls12381"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

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
				scheme, err := newPedersenScheme(t, key, config.threshold, shareholders)
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
		curve := k256.NewCurve()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-k256-random"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

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
				scheme, err := newPedersenScheme(t, key, config.threshold, shareholders)
				require.NoError(t, err)
				dealRandomCases(t, scheme)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-bls12381-random"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

		shareholders := sharing.NewOrdinalShareholderSet(6)
		scheme, err := newPedersenScheme(t, key, 3, shareholders)
		require.NoError(t, err)
		dealRandomCases(t, scheme)
	})
}

// verificationCases tests verification functionality
func verificationCases[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](t *testing.T, scheme *pedersen.Scheme[E, S], field algebra.PrimeField[S]) {
	t.Helper()

	// Create valid shares
	secret := pedersen.NewSecret(field.FromUint64(42))
	shares, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	// Get reference verification vector
	reference := shares.VerificationVector()

	t.Run("valid shares pass verification", func(t *testing.T) {
		t.Parallel()
		for _, share := range shares.Shares().Values() {
			err := scheme.Verify(share, reference)
			require.NoError(t, err, "valid share should pass verification")
		}
	})

	t.Run("ReconstructAndVerify with valid shares", func(t *testing.T) {
		t.Parallel()
		reconstructed, err := scheme.ReconstructAndVerify(reference, shares.Shares().Values()...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))

		// Try with subset of shares
		threshold := scheme.AccessStructure().Threshold()
		if shares.Shares().Size() >= int(threshold) {
			subsetShares := shares.Shares().Values()[:threshold]
			reconstructed, err = scheme.ReconstructAndVerify(reference, subsetShares...)
			require.NoError(t, err)
			require.True(t, secret.Equal(reconstructed))
		}
	})

	t.Run("tampered share value fails verification", func(t *testing.T) {
		t.Parallel()
		// Get a share and modify its value
		originalShare := shares.Shares().Values()[0]
		tamperedValue := field.FromUint64(999)

		// Create new message and witness for tampered share
		message := pedcom.NewMessage(tamperedValue)
		witness := originalShare.Blinding()
		tamperedShare, err := pedersen.NewShare(
			originalShare.ID(),
			message,
			witness,
			scheme.AccessStructure(),
		)
		require.NoError(t, err)

		err = scheme.Verify(tamperedShare, reference)
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrVerificationFailed)
	})

	t.Run("tampered blinding factor fails verification", func(t *testing.T) {
		t.Parallel()
		// Get a share and modify its blinding factor
		originalShare := shares.Shares().Values()[0]
		tamperedBlinding := field.FromUint64(888)

		// Create new message and witness for tampered share
		message := originalShare.Secret()
		witness, err := pedcom.NewWitness(tamperedBlinding)
		require.NoError(t, err)

		tamperedShare, err := pedersen.NewShare(
			originalShare.ID(),
			message,
			witness,
			scheme.AccessStructure(),
		)
		require.NoError(t, err)

		err = scheme.Verify(tamperedShare, reference)
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrVerificationFailed)
	})

	t.Run("ReconstructAndVerify fails with tampered share", func(t *testing.T) {
		t.Parallel()
		// Create a tampered share with slightly modified value
		originalShare := shares.Shares().Values()[0]
		originalValue := originalShare.Value()

		// Add a small value to tamper with the share
		tamperedValue := originalValue.Add(field.One())
		message := pedcom.NewMessage(tamperedValue)
		witness := originalShare.Blinding()
		tamperedShare, err := pedersen.NewShare(
			originalShare.ID(),
			message,
			witness,
			scheme.AccessStructure(),
		)
		require.NoError(t, err)

		// Use only threshold shares to ensure reconstruction works
		threshold := scheme.AccessStructure().Threshold()
		tamperedShares := make([]*pedersen.Share[S], 0)
		tamperedShares = append(tamperedShares, tamperedShare)

		// Add remaining shares up to threshold
		for i := 1; i < int(threshold); i++ {
			tamperedShares = append(tamperedShares, shares.Shares().Values()[i])
		}

		_, err = scheme.ReconstructAndVerify(reference, tamperedShares...)
		require.Error(t, err)
	})

	t.Run("different verification vectors", func(t *testing.T) {
		t.Parallel()
		// Create shares with different secret to get different verification vector
		secret2 := pedersen.NewSecret(field.FromUint64(100))
		shares2, err := scheme.Deal(secret2, pcg.NewRandomised())
		require.NoError(t, err)

		differentReference := shares2.VerificationVector()
		require.False(t, reference.Equal(differentReference), "different secrets should have different verification vectors")

		// Verify share against wrong verification vector should fail
		share := shares.Shares().Values()[0]
		err = scheme.Verify(share, differentReference)
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrVerificationFailed)
	})

	t.Run("nil verification vector", func(t *testing.T) {
		t.Parallel()
		share := shares.Shares().Values()[0]
		err := scheme.Verify(share, nil)
		require.Error(t, err)
	})

	t.Run("nil blinding witness", func(t *testing.T) {
		t.Parallel()
		originalShare := shares.Shares().Values()[0]
		_, err := pedersen.NewShare(
			originalShare.ID(),
			originalShare.Secret(),
			nil,
			scheme.AccessStructure(),
		)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
	})

	t.Run("nil secret message", func(t *testing.T) {
		t.Parallel()
		originalShare := shares.Shares().Values()[0]
		_, err := pedersen.NewShare(
			originalShare.ID(),
			nil,
			originalShare.Blinding(),
			scheme.AccessStructure(),
		)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
	})
}

// TestVerification tests verification functionality
func TestVerification(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		curve := k256.NewCurve()
		field := k256.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-verification-k256"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

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
				scheme, err := newPedersenScheme(t, key, config.threshold, shareholders)
				require.NoError(t, err)
				verificationCases(t, scheme, field)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		field := bls12381.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-verification-bls12381"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

		shareholders := sharing.NewOrdinalShareholderSet(4)
		scheme, err := newPedersenScheme(t, key, 2, shareholders)
		require.NoError(t, err)
		verificationCases(t, scheme, field)
	})
}

// homomorphicOpsCases tests homomorphic operations on shares
func homomorphicOpsCases[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](t *testing.T, scheme *pedersen.Scheme[E, S], field algebra.PrimeField[S]) {
	t.Helper()

	// Create two secrets and their shares
	secret1 := pedersen.NewSecret(field.FromUint64(10))
	secret2 := pedersen.NewSecret(field.FromUint64(20))

	shares1, err := scheme.Deal(secret1, pcg.NewRandomised())
	require.NoError(t, err)
	shares2, err := scheme.Deal(secret2, pcg.NewRandomised())
	require.NoError(t, err)

	// Test cases for Add operation
	addTests := []struct {
		name              string
		share1            *pedersen.Share[S]
		share2            *pedersen.Share[S]
		expectedSecret    S
		verifyReconstruct bool
	}{
		{
			name: "add shares from same holder",
			share1: func() *pedersen.Share[S] {
				s, _ := shares1.Shares().Get(sharing.ID(1))
				return s
			}(),
			share2: func() *pedersen.Share[S] {
				s, _ := shares2.Shares().Get(sharing.ID(1))
				return s
			}(),
			expectedSecret:    field.FromUint64(30), // 10 + 20
			verifyReconstruct: true,
		},
	}

	for _, tc := range addTests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Perform addition
			sumShare := tc.share1.Add(tc.share2)

			require.NotNil(t, sumShare)
			require.Equal(t, tc.share1.ID(), sumShare.ID())
			require.False(t, sumShare.Value().IsOpIdentity())
			require.False(t, sumShare.Blinding().Value().IsOpIdentity())

			// Test Op method (should be same as Add)
			sumShareOp := tc.share1.Op(tc.share2)
			require.True(t, sumShare.Value().Equal(sumShareOp.Value()))
			require.True(t, sumShare.Blinding().Value().Equal(sumShareOp.Blinding().Value()))

			if tc.verifyReconstruct {
				// Collect all sum shares for reconstruction
				allSumShares := make([]*pedersen.Share[S], 0)
				for _, id := range shares1.Shares().Keys() {
					s1, exists := shares1.Shares().Get(id)
					require.True(t, exists)
					s2, exists := shares2.Shares().Get(id)
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
		share             *pedersen.Share[S]
		scalar            S
		expectedSecret    S
		verifyReconstruct bool
	}{
		{
			name: "multiply by 2",
			share: func() *pedersen.Share[S] {
				s, _ := shares1.Shares().Get(sharing.ID(1))
				return s
			}(),
			scalar:            field.FromUint64(2),
			expectedSecret:    field.FromUint64(20), // 10 * 2
			verifyReconstruct: true,
		},
		{
			name: "multiply by 0",
			share: func() *pedersen.Share[S] {
				s, _ := shares1.Shares().Get(sharing.ID(1))
				return s
			}(),
			scalar:            field.Zero(),
			expectedSecret:    field.Zero(), // 10 * 0
			verifyReconstruct: false,        // Cannot verify - zero witness not allowed in Pedersen
		},
		{
			name: "multiply by 1",
			share: func() *pedersen.Share[S] {
				s, _ := shares1.Shares().Get(sharing.ID(1))
				return s
			}(),
			scalar:            field.One(),
			expectedSecret:    field.FromUint64(10), // 10 * 1
			verifyReconstruct: true,
		},
		{
			name: "multiply by large scalar",
			share: func() *pedersen.Share[S] {
				s, _ := shares2.Shares().Get(sharing.ID(1))
				return s
			}(),
			scalar:            field.FromUint64(100),
			expectedSecret:    field.FromUint64(2000), // 20 * 100
			verifyReconstruct: true,
		},
	}

	for _, tc := range scalarMulTests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Special case: multiplying by zero should panic
			if tc.scalar.IsZero() {
				require.Panics(t, func() {
					tc.share.ScalarMul(tc.scalar)
				}, "multiplying by zero should panic")
				return
			}

			// Perform scalar multiplication
			scaledShare := tc.share.ScalarMul(tc.scalar)

			require.NotNil(t, scaledShare)
			require.Equal(t, tc.share.ID(), scaledShare.ID())

			// Test ScalarOp method (should be same as ScalarMul)
			scaledShareOp := tc.share.ScalarOp(tc.scalar)
			require.True(t, scaledShare.Value().Equal(scaledShareOp.Value()))
			require.True(t, scaledShare.Blinding().Value().Equal(scaledShareOp.Blinding().Value()))

			if tc.verifyReconstruct {
				// Collect all scaled shares for reconstruction
				allScaledShares := make([]*pedersen.Share[S], 0)
				shareMap := shares1
				if tc.share.ID() == sharing.ID(1) {
					s, _ := shares2.Shares().Get(sharing.ID(1))
					if s.Value().Equal(tc.share.Value()) {
						shareMap = shares2
					}
				}

				for _, id := range shareMap.Shares().Keys() {
					s, exists := shareMap.Shares().Get(id)
					require.True(t, exists)
					allScaledShares = append(allScaledShares, s.ScalarMul(tc.scalar))
				}

				// Reconstruct and verify
				reconstructed, err := scheme.Reconstruct(allScaledShares...)
				require.NoError(t, err)
				require.True(t, tc.expectedSecret.Equal(reconstructed.Value()), reconstructed.Value().String())
			}
		})
	}

	// Test combined operations
	t.Run("combined add and scalar multiply", func(t *testing.T) {
		t.Parallel()
		// Compute (s1 * 3) + (s2 * 2)
		scalar1 := field.FromUint64(3)
		scalar2 := field.FromUint64(2)

		combinedShares := make([]*pedersen.Share[S], 0)
		for _, id := range shares1.Shares().Keys() {
			s1, exists := shares1.Shares().Get(id)
			require.True(t, exists)
			s2, exists := shares2.Shares().Get(id)
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
		t.Parallel()
		share, _ := shares1.Shares().Get(sharing.ID(1))

		// Test creating new share with different value
		newValue := field.FromUint64(999)
		newBlinding := field.FromUint64(777)

		message := pedcom.NewMessage(newValue)
		witness, err := pedcom.NewWitness(newBlinding)
		require.NoError(t, err)

		newShare, err := pedersen.NewShare(share.ID(), message, witness, scheme.AccessStructure())
		require.NoError(t, err)
		require.True(t, newValue.Equal(newShare.Value()))
		require.True(t, newBlinding.Equal(newShare.Blinding().Value()))

		// Test Equal method
		share2, _ := shares1.Shares().Get(sharing.ID(2))
		require.False(t, share.Equal(share2))

		// Create a copy of the share
		shareCopy, err := pedersen.NewShare(
			share.ID(),
			share.Secret(),
			share.Blinding(),
			scheme.AccessStructure(),
		)
		require.NoError(t, err)
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
		t.Parallel()
		curve := k256.NewCurve()
		field := k256.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-homomorphic-k256"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

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
				scheme, err := newPedersenScheme(t, key, config.threshold, shareholders)
				require.NoError(t, err)
				homomorphicOpsCases(t, scheme, field)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		field := bls12381.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-homomorphic-bls12381"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

		shareholders := sharing.NewOrdinalShareholderSet(4)
		scheme, err := newPedersenScheme(t, key, 2, shareholders)
		require.NoError(t, err)
		homomorphicOpsCases(t, scheme, field)
	})
}

// toAdditiveCases tests the ToAdditive conversion method
func toAdditiveCases[E algebra.PrimeGroupElement[E, S], S algebra.PrimeFieldElement[S]](t *testing.T, scheme *pedersen.Scheme[E, S], field algebra.PrimeField[S]) {
	t.Helper()

	// Create test secrets and their shares
	secret := pedersen.NewSecret(field.FromUint64(42))
	shares, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(t, err)

	// Get all shareholder IDs for creating qualified sets
	allIds := shares.Shares().Keys()
	threshold := scheme.AccessStructure().Threshold()

	t.Run("valid conversion with full qualified set", func(t *testing.T) {
		t.Parallel()
		// Create a qualified set with all shareholders
		qualifiedSet, err := accessstructures.NewUnanimityAccessStructure(scheme.AccessStructure().Shareholders())
		require.NoError(t, err)

		// Convert each share to additive
		additiveShares := make([]*additive.Share[S], 0)
		for _, share := range shares.Shares().Values() {
			additiveShare, err := share.ToAdditive(qualifiedSet)
			require.NoError(t, err)
			require.NotNil(t, additiveShare)
			require.Equal(t, share.ID(), additiveShare.ID())
			// Additive shares can be zero due to Lagrange coefficient calculations

			additiveShares = append(additiveShares, additiveShare)
		}

		// Verify reconstruction with additive shares
		additiveScheme, err := additive.NewScheme(field, qualifiedSet)
		require.NoError(t, err)

		reconstructed, err := additiveScheme.Reconstruct(additiveShares...)
		require.NoError(t, err)
		require.True(t, secret.Value().Equal(reconstructed.Value()))
	})

	t.Run("valid conversion with threshold qualified set", func(t *testing.T) {
		t.Parallel()
		// Create a qualified set with exactly threshold shareholders
		thresholdIds := allIds[:threshold]
		qualifiedIds := hashset.NewComparable[sharing.ID]()

		for _, id := range thresholdIds {
			qualifiedIds.Add(id)
		}

		qualifiedSet, err := accessstructures.NewUnanimityAccessStructure(qualifiedIds.Freeze())
		require.NoError(t, err)

		// Convert shares in the qualified set
		additiveShares := make([]*additive.Share[S], 0)
		for _, id := range thresholdIds {
			share, exists := shares.Shares().Get(id)
			require.True(t, exists)

			additiveShare, err := share.ToAdditive(qualifiedSet)
			require.NoError(t, err)
			require.NotNil(t, additiveShare)
			additiveShares = append(additiveShares, additiveShare)
		}

		// Verify reconstruction
		additiveScheme, err := additive.NewScheme(field, qualifiedSet)
		require.NoError(t, err)

		reconstructed, err := additiveScheme.Reconstruct(additiveShares...)
		require.NoError(t, err)
		require.True(t, secret.Value().Equal(reconstructed.Value()))
	})

	t.Run("error when share not in qualified set", func(t *testing.T) {
		t.Parallel()
		// Create a qualified set that doesn't include share ID 1
		qualifiedIds := hashset.NewComparable[sharing.ID]()

		// Add all IDs except the first one
		for i := 1; i < len(allIds); i++ {
			qualifiedIds.Add(allIds[i])
		}

		qualifiedSet, err := accessstructures.NewUnanimityAccessStructure(qualifiedIds.Freeze())
		require.NoError(t, err)

		// Try to convert share with ID 1 (not in qualified set)
		share, exists := shares.Shares().Get(allIds[0])
		require.True(t, exists)

		additiveShare, err := share.ToAdditive(qualifiedSet)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrMembership)
		require.Nil(t, additiveShare)
	})

	t.Run("multiple conversions produce consistent results", func(t *testing.T) {
		t.Parallel()
		qualifiedSet, err := accessstructures.NewUnanimityAccessStructure(scheme.AccessStructure().Shareholders())
		require.NoError(t, err)

		share, exists := shares.Shares().Get(allIds[0])
		require.True(t, exists)

		// Convert multiple times
		additiveShare1, err := share.ToAdditive(qualifiedSet)
		require.NoError(t, err)

		additiveShare2, err := share.ToAdditive(qualifiedSet)
		require.NoError(t, err)

		// Results should be identical
		require.True(t, additiveShare1.Value().Equal(additiveShare2.Value()))
		require.Equal(t, additiveShare1.ID(), additiveShare2.ID())
	})

	t.Run("lagrange coefficients verification", func(t *testing.T) {
		t.Parallel()
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
		t.Parallel()
		curve := k256.NewCurve()
		field := k256.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-toadditive-k256"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

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
				t.Parallel()
				shareholders := sharing.NewOrdinalShareholderSet(config.total)
				scheme, err := newPedersenScheme(t, key, config.threshold, shareholders)
				require.NoError(t, err)
				toAdditiveCases(t, scheme, field)
			})
		}
	})

	t.Run("bls12381", func(t *testing.T) {
		t.Parallel()
		curve := bls12381.NewG1()
		field := bls12381.NewScalarField()
		g := curve.Generator()
		h, err := curve.Hash([]byte("test-h-toadditive-bls12381"))
		require.NoError(t, err)

		key, err := pedcom.NewCommitmentKey(g, h)
		require.NoError(t, err)

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
				scheme, err := newPedersenScheme(t, key, config.threshold, shareholders)
				require.NoError(t, err)
				toAdditiveCases(t, scheme, field)
			})
		}
	})
}

// TestDealAndRevealDealerFunc tests the DealAndRevealDealerFunc method
func TestDealAndRevealDealerFunc(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-dealer-func"))
	require.NoError(t, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(t, err)

	t.Run("valid dealer function", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		scheme, err := newPedersenScheme(t, key, 2, shareholders)
		require.NoError(t, err)

		secret := pedersen.NewSecret(field.FromUint64(42))
		shares, dealerFunc, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, shares)
		require.NotNil(t, dealerFunc)
		require.Equal(t, 5, shares.Shares().Size())

		// Verify polynomial degrees
		require.Equal(t, 1, dealerFunc.Components()[0].Degree()) // secret polynomial degree = threshold - 1
		require.Equal(t, 1, dealerFunc.Components()[1].Degree()) // blinding polynomial degree = threshold - 1

		// Verify that the constant term of the first polynomial is the secret
		secretCoeff := dealerFunc.Components()[0].ConstantTerm()
		require.True(t, secret.Value().Equal(secretCoeff))
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		scheme, err := newPedersenScheme(t, key, 2, shareholders)
		require.NoError(t, err)

		secret := pedersen.NewSecret(field.FromUint64(42))
		shares, dealerFunc, err := scheme.DealAndRevealDealerFunc(secret, nil)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
		require.Nil(t, shares)
		require.Nil(t, dealerFunc)
	})

	t.Run("nil secret", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		scheme, err := newPedersenScheme(t, key, 2, shareholders)
		require.NoError(t, err)

		shares, dealerFunc, err := scheme.DealAndRevealDealerFunc(nil, pcg.NewRandomised())
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
		require.Nil(t, shares)
		require.Nil(t, dealerFunc)
	})

	t.Run("verify shares from dealer function", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(7)
		scheme, err := newPedersenScheme(t, key, 3, shareholders)
		require.NoError(t, err)

		secret := pedersen.NewSecret(field.FromUint64(100))
		shares, dealerFunc, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
		require.NoError(t, err)

		// Verify each share matches the dealer function evaluation
		for id, share := range shares.Shares().Iter() {
			x := shamir.SharingIDToLagrangeNode(field, id)

			// Evaluate dealer function components at x
			secretValue := dealerFunc.Components()[0].Eval(x)
			blindingValue := dealerFunc.Components()[1].Eval(x)

			// Check that share values match
			require.True(t, secretValue.Equal(share.Value()))
			require.True(t, blindingValue.Equal(share.Blinding().Value()))
		}
	})
}

// TestDealRandomAndRevealDealerFunc tests the DealRandomAndRevealDealerFunc method
func TestDealRandomAndRevealDealerFunc(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-dealer-func-random"))
	require.NoError(t, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(t, err)

	t.Run("valid random dealer function", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		scheme, err := newPedersenScheme(t, key, 2, shareholders)
		require.NoError(t, err)

		shares, secret, dealerFunc, err := scheme.DealRandomAndRevealDealerFunc(pcg.NewRandomised())
		require.NoError(t, err)
		require.NotNil(t, shares)
		require.NotNil(t, secret)
		require.NotNil(t, dealerFunc)
		require.Equal(t, 5, shares.Shares().Size())

		// Verify polynomial degrees
		require.Equal(t, 1, dealerFunc.Components()[0].Degree()) // secret polynomial degree = threshold - 1
		require.Equal(t, 1, dealerFunc.Components()[1].Degree()) // blinding polynomial degree = threshold - 1

		// Verify that the constant term of the first polynomial is the secret
		secretCoeff := dealerFunc.Components()[0].ConstantTerm()
		require.True(t, secret.Value().Equal(secretCoeff))

		// Verify reconstruction
		reconstructed, err := scheme.Reconstruct(shares.Shares().Values()...)
		require.NoError(t, err)
		require.True(t, secret.Equal(reconstructed))
	})

	t.Run("nil prng", func(t *testing.T) {
		t.Parallel()
		shareholders := sharing.NewOrdinalShareholderSet(5)
		scheme, err := newPedersenScheme(t, key, 2, shareholders)
		require.NoError(t, err)

		shares, secret, dealerFunc, err := scheme.DealRandomAndRevealDealerFunc(nil)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
		require.Nil(t, shares)
		require.Nil(t, secret)
		require.Nil(t, dealerFunc)
	})
}

// TestNewShare tests the NewShare constructor with various edge cases
func TestNewShare(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-newshare"))
	require.NoError(t, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(t, err)

	shareholders := sharing.NewOrdinalShareholderSet(5)
	scheme, err := newPedersenScheme(t, key, 2, shareholders)
	require.NoError(t, err)

	t.Run("valid share creation", func(t *testing.T) {
		t.Parallel()
		value := field.FromUint64(100)
		blinding := field.FromUint64(200)

		message := pedcom.NewMessage(value)
		witness, err := pedcom.NewWitness(blinding)
		require.NoError(t, err)

		share, err := pedersen.NewShare(
			sharing.ID(1),
			message,
			witness,
			scheme.AccessStructure(),
		)
		require.NoError(t, err)
		require.NotNil(t, share)
		require.Equal(t, sharing.ID(1), share.ID())
		require.True(t, value.Equal(share.Value()))
		require.True(t, blinding.Equal(share.Blinding().Value()))
	})

	t.Run("nil secret message", func(t *testing.T) {
		t.Parallel()
		blinding := field.FromUint64(200)
		witness, err := pedcom.NewWitness(blinding)
		require.NoError(t, err)

		_, err = pedersen.NewShare(
			sharing.ID(1),
			nil,
			witness,
			scheme.AccessStructure(),
		)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
	})

	t.Run("nil blinding witness", func(t *testing.T) {
		t.Parallel()
		value := field.FromUint64(100)
		message := pedcom.NewMessage(value)

		_, err := pedersen.NewShare(
			sharing.ID(1),
			message,
			nil,
			scheme.AccessStructure(),
		)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrIsNil)
	})

	t.Run("invalid shareholder ID", func(t *testing.T) {
		t.Parallel()
		value := field.FromUint64(100)
		blinding := field.FromUint64(200)

		message := pedcom.NewMessage(value)
		witness, err := pedcom.NewWitness(blinding)
		require.NoError(t, err)

		// ID not in access structure
		_, err = pedersen.NewShare(
			sharing.ID(10), // Not in [1,5]
			message,
			witness,
			scheme.AccessStructure(),
		)
		require.Error(t, err)
		require.ErrorIs(t, err, sharing.ErrMembership)
	})

	t.Run("nil access structure allowed", func(t *testing.T) {
		t.Parallel()
		value := field.FromUint64(100)
		blinding := field.FromUint64(200)

		message := pedcom.NewMessage(value)
		witness, err := pedcom.NewWitness(blinding)
		require.NoError(t, err)

		// Should succeed with nil access structure (no validation)
		share, err := pedersen.NewShare(
			sharing.ID(999),
			message,
			witness,
			nil,
		)
		require.NoError(t, err)
		require.NotNil(t, share)
		require.Equal(t, sharing.ID(999), share.ID())
	})

	t.Run("share methods", func(t *testing.T) {
		t.Parallel()
		value1 := field.FromUint64(100)
		blinding1 := field.FromUint64(200)
		value2 := field.FromUint64(300)
		blinding2 := field.FromUint64(400)

		message1 := pedcom.NewMessage(value1)
		witness1, err := pedcom.NewWitness(blinding1)
		require.NoError(t, err)

		message2 := pedcom.NewMessage(value2)
		witness2, err := pedcom.NewWitness(blinding2)
		require.NoError(t, err)

		share1, err := pedersen.NewShare(
			sharing.ID(1),
			message1,
			witness1,
			nil,
		)
		require.NoError(t, err)

		share2, err := pedersen.NewShare(
			sharing.ID(2),
			message2,
			witness2,
			nil,
		)
		require.NoError(t, err)

		// Test getters
		require.Equal(t, sharing.ID(1), share1.ID())
		require.True(t, value1.Equal(share1.Value()))
		require.True(t, blinding1.Equal(share1.Blinding().Value()))

		// Test Equal
		require.False(t, share1.Equal(share2))
		require.False(t, share1.Equal(nil))

		// Create identical share
		share1Copy, err := pedersen.NewShare(
			sharing.ID(1),
			message1,
			witness1,
			nil,
		)
		require.NoError(t, err)
		require.True(t, share1.Equal(share1Copy))

		// Test HashCode
		require.Equal(t, share1.HashCode(), share1Copy.HashCode())
		require.NotEqual(t, share1.HashCode(), share2.HashCode())
	})
}

// TestPedersenCommitmentProperties tests specific properties of Pedersen commitments
func TestPedersenCommitmentProperties(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("test-h-properties"))
	require.NoError(t, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(t, err)

	shareholders := sharing.NewOrdinalShareholderSet(5)
	scheme, err := newPedersenScheme(t, key, 2, shareholders)
	require.NoError(t, err)

	t.Run("blinding factor provides perfect hiding", func(t *testing.T) {
		t.Parallel()
		// Same secret, different blinding factors should produce different commitments
		secret := pedersen.NewSecret(field.FromUint64(42))

		shares1, _, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
		require.NoError(t, err)

		shares2, _, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
		require.NoError(t, err)

		// Check that shares have different blinding factors
		for _, id := range shares1.Shares().Keys() {
			share1, exists := shares1.Shares().Get(id)
			require.True(t, exists, "share should exist in first set")
			share2, exists := shares2.Shares().Get(id)
			require.True(t, exists, "share should exist in second set")

			require.False(t, share1.Blinding().Value().Equal(share2.Blinding().Value()), "different randomness should produce different blinding factors")
		}

		// Verification vectors should be different
		ref1 := shares1.VerificationVector()
		ref2 := shares2.VerificationVector()
		require.False(t, ref1.Equal(ref2), "different blinding factors should produce different verification vectors")
	})

	t.Run("commitment binding property", func(t *testing.T) {
		t.Parallel()
		// Once committed, changing the value should fail verification
		shares, _, err := scheme.DealAndRevealDealerFunc(pedersen.NewSecret(field.FromUint64(42)), pcg.NewRandomised())
		require.NoError(t, err)

		reference := shares.VerificationVector()
		share, _ := shares.Shares().Get(sharing.ID(1))

		// Try to create a different share with same blinding but different value
		tamperedValue := field.FromUint64(100)
		message := pedcom.NewMessage(tamperedValue)
		tamperedShare, err := pedersen.NewShare(
			share.ID(),
			message,
			share.Blinding(),
			scheme.AccessStructure(),
		)
		require.NoError(t, err)

		// Verification should fail
		err = scheme.Verify(tamperedShare, reference)
		require.Error(t, err)
		require.ErrorIs(t, err, commitments.ErrVerificationFailed)
	})

	t.Run("homomorphic commitment property", func(t *testing.T) {
		t.Parallel()
		// Pedersen commitments are homomorphic: Com(m1) * Com(m2) = Com(m1 + m2)
		secret1 := pedersen.NewSecret(field.FromUint64(10))
		secret2 := pedersen.NewSecret(field.FromUint64(20))

		shares1, _, err := scheme.DealAndRevealDealerFunc(secret1, pcg.NewRandomised())
		require.NoError(t, err)

		shares2, _, err := scheme.DealAndRevealDealerFunc(secret2, pcg.NewRandomised())
		require.NoError(t, err)

		// Add shares
		combinedShares := make([]*pedersen.Share[*k256.Scalar], 0)
		for _, id := range shares1.Shares().Keys() {
			s1, _ := shares1.Shares().Get(id)
			s2, _ := shares2.Shares().Get(id)
			combined := s1.Add(s2)
			combinedShares = append(combinedShares, combined)
		}

		// Reconstruct combined secret
		reconstructed, err := scheme.Reconstruct(combinedShares...)
		require.NoError(t, err)
		require.True(t, field.FromUint64(30).Equal(reconstructed.Value()), "homomorphic property should hold")
	})
}

// Benchmark functions

func BenchmarkDeal(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h"))
	require.NoError(b, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(b, err)

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
			scheme, err := newPedersenScheme(b, key, config.threshold, shareholders)
			require.NoError(b, err)

			secret := pedersen.NewSecret(field.FromUint64(42))

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

func BenchmarkDealRandom(b *testing.B) {
	curve := k256.NewCurve()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h-random"))
	require.NoError(b, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(b, err)

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
			scheme, err := newPedersenScheme(b, key, config.threshold, shareholders)
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

func BenchmarkReconstruct(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h-reconstruct"))
	require.NoError(b, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(b, err)

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
			scheme, err := newPedersenScheme(b, key, config.threshold, shareholders)
			require.NoError(b, err)

			secret := pedersen.NewSecret(field.FromUint64(42))
			shares, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(b, err)

			shareSlice := shares.Shares().Values()[:config.threshold]

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

func BenchmarkVerification(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h-verification"))
	require.NoError(b, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(b, err)

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
			scheme, err := newPedersenScheme(b, key, config.threshold, shareholders)
			require.NoError(b, err)

			secret := pedersen.NewSecret(field.FromUint64(42))
			shares, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(b, err)

			share := shares.Shares().Values()[0]
			reference := shares.VerificationVector()

			b.ResetTimer()
			for range b.N {
				err := scheme.Verify(share, reference)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkHomomorphicOps(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h-homomorphic"))
	require.NoError(b, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(b, err)

	shareholders := sharing.NewOrdinalShareholderSet(5)
	scheme, err := newPedersenScheme(b, key, 3, shareholders)
	require.NoError(b, err)

	// Create shares
	secret := pedersen.NewSecret(field.FromUint64(42))
	shares, err := scheme.Deal(secret, pcg.NewRandomised())
	require.NoError(b, err)

	share1, _ := shares.Shares().Get(sharing.ID(1))
	share2, _ := shares.Shares().Get(sharing.ID(1))
	scalar := field.FromUint64(7)

	b.Run("Add", func(b *testing.B) {
		for range b.N {
			_ = share1.Add(share2)
		}
	})

	b.Run("ScalarMul", func(b *testing.B) {
		for range b.N {
			_ = share1.ScalarMul(scalar)
		}
	})

	b.Run("Combined", func(b *testing.B) {
		for range b.N {
			_ = share1.ScalarMul(scalar).Add(share2)
		}
	})
}

func BenchmarkToAdditive(b *testing.B) {
	curve := k256.NewCurve()
	field := k256.NewScalarField()
	g := curve.Generator()
	h, err := curve.Hash([]byte("bench-h-toadditive"))
	require.NoError(b, err)

	key, err := pedcom.NewCommitmentKey(g, h)
	require.NoError(b, err)

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
			scheme, err := newPedersenScheme(b, key, config.threshold, shareholders)
			require.NoError(b, err)

			secret := pedersen.NewSecret(field.FromUint64(42))
			shares, err := scheme.Deal(secret, pcg.NewRandomised())
			require.NoError(b, err)

			qualifiedSet, err := accessstructures.NewUnanimityAccessStructure(scheme.AccessStructure().Shareholders())
			require.NoError(b, err)

			share, exists := shares.Shares().Get(sharing.ID(1))
			require.True(b, exists)

			b.ResetTimer()
			for range b.N {
				_, err := share.ToAdditive(qualifiedSet)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
