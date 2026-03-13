package kw_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/mat"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing"
	"github.com/bronlabs/bron-crypto/pkg/mpc/sharing/scheme/kw"
)

// ---------------------------------------------------------------------------
// NewDealerFunc – construction
// ---------------------------------------------------------------------------

func TestNewDealerFunc_NilMSP(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	colMod, err := mat.NewMatrixModule(2, 1, field)
	require.NoError(t, err)
	col, err := colMod.NewRowMajor(field.One(), field.Zero())
	require.NoError(t, err)

	_, err = kw.NewDealerFunc(col, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestNewDealerFunc_NilRandomColumn(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	_, err := kw.NewDealerFunc(nil, scheme.MSP())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestNewDealerFunc_NotColumnVector(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	// Create a row vector (1 x 2) instead of column
	rowMod, err := mat.NewMatrixModule(1, 2, field)
	require.NoError(t, err)
	row, err := rowMod.NewRowMajor(field.One(), field.Zero())
	require.NoError(t, err)

	_, err = kw.NewDealerFunc(row, scheme.MSP())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrValue)
}

func TestNewDealerFunc_TooFewRows(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	// Column vector with only 1 row
	colMod, err := mat.NewMatrixModule(1, 1, field)
	require.NoError(t, err)
	col, err := colMod.NewRowMajor(field.One())
	require.NoError(t, err)

	_, err = kw.NewDealerFunc(col, scheme.MSP())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrValue)
}

func TestNewDealerFunc_DimensionMismatch(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	// MSP.D() is the number of columns in the MSP matrix.
	// Create a column vector with wrong number of rows (not matching D).
	wrongD := scheme.MSP().D() + 5
	colMod, err := mat.NewMatrixModule(wrongD, 1, field)
	require.NoError(t, err)
	col := colMod.Zero()

	_, err = kw.NewDealerFunc(col, scheme.MSP())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// DealerFunc – accessors and correctness
// ---------------------------------------------------------------------------

func TestDealerFunc_SecretMatchesReconstruction(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))

			_, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			// DealerFunc.Secret() should return the same secret value
			require.True(t, secret.Equal(df.Secret()),
				"DealerFunc.Secret() must match the dealt secret")
		})
	}
}

func TestDealerFunc_ShareOfMatchesDealOutput(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(99))

			out, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			// Each share from DealerFunc.ShareOf must match the share in DealerOutput
			for _, id := range fx.shareholders {
				dfShare, err := df.ShareOf(id)
				require.NoError(t, err)
				outShare, ok := out.Shares().Get(id)
				require.True(t, ok)
				require.True(t, dfShare.Equal(outShare),
					"DealerFunc.ShareOf(%d) must match DealerOutput share", id)
			}
		})
	}
}

func TestDealerFunc_ShareOfNonExistentID(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t) // shareholders {1,2,3}
	scheme := newKWScheme(t, field, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	_, err = df.ShareOf(999)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrMembership)
}

func TestDealerFunc_SharesReconstructToSecret(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(12345))

			_, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			// Collect shares via DealerFunc.ShareOf
			for _, qset := range fx.qualified {
				shares := make([]*kw.Share[*k256.Scalar], len(qset))
				for i, id := range qset {
					sh, err := df.ShareOf(id)
					require.NoError(t, err)
					shares[i] = sh
				}
				reconstructed, err := scheme.Reconstruct(shares...)
				require.NoError(t, err)
				require.True(t, secret.Equal(reconstructed),
					"shares from DealerFunc.ShareOf must reconstruct the secret for set %v", qset)
			}
		})
	}
}

func TestDealerFunc_Accessors(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.FromUint64(7)), pcg.NewRandomised())
	require.NoError(t, err)

	require.NotNil(t, df.RandomColumn())
	require.NotNil(t, df.MSP())
	require.NotNil(t, df.Lambda())

	// Lambda should be a column vector of size MSP.Size() x 1
	rows, cols := df.Lambda().Dimensions()
	require.Equal(t, int(df.MSP().Size()), rows)
	require.Equal(t, 1, cols)

	// RandomColumn should be a column vector of size MSP.D() x 1
	rRows, rCols := df.RandomColumn().Dimensions()
	require.Equal(t, int(df.MSP().D()), rRows)
	require.Equal(t, 1, rCols)
}

func TestDealerFunc_LambdaIsProductOfMSPAndRandomColumn(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.FromUint64(55)), pcg.NewRandomised())
	require.NoError(t, err)

	// Verify: lambda = M * randomColumn
	expected, err := df.MSP().Matrix().TryMul(df.RandomColumn())
	require.NoError(t, err)
	require.True(t, df.Lambda().Equal(expected),
		"lambda must equal MSP.Matrix * randomColumn")
}

// ---------------------------------------------------------------------------
// LiftDealerFunc – construction and error cases
// ---------------------------------------------------------------------------

func TestLiftDealerFunc_NilDealerFunc(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	_, err := kw.LiftDealerFunc(nil, curve.Generator())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestLiftDealerFunc_NilBasePoint(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	_, err = kw.LiftDealerFunc[*k256.Point](df, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestLiftDealerFunc_LiftedSecretMatchesScalarMul(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	curve := k256.NewCurve()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))

			_, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			ldf, err := kw.LiftDealerFunc(df, gen)
			require.NoError(t, err)

			// LiftedSecret should equal gen * secret
			expected := gen.ScalarOp(secret.Value())
			require.True(t, expected.Equal(ldf.LiftedSecret().Value()),
				"lifted secret should be basePoint * secret")
		})
	}
}

func TestLiftDealerFunc_LiftedShareMatchesManualLift(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	curve := k256.NewCurve()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(77))

			_, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			ldf, err := kw.LiftDealerFunc(df, gen)
			require.NoError(t, err)

			for _, id := range fx.shareholders {
				liftedShare, err := ldf.ShareOf(id)
				require.NoError(t, err)

				// Manually lift the scalar share
				scalarShare, err := df.ShareOf(id)
				require.NoError(t, err)
				manualLift, err := kw.LiftShare(scalarShare, gen)
				require.NoError(t, err)

				require.True(t, liftedShare.Equal(manualLift),
					"LiftDealerFunc.ShareOf(%d) must match LiftShare of scalar share", id)
			}
		})
	}
}

func TestLiftDealerFunc_ShareOfNonExistentID(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	curve := k256.NewCurve()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	ldf, err := kw.LiftDealerFunc(df, curve.Generator())
	require.NoError(t, err)

	_, err = ldf.ShareOf(999)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrMembership)
}

func TestLiftDealerFunc_Accessors(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	curve := k256.NewCurve()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.FromUint64(3)), pcg.NewRandomised())
	require.NoError(t, err)

	ldf, err := kw.LiftDealerFunc(df, curve.Generator())
	require.NoError(t, err)

	require.NotNil(t, ldf.VerificationVector())
	require.NotNil(t, ldf.MSP())
	require.NotNil(t, ldf.Lambda())
}

// ---------------------------------------------------------------------------
// NewLiftedDealerFunc – construction and error cases
// ---------------------------------------------------------------------------

func TestNewLiftedDealerFunc_NilVerificationVector(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	_, err := kw.NewLiftedDealerFunc[*k256.Point](nil, scheme.MSP())
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestNewLiftedDealerFunc_NilMSP(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	curve := k256.NewCurve()
	fx := thresholdFixture(t)
	scheme := newKWScheme(t, field, fx.ac)

	_, df, err := scheme.DealAndRevealDealerFunc(kw.NewSecret(field.One()), pcg.NewRandomised())
	require.NoError(t, err)

	vv, err := mat.Lift(df.RandomColumn(), curve.Generator())
	require.NoError(t, err)

	_, err = kw.NewLiftedDealerFunc(vv, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, sharing.ErrIsNil)
}

func TestNewLiftedDealerFunc_ConsistentWithLiftDealerFunc(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	curve := k256.NewCurve()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(42))

			_, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			// Method 1: LiftDealerFunc
			ldf1, err := kw.LiftDealerFunc(df, gen)
			require.NoError(t, err)

			// Method 2: NewLiftedDealerFunc from verification vector
			vv, err := mat.Lift(df.RandomColumn(), gen)
			require.NoError(t, err)
			ldf2, err := kw.NewLiftedDealerFunc(vv, df.MSP())
			require.NoError(t, err)

			// Both should produce the same lifted secret
			require.True(t, ldf1.LiftedSecret().Equal(ldf2.LiftedSecret()),
				"LiftDealerFunc and NewLiftedDealerFunc must produce the same lifted secret")

			// Both should produce the same lifted shares
			for _, id := range fx.shareholders {
				sh1, err := ldf1.ShareOf(id)
				require.NoError(t, err)
				sh2, err := ldf2.ShareOf(id)
				require.NoError(t, err)
				require.True(t, sh1.Equal(sh2),
					"lifted shares for ID %d must match between LiftDealerFunc and NewLiftedDealerFunc", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Feldman-style verification: lifted share from LiftedDealerFunc matches
// manual lift of scalar share (the core Feldman check)
// ---------------------------------------------------------------------------

func TestLiftedDealerFunc_FeldmanVerification(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	curve := k256.NewCurve()
	gen := curve.Generator()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)
			secret := kw.NewSecret(field.FromUint64(12345))

			_, df, err := scheme.DealAndRevealDealerFunc(secret, pcg.NewRandomised())
			require.NoError(t, err)

			// Build the "public" lifted dealer func from the verification vector only
			vv, err := mat.Lift(df.RandomColumn(), gen)
			require.NoError(t, err)
			ldf, err := kw.NewLiftedDealerFunc(vv, df.MSP())
			require.NoError(t, err)

			for _, id := range fx.shareholders {
				// Public computation: lifted share from verification vector
				liftedShare, err := ldf.ShareOf(id)
				require.NoError(t, err)

				// Shareholder computation: lift the scalar share
				scalarShare, err := df.ShareOf(id)
				require.NoError(t, err)
				manualLift, err := kw.LiftShare(scalarShare, gen)
				require.NoError(t, err)

				require.True(t, liftedShare.Equal(manualLift),
					"Feldman verification failed: lifted share from verification vector "+
						"must equal manually lifted scalar share for ID %d", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DealerFunc – random secrets round-trip
// ---------------------------------------------------------------------------

func TestDealerFunc_RandomSecretsRoundTrip(t *testing.T) {
	t.Parallel()

	field := k256.NewScalarField()
	prng := pcg.NewRandomised()

	for _, fx := range allFixtures(t) {
		t.Run(fx.name, func(t *testing.T) {
			t.Parallel()
			scheme := newKWScheme(t, field, fx.ac)

			for range 5 {
				out, secret, df, err := scheme.DealRandomAndRevealDealerFunc(prng)
				require.NoError(t, err)
				require.NotNil(t, out)
				require.NotNil(t, secret)

				// DealerFunc.Secret() must match the returned secret
				require.True(t, secret.Equal(df.Secret()))

				// Shares from DealerFunc must reconstruct the secret
				for _, qset := range fx.qualified {
					shares := make([]*kw.Share[*k256.Scalar], len(qset))
					for i, id := range qset {
						sh, err := df.ShareOf(id)
						require.NoError(t, err)
						shares[i] = sh
					}
					reconstructed, err := scheme.Reconstruct(shares...)
					require.NoError(t, err)
					require.True(t, secret.Equal(reconstructed))
				}
			}
		})
	}
}
