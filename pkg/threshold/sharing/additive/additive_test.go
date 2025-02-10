package additive_test

import (
	crand "crypto/rand"
	"fmt"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/pasta"
	"github.com/bronlabs/krypton-primitives/pkg/base/types"
	"github.com/bronlabs/krypton-primitives/pkg/base/utils/maputils"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/k256"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves/p256"
	"github.com/bronlabs/krypton-primitives/pkg/threshold/sharing/additive"
)

var supportedCurves = []curves.Curve{
	k256.NewCurve(),
	p256.NewCurve(),
	edwards25519.NewCurve(),
	pasta.NewPallasCurve(),
	pasta.NewVestaCurve(),
	bls12381.NewG1(),
	bls12381.NewG2(),
}

var supportedTotals = []uint{2, 3, 5}

func TestDealAndOpen(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secret, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				shares, err := dealer.Deal(secret, prng)
				require.NoError(t, err)
				require.NotNil(t, shares)
				require.Len(t, shares, int(total))

				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecret)
				require.True(t, secret.Equal(recomputedSecret))
			})
		}
	}
}

func TestShareAndOpenInExponent(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secret, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretInExp := curve.ScalarBaseMult(secret)

				shares, err := dealer.Deal(secret, prng)
				require.NoError(t, err)
				require.NotNil(t, shares)
				require.Len(t, shares, int(total))
				sharesInExponent := maputils.MapValues(shares, func(_ types.SharingID, s *additive.Share) *additive.ShareInExp { return s.Exp() })

				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExponent))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecretInExp)
				require.True(t, secretInExp.Equal(recomputedSecretInExp))
			})
		}
	}
}

func TestLinearAdd(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))

				sharesB, err := dealer.Deal(secretB, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesB)
				require.Len(t, sharesB, int(total))

				secret := secretA.Add(secretB)
				shares := sharing.AddSharesMap(dealer, sharesA, sharesB)

				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecret)
				require.Zero(t, secret.Cmp(recomputedSecret))
			})
		}
	}
}

func TestLinearAddValue(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))

				secret := secretA.Add(secretB)
				shares := sharing.AddSharesValueMap(dealer, sharesA, secretB)

				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecret)
				require.Zero(t, secret.Cmp(recomputedSecret))
			})
		}
	}
}

func TestLinearSub(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))

				sharesB, err := dealer.Deal(secretB, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesB)
				require.Len(t, sharesB, int(total))

				secret := secretA.Sub(secretB)
				shares := sharing.SubSharesMap(dealer, sharesA, sharesB)

				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecret)
				require.Zero(t, secret.Cmp(recomputedSecret))
			})
		}
	}
}

func TestLinearSubValue(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))

				secret := secretA.Sub(secretB)
				shares := sharing.SubSharesValueMap(dealer, sharesA, secretB)

				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecret)
				require.Zero(t, secret.Cmp(recomputedSecret))
			})
		}
	}
}

func TestLinearNeg(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))

				secret := secretA.Neg()
				shares := sharing.NegSharesMap(dealer, sharesA)

				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecret)
				require.Zero(t, secret.Cmp(recomputedSecret))
			})
		}
	}
}

func TestLinearScalarMul(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				scalar, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))

				secret := secretA.Mul(scalar)
				shares := sharing.MulSharesMap(dealer, sharesA, scalar)

				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecret)
				require.Zero(t, secret.Cmp(recomputedSecret))
			})
		}
	}
}

func TestLinearAddInExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretAInExp := curve.ScalarBaseMult(secretA)
				secretB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretBInExp := curve.ScalarBaseMult(secretB)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))
				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *additive.Share) *additive.ShareInExp { return s.Exp() })

				sharesB, err := dealer.Deal(secretB, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesB)
				require.Len(t, sharesB, int(total))
				sharesBInExp := maputils.MapValues(sharesB, func(_ types.SharingID, s *additive.Share) *additive.ShareInExp { return s.Exp() })

				secretInExp := secretAInExp.Add(secretBInExp)
				sharesInExp := maputils.Join(sharesAInExp, sharesBInExp, func(_ types.SharingID, l, r *additive.ShareInExp) *additive.ShareInExp { return l.Add(r) })

				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecretInExp)
				require.True(t, secretInExp.Equal(recomputedSecretInExp))
			})
		}
	}
}

func TestLinearAddValueInExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretAInExp := curve.ScalarBaseMult(secretA)

				secretB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretBInExp := curve.ScalarBaseMult(secretB)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))
				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *additive.Share) *additive.ShareInExp { return s.Exp() })

				secretInExp := secretAInExp.Add(secretBInExp)
				sharesInExp := maputils.MapValues(sharesAInExp, func(_ types.SharingID, s *additive.ShareInExp) *additive.ShareInExp { return s.AddValue(secretBInExp) })

				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecretInExp)
				require.True(t, secretInExp.Equal(recomputedSecretInExp))
			})
		}
	}
}

func TestLinearSubInExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretAInExp := curve.ScalarBaseMult(secretA)
				secretB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretBInExp := curve.ScalarBaseMult(secretB)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))
				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *additive.Share) *additive.ShareInExp { return s.Exp() })

				sharesB, err := dealer.Deal(secretB, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesB)
				require.Len(t, sharesB, int(total))
				sharesBInExp := maputils.MapValues(sharesB, func(_ types.SharingID, s *additive.Share) *additive.ShareInExp { return s.Exp() })

				secretInExp := secretAInExp.Sub(secretBInExp)
				sharesInExp := maputils.Join(sharesAInExp, sharesBInExp, func(_ types.SharingID, l, r *additive.ShareInExp) *additive.ShareInExp { return l.Sub(r) })

				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecretInExp)
				require.True(t, secretInExp.Equal(recomputedSecretInExp))
			})
		}
	}
}

func TestLinearSubValueInExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretAInExp := curve.ScalarBaseMult(secretA)

				secretB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)
				secretBInExp := curve.ScalarBaseMult(secretB)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))
				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *additive.Share) *additive.ShareInExp { return s.Exp() })

				secretInExp := secretAInExp.Sub(secretBInExp)
				sharesInExp := maputils.MapValues(sharesAInExp, func(_ types.SharingID, s *additive.ShareInExp) *additive.ShareInExp { return s.SubValue(secretBInExp) })

				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecretInExp)
				require.True(t, secretInExp.Equal(recomputedSecretInExp))
			})
		}
	}
}

func TestLinearNegInExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))
				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *additive.Share) *additive.ShareInExp { return s.Exp() })

				secret := secretA.Neg()
				secretInExp := curve.ScalarBaseMult(secret)
				sharesInExp := maputils.MapValues(sharesAInExp, func(_ types.SharingID, s *additive.ShareInExp) *additive.ShareInExp { return s.Neg() })

				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecretInExp)
				require.True(t, secretInExp.Equal(recomputedSecretInExp))
			})
		}
	}
}

func TestLinearScalarMulInExp(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	for _, curve := range supportedCurves {
		for _, total := range supportedTotals {
			t.Run(fmt.Sprintf("%s_%d", curve.Name(), total), func(t *testing.T) {
				t.Parallel()

				dealer, err := additive.NewScheme(total, curve)
				require.NoError(t, err)
				require.NotNil(t, dealer)

				secretA, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				secretB, err := curve.ScalarField().Random(prng)
				require.NoError(t, err)

				sharesA, err := dealer.Deal(secretA, prng)
				require.NoError(t, err)
				require.NotNil(t, sharesA)
				require.Len(t, sharesA, int(total))
				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *additive.Share) *additive.ShareInExp { return s.Exp() })

				secret := secretA.Mul(secretB)
				secretInExp := curve.ScalarBaseMult(secret)
				sharesInExp := maputils.MapValues(sharesAInExp, func(_ types.SharingID, s *additive.ShareInExp) *additive.ShareInExp { return s.ScalarMul(secretB) })

				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
				require.NoError(t, err)
				require.NotNil(t, recomputedSecretInExp)
				require.True(t, secretInExp.Equal(recomputedSecretInExp))
			})
		}
	}
}
