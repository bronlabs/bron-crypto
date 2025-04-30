package shamir_test

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/threshold/sharing/shamir"
)

//var supportedCurve = []curves.Curve{
//	k256.NewCurve(),
//	p256.NewCurve(),
//	edwards25519.NewCurve(),
//	pasta.NewPallasCurve(),
//	pasta.NewVestaCurve(),
//	bls12381.NewG1(),
//	bls12381.NewG2(),
//}

var supportedAccessStructures = []struct{ th, n uint }{
	{2, 2},
	{2, 3},
	{3, 3},
	{3, 5},
	{7, 18},
}

func TestShamirDealInvalidArgs(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		testShamirDealInvalidArgs(t, k256.NewScalarField())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		testShamirDealInvalidArgs(t, p256.NewScalarField())
	})
	t.Run("edwards25519", func(t *testing.T) {
		t.Parallel()
		testShamirDealInvalidArgs(t, edwards25519.NewScalarField())
	})
	t.Run("pallas", func(t *testing.T) {
		t.Parallel()
		testShamirDealInvalidArgs(t, pasta.NewPallasScalarField())
	})
	t.Run("vesta", func(t *testing.T) {
		t.Parallel()
		testShamirDealInvalidArgs(t, pasta.NewVestaScalarField())
	})
	t.Run("bls12381", func(t *testing.T) {
		t.Parallel()
		testShamirDealInvalidArgs(t, bls12381.NewScalarField())
	})
}

func testShamirDealInvalidArgs[SF fields.PrimeField[S], S fields.PrimeFieldElement[S]](tb testing.TB, scalarField SF) {
	tb.Helper()

	_, err := shamir.NewScheme(0, 0, scalarField)
	require.Error(tb, err)
}

// TODO: do the rest

//
//func testShamirOpenNoShares[SF fields.PrimeField[S], S fields.PrimeFieldElement[S]](tb testing.TB, scalarField SF, th, n uint) {
//	tb.Helper()
//	scheme, err := shamir.NewScheme(th, n, scalarField)
//	require.NoError(t, err)
//	require.NotNil(t, scheme)
//	_, err = scheme.Open()
//	require.Error(t, err)
//}

//func TestShamirOpenDuplicateShare(t *testing.T) {
//	t.Parallel()
//
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				scheme, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, scheme)
//				_, err = scheme.Open([]*shamir.Share{
//					{
//						Id:    1,
//						Value: curve.ScalarField().New(3),
//					},
//					{
//						Id:    1,
//						Value: curve.ScalarField().New(3),
//					},
//				}...)
//				require.Error(t, err)
//			})
//		}
//	}
//}
//
//func TestShamirOpenBadIdentifier(t *testing.T) {
//	t.Parallel()
//
//	for _, curve := range supportedCurve {
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			scheme, err := shamir.NewScheme(2, 3, curve)
//			require.NoError(t, err)
//			require.NotNil(t, scheme)
//			shares := []*shamir.Share{
//				{
//					Id:    0,
//					Value: curve.ScalarField().New(3),
//				},
//				{
//					Id:    2,
//					Value: curve.ScalarField().New(3),
//				},
//			}
//			_, err = scheme.Open(shares...)
//			require.Error(t, err)
//			shares[0] = &shamir.Share{
//				Id:    4,
//				Value: curve.ScalarField().New(3),
//			}
//			_, err = scheme.Open(shares...)
//			require.Error(t, err)
//		})
//	}
//}
//
//func TestShamirOpenSingle(t *testing.T) {
//	t.Parallel()
//	prng := crand.Reader
//
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				scheme, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, scheme)
//
//				randomScalar, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				shares, err := scheme.Deal(randomScalar, prng)
//				require.NoError(t, err)
//				require.NotNil(t, shares)
//				secret, err := scheme.Open(slices.Collect(maps.Values(shares))...)
//				require.NoError(t, err)
//				require.True(t, secret.Equal(randomScalar))
//			})
//		}
//	}
//}
//
//func TestShamirOpenSingleInExp(t *testing.T) {
//	t.Parallel()
//	prng := crand.Reader
//
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				scheme, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, scheme)
//
//				randomScalar, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				randomPoint := curve.ScalarBaseMult(randomScalar)
//
//				shares, err := scheme.Deal(randomScalar, prng)
//				require.NoError(t, err)
//				require.NotNil(t, shares)
//				sharesInExp := maputils.MapValues(shares, func(_ types.SharingID, share *shamir.Share) *shamir.ShareInExp { return share.Exp() })
//
//				secretInExp, err := scheme.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
//				require.NoError(t, err)
//				require.True(t, secretInExp.Equal(randomPoint))
//			})
//		}
//	}
//}
//
//// Test ComputeL function to compute Lagrange coefficients.
//func TestShamirComputeL(t *testing.T) {
//	t.Parallel()
//	curve := edwards25519.NewCurve()
//	scheme, err := shamir.NewScheme(2, 2, curve)
//	require.NoError(t, err)
//	require.NotNil(t, scheme)
//	secret, err := curve.ScalarField().Hash([]byte("test"))
//	require.NoError(t, err)
//	shares, err := scheme.Deal(secret, crand.Reader)
//	require.NoError(t, err)
//	require.NotNil(t, shares)
//	var identities []types.SharingID
//	for _, xi := range shares {
//		identities = append(identities, xi.Id)
//	}
//	lCoeffs, err := scheme.LagrangeCoefficients(identities)
//	require.NoError(t, err)
//	require.NotNil(t, lCoeffs)
//	require.Len(t, lCoeffs, len(identities))
//
//	// Checking we can reconstruct the same secret using Lagrange coefficients.
//	result := curve.Scalar()
//	for _, r := range shares {
//		result = result.Add(r.Value.Mul(lCoeffs[r.Id]))
//	}
//	require.Equal(t, result.Bytes(), secret.Bytes())
//}
//
//func TestShamirAllCombinations(t *testing.T) {
//	t.Parallel()
//	prng := crand.Reader
//
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				scheme, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, scheme)
//
//				secret, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				shares, err := scheme.Deal(secret, prng)
//				require.NoError(t, err)
//				require.NotNil(t, shares)
//
//				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), as.th)
//				require.NoError(t, err)
//				for _, combination := range combinations {
//					reconstructed, err := scheme.Open(combination...)
//					require.NoError(t, err)
//					require.True(t, reconstructed.Equal(secret))
//				}
//			})
//		}
//	}
//}
//
//func TestAdditiveAllCombinations(t *testing.T) {
//	t.Parallel()
//	prng := crand.Reader
//
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				scheme, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, scheme)
//
//				secret, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				shares, err := scheme.Deal(secret, prng)
//				require.NoError(t, err)
//				require.NotNil(t, shares)
//
//				combinations, err := combinatorics.Combinations(slices.Collect(maps.Values(shares)), as.th)
//				require.NoError(t, err)
//
//				for _, combination := range combinations {
//					var ids []types.SharingID
//					for _, share := range combination {
//						ids = append(ids, share.Id)
//					}
//
//					s := curve.ScalarField().Zero()
//					for _, share := range combination {
//						sAdd, err := share.ToAdditive(ids)
//						require.NoError(t, err)
//						s = s.Add(sAdd)
//					}
//
//					require.True(t, secret.Equal(s))
//				}
//			})
//		}
//	}
//}
//
//func TestLinearAdd(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretB, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//
//				sharesB, err := dealer.Deal(secretB, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesB)
//
//				secret := secretA.Add(secretB)
//				shares := sharing.AddSharesMap(dealer, sharesA, sharesB)
//
//				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecret)
//				require.Zero(t, secret.Cmp(recomputedSecret))
//			})
//		}
//	}
//}
//
//func TestLinearAddValue(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretB, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//
//				secret := secretA.Add(secretB)
//				shares := sharing.AddSharesValueMap(dealer, sharesA, secretB)
//
//				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecret)
//				require.Zero(t, secret.Cmp(recomputedSecret))
//			})
//		}
//	}
//}
//
//func TestLinearSub(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretB, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//
//				sharesB, err := dealer.Deal(secretB, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesB)
//
//				secret := secretA.Sub(secretB)
//				shares := sharing.SubSharesMap(dealer, sharesA, sharesB)
//
//				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecret)
//				require.Zero(t, secret.Cmp(recomputedSecret))
//			})
//		}
//	}
//}
//
//func TestLinearSubValue(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretB, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//
//				secret := secretA.Sub(secretB)
//				shares := sharing.SubSharesValueMap(dealer, sharesA, secretB)
//
//				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecret)
//				require.Zero(t, secret.Cmp(recomputedSecret))
//			})
//		}
//	}
//}
//
//func TestLinearNeg(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//
//				secret := secretA.Neg()
//				shares := sharing.NegSharesMap(dealer, sharesA)
//
//				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecret)
//				require.Zero(t, secret.Cmp(recomputedSecret))
//			})
//		}
//	}
//}
//
//func TestLinearScalarMul(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				scalar, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//
//				secret := secretA.Mul(scalar)
//				shares := sharing.MulSharesMap(dealer, sharesA, scalar)
//
//				recomputedSecret, err := dealer.Open(slices.Collect(maps.Values(shares))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecret)
//				require.Zero(t, secret.Cmp(recomputedSecret))
//			})
//		}
//	}
//}
//
//func TestLinearAddInExp(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretAInExp := curve.ScalarBaseMult(secretA)
//				secretB, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretBInExp := curve.ScalarBaseMult(secretB)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *shamir.Share) *shamir.ShareInExp { return s.Exp() })
//
//				sharesB, err := dealer.Deal(secretB, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesB)
//				sharesBInExp := maputils.MapValues(sharesB, func(_ types.SharingID, s *shamir.Share) *shamir.ShareInExp { return s.Exp() })
//
//				secretInExp := secretAInExp.Add(secretBInExp)
//				sharesInExp := maputils.Join(sharesAInExp, sharesBInExp, func(_ types.SharingID, l, r *shamir.ShareInExp) *shamir.ShareInExp { return l.Add(r) })
//
//				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecretInExp)
//				require.True(t, secretInExp.Equal(recomputedSecretInExp))
//			})
//		}
//	}
//}
//
//func TestLinearAddValueInExp(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretAInExp := curve.ScalarBaseMult(secretA)
//
//				secretB, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretBInExp := curve.ScalarBaseMult(secretB)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *shamir.Share) *shamir.ShareInExp { return s.Exp() })
//
//				secretInExp := secretAInExp.Add(secretBInExp)
//				sharesInExp := maputils.MapValues(sharesAInExp, func(_ types.SharingID, s *shamir.ShareInExp) *shamir.ShareInExp { return s.AddValue(secretBInExp) })
//
//				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecretInExp)
//				require.True(t, secretInExp.Equal(recomputedSecretInExp))
//			})
//		}
//	}
//}
//
//func TestLinearSubInExp(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretAInExp := curve.ScalarBaseMult(secretA)
//				secretB, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretBInExp := curve.ScalarBaseMult(secretB)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *shamir.Share) *shamir.ShareInExp { return s.Exp() })
//
//				sharesB, err := dealer.Deal(secretB, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesB)
//				sharesBInExp := maputils.MapValues(sharesB, func(_ types.SharingID, s *shamir.Share) *shamir.ShareInExp { return s.Exp() })
//
//				secretInExp := secretAInExp.Sub(secretBInExp)
//				sharesInExp := maputils.Join(sharesAInExp, sharesBInExp, func(_ types.SharingID, l, r *shamir.ShareInExp) *shamir.ShareInExp { return l.Sub(r) })
//
//				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecretInExp)
//				require.True(t, secretInExp.Equal(recomputedSecretInExp))
//			})
//		}
//	}
//}
//
//func TestLinearSubValueInExp(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretAInExp := curve.ScalarBaseMult(secretA)
//
//				secretB, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//				secretBInExp := curve.ScalarBaseMult(secretB)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *shamir.Share) *shamir.ShareInExp { return s.Exp() })
//
//				secretInExp := secretAInExp.Sub(secretBInExp)
//				sharesInExp := maputils.MapValues(sharesAInExp, func(_ types.SharingID, s *shamir.ShareInExp) *shamir.ShareInExp { return s.SubValue(secretBInExp) })
//
//				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecretInExp)
//				require.True(t, secretInExp.Equal(recomputedSecretInExp))
//			})
//		}
//	}
//}
//
//func TestLinearNegInExp(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *shamir.Share) *shamir.ShareInExp { return s.Exp() })
//
//				secret := secretA.Neg()
//				secretInExp := curve.ScalarBaseMult(secret)
//				sharesInExp := maputils.MapValues(sharesAInExp, func(_ types.SharingID, s *shamir.ShareInExp) *shamir.ShareInExp { return s.Neg() })
//
//				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecretInExp)
//				require.True(t, secretInExp.Equal(recomputedSecretInExp))
//			})
//		}
//	}
//}
//
//func TestLinearScalarMulInExp(t *testing.T) {
//	t.Parallel()
//
//	prng := crand.Reader
//	for _, curve := range supportedCurve {
//		for _, as := range supportedAccessStructures {
//			t.Run(fmt.Sprintf("%s_(%d,%d)", curve.Name(), as.th, as.n), func(t *testing.T) {
//				t.Parallel()
//
//				dealer, err := shamir.NewScheme(as.th, as.n, curve)
//				require.NoError(t, err)
//				require.NotNil(t, dealer)
//
//				secretA, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				secretB, err := curve.ScalarField().Random(prng)
//				require.NoError(t, err)
//
//				sharesA, err := dealer.Deal(secretA, prng)
//				require.NoError(t, err)
//				require.NotNil(t, sharesA)
//				sharesAInExp := maputils.MapValues(sharesA, func(_ types.SharingID, s *shamir.Share) *shamir.ShareInExp { return s.Exp() })
//
//				secret := secretA.Mul(secretB)
//				secretInExp := curve.ScalarBaseMult(secret)
//				sharesInExp := maputils.MapValues(sharesAInExp, func(_ types.SharingID, s *shamir.ShareInExp) *shamir.ShareInExp { return s.ScalarMul(secretB) })
//
//				recomputedSecretInExp, err := dealer.OpenInExponent(slices.Collect(maps.Values(sharesInExp))...)
//				require.NoError(t, err)
//				require.NotNil(t, recomputedSecretInExp)
//				require.True(t, secretInExp.Equal(recomputedSecretInExp))
//			})
//		}
//	}
//}
//
//func TestMarshalJsonRoundTrip(t *testing.T) {
//	t.Parallel()
//
//	for _, curve := range supportedCurve {
//		t.Run(curve.Name(), func(t *testing.T) {
//			t.Parallel()
//
//			shares := []shamir.Share{
//				{Id: 0, Value: curve.ScalarField().New(300)},
//				{Id: 2, Value: curve.ScalarField().New(300000)},
//				{Id: 20, Value: curve.ScalarField().New(12812798)},
//				{Id: 31, Value: curve.ScalarField().New(17)},
//				{Id: 57, Value: curve.ScalarField().New(5066680)},
//				{Id: 128, Value: curve.ScalarField().New(3005)},
//				{Id: 19, Value: curve.ScalarField().New(317)},
//				{Id: 7, Value: curve.ScalarField().New(323)},
//				{Id: 222, Value: curve.ScalarField().New(1).Neg()},
//			}
//
//			for _, in := range shares {
//				input, err := json.Marshal(in)
//				require.NoError(t, err)
//				require.NotNil(t, input)
//
//				// Unmarshal and test
//				var out shamir.Share
//				out.Value = curve.ScalarField().Element()
//				err = json.Unmarshal(input, &out)
//				require.NoError(t, err)
//				require.Equal(t, in.Id, out.Id)
//				require.Equal(t, in.Value, out.Value)
//			}
//		})
//	}
//}
