package lindell17

import (
	crand "crypto/rand"
	"io"
	"math/big"

	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/curveutils"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
)

// DecomposeInQThirds splits scalar x to x' and x” such that x = 3x' + x” and x', x” are in range [q/3, 2q/3).
func DecomposeInQThirds(scalar curves.Scalar, prng io.Reader) (xPrime, xDoublePrime curves.Scalar, i int, err error) {
	curve, err := scalar.Curve()
	if err != nil {
		return nil, nil, 0, errs.WrapInvalidCurve(err, "invalid curve %s", scalar.CurveName())
	}
	order := curve.Profile().SubGroupOrder()

	i = 0
	l := new(big.Int).Div(new(big.Int).Add(order, big.NewInt(2)), big.NewInt(3))
	h := new(big.Int).Div(new(big.Int).Add(new(big.Int).Mul(order, big.NewInt(2)), big.NewInt(2)), big.NewInt(3))
	for {
		r, err := crand.Int(prng, new(big.Int).Sub(h, l))
		if err != nil {
			return nil, nil, 0, errs.WrapFailed(err, "cannot generate random")
		}
		xPrimeInt := new(big.Int).Add(l, r)
		xPrime, err = curve.Scalar().SetBigInt(xPrimeInt)
		if err != nil {
			return nil, nil, 0, errs.WrapFailed(err, "cannot set scalar")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)

		if IsInSecondThird(xPrime) && IsInSecondThird(xDoublePrime) {
			break
		}

		i++ // failsafe
		if i > 974 {
			// probability of this happening is (5/6)^(974) =~ (1/2)^(256)
			// this is because doing this randomly you have 1/6 chance to get x' such that x'' will be in range
			// see SplitDeterministically function for details
			return nil, nil, 0, errs.NewFailed("cannot find x' and x''")
		}
	}

	// double check
	if xPrime.Add(xPrime).Add(xPrime).Add(xDoublePrime).Cmp(scalar) != 0 {
		return nil, nil, 0, errs.NewFailed("split failed")
	}
	return xPrime, xDoublePrime, i, nil
}

// DecomposeInQThirdsDeterministically splits scalar x deterministically to x' and x” such that x = 3x' + x” and x', x” are in range [q/3, 2q/3).
func DecomposeInQThirdsDeterministically(scalar curves.Scalar, prng io.Reader) (xPrime, xDoublePrime curves.Scalar, err error) {
	switch {
	case inEighteenth(0, 3, scalar):
		xPrime, err = randomInEighteenth(9, 10, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(3, 6, scalar):
		xPrime, err = randomInEighteenth(10, 11, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(6, 9, scalar):
		xPrime, err = randomInEighteenth(11, 12, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(9, 12, scalar):
		xPrime, err = randomInEighteenth(6, 7, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(12, 15, scalar):
		xPrime, err = randomInEighteenth(7, 8, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	case inEighteenth(15, 18, scalar):
		xPrime, err = randomInEighteenth(8, 9, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, errs.WrapFailed(err, "could not construct xPrime")
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	default:
		return nil, nil, errs.NewFailed("oops")
	}

	// double check
	if !IsInSecondThird(xPrime) || !IsInSecondThird(xDoublePrime) {
		return nil, nil, errs.NewFailed("split failed")
	}
	if xPrime.Add(xPrime).Add(xPrime).Add(xDoublePrime).Cmp(scalar) != 0 {
		return nil, nil, errs.NewFailed("split failed")
	}
	return xPrime, xDoublePrime, nil
}

// IsInSecondThird check if scalar s: q/3 <= s < 2q/3 (q being subgroup order).
func IsInSecondThird(scalar curves.Scalar) bool {
	curve, err := (scalar.Curve())
	if err != nil {
		return false
	}
	order := curve.Profile().SubGroupOrder()
	l := new(big.Int).Div(new(big.Int).Add(order, big.NewInt(2)), big.NewInt(3))
	twoL := new(big.Int).Div(new(big.Int).Add(new(big.Int).Mul(order, big.NewInt(2)), big.NewInt(2)), big.NewInt(3))
	return scalar.BigInt().Cmp(l) >= 0 && scalar.BigInt().Cmp(twoL) < 0
}

func inEighteenth(lowBoundInclusive, highBoundExclusive int64, x curves.Scalar) bool {
	curve, err := x.Curve()
	if err != nil {
		return false
	}
	order := curve.Profile().SubGroupOrder()

	l := new(big.Int).Div(new(big.Int).Add(new(big.Int).Mul(order, big.NewInt(lowBoundInclusive)), big.NewInt(17)), big.NewInt(18))
	h := new(big.Int).Div(new(big.Int).Add(new(big.Int).Mul(order, big.NewInt(highBoundExclusive)), big.NewInt(17)), big.NewInt(18))
	return x.BigInt().Cmp(l) >= 0 && x.BigInt().Cmp(h) < 0
}

func randomInEighteenth(lowBoundInclusive, highBoundExclusive int64, curveName string, prng io.Reader) (curves.Scalar, error) {
	curve, err := curveutils.GetCurveByName(curveName)
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not get curve")
	}
	order := curve.Profile().SubGroupOrder()

	l := new(big.Int).Div(new(big.Int).Add(new(big.Int).Mul(order, big.NewInt(lowBoundInclusive)), big.NewInt(17)), big.NewInt(18))
	h := new(big.Int).Div(new(big.Int).Add(new(big.Int).Mul(order, big.NewInt(highBoundExclusive)), big.NewInt(17)), big.NewInt(18))

	x, err := crand.Int(prng, new(big.Int).Sub(h, l))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get random number")
	}
	x = new(big.Int).Add(l, x)

	xScalar, err := curve.Scalar().SetBigInt(x)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set big int")
	}

	return xScalar, nil
}
