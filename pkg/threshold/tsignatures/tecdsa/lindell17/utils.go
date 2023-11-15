package lindell17

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

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
	curve := scalar.Curve()
	order := curve.Profile().SubGroupOrder().Nat()
	orderPlusTwo := new(saferith.Nat).Add(order, new(saferith.Nat).SetUint64(2), -1)
	l := new(saferith.Nat).Div(orderPlusTwo, saferith.ModulusFromUint64(3), order.AnnouncedLen())
	orderTimesTwo := new(saferith.Nat).Add(order, order, -1)
	orderTimesTwoPlusTwo := new(saferith.Nat).Add(orderTimesTwo, new(saferith.Nat).SetUint64(2), -1)
	twoL := new(saferith.Nat).Div(orderTimesTwoPlusTwo, saferith.ModulusFromUint64(3), order.AnnouncedLen())
	ok1, ok2, _ := scalar.Nat().Cmp(l)
	_, _, ok3 := scalar.Nat().Cmp(twoL)
	return ((ok1 | ok2) & ok3) != 0
}

func inEighteenth(lowBoundInclusive, highBoundExclusive uint64, x curves.Scalar) bool {
	curve := x.Curve()
	order := curve.Profile().SubGroupOrder()

	orderTimesLow := new(saferith.Nat).Mul(order.Nat(), new(saferith.Nat).SetUint64(lowBoundInclusive), -1)
	orderTimesLowPlusSeventeen := new(saferith.Nat).Add(orderTimesLow, new(saferith.Nat).SetUint64(17), -1)
	l := new(saferith.Nat).Div(orderTimesLowPlusSeventeen, saferith.ModulusFromUint64(18), -1)

	orderTimesHigh := new(saferith.Nat).Mul(order.Nat(), new(saferith.Nat).SetUint64(highBoundExclusive), -1)
	orderTimesHighPlusSeventeen := new(saferith.Nat).Add(orderTimesHigh, new(saferith.Nat).SetUint64(17), -1)
	h := new(saferith.Nat).Div(orderTimesHighPlusSeventeen, saferith.ModulusFromUint64(18), -1)

	ok1, ok2, _ := x.Nat().Cmp(l)
	_, _, ok3 := x.Nat().Cmp(h)
	return ((ok1 | ok2) & ok3) != 0
}

func randomInEighteenth(lowBoundInclusive, highBoundExclusive uint64, curveName string, prng io.Reader) (curves.Scalar, error) {
	curve, err := curveutils.GetCurveByName(curveName)
	if err != nil {
		return nil, errs.WrapInvalidCurve(err, "could not get curve")
	}
	order := curve.Profile().SubGroupOrder().Nat()

	orderTimesLow := new(saferith.Nat).Mul(order, new(saferith.Nat).SetUint64(lowBoundInclusive), -1)
	orderTimesLowPlusSeventeen := new(saferith.Nat).Add(orderTimesLow, new(saferith.Nat).SetUint64(17), -1)
	l := new(saferith.Nat).Div(orderTimesLowPlusSeventeen, saferith.ModulusFromUint64(18), order.AnnouncedLen())

	orderTimesHigh := new(saferith.Nat).Mul(order, new(saferith.Nat).SetUint64(highBoundExclusive), -1)
	orderTimesHighPlusSeventeen := new(saferith.Nat).Add(orderTimesHigh, new(saferith.Nat).SetUint64(17), -1)
	h := new(saferith.Nat).Div(orderTimesHighPlusSeventeen, saferith.ModulusFromUint64(18), order.AnnouncedLen())

	x, err := utils.RandomNat(prng, l, h)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not get random number")
	}

	xScalar, err := curve.Scalar().SetNat(x)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set big int")
	}

	return xScalar, nil
}
