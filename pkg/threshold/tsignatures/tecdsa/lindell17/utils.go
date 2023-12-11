package lindell17

import (
	"crypto/subtle"
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

// DecomposeInQThirdsBis splits scalar x deterministically to x' and x” such that x = 3x' + x” and x', x” are in range [q/3, 2q/3).
func DecomposeInQThirdsBis(scalar curves.Scalar, prng io.Reader) (xPrime, xPrimePrime curves.Scalar, err error) {
	xNat := scalar.Nat()
	qNat := scalar.Curve().Profile().SubGroupOrder().Nat()
	// Sample x” from [q/3, 2q/3)
	qThirds := qNat.Div(qNat, saferith.ModulusFromUint64(3), qNat.AnnouncedLen())
	twoqThirds := qNat.Mul(qThirds, new(saferith.Nat).SetUint64(2), qNat.AnnouncedLen())
	twoqThirdsMinus2 := qNat.Sub(twoqThirds, new(saferith.Nat).SetUint64(2), qNat.AnnouncedLen())
	xPrimePrimeNat, err := utils.RandomNat(prng, qThirds, twoqThirdsMinus2)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not get random number")
	}
	// Set x' so that x = 3x' + x” and x” be in range [q/3, 2q/3)
	xPrimeBytes := make([]byte, utils.CeilDiv(qNat.AnnouncedLen(), 8))
	jSelected := 0
	for j := 0; j <= 2; j++ {
		// x” = (x - x' + j) / 3 + q/3
		xPrimeJ := xNat.Sub(xNat, xPrimePrimeNat, qNat.AnnouncedLen())
		xPrimeJ = xPrimeJ.Add(xPrimeJ, new(saferith.Nat).SetUint64(uint64(j)), qNat.AnnouncedLen())
		xPrimeJ = xPrimeJ.Div(xPrimeJ, saferith.ModulusFromUint64(3), qNat.AnnouncedLen())
		xPrimeJ = xPrimeJ.Add(xPrimeJ, qThirds, qNat.AnnouncedLen())
		// b = (x == 3x' + x”)
		xPrimeNatTriple := qNat.Mul(xPrimeJ, new(saferith.Nat).SetUint64(3), qNat.AnnouncedLen())
		xExpected := qNat.Add(xPrimeNatTriple, xPrimePrimeNat, qNat.AnnouncedLen())
		b := int(xNat.Eq(xExpected))
		// xPrimeNat = b * xPrimeNat + (1 - b) * xPrimeNat
		subtle.ConstantTimeCopy(b, xPrimeJ.Bytes(), xPrimeBytes)
		jSelected = subtle.ConstantTimeSelect(b, j, jSelected)
	}
	// x' = x' + jSelected
	xPrimeNat := xNat.Add(new(saferith.Nat).SetBytes(xPrimeBytes), new(saferith.Nat).SetUint64(uint64(jSelected)), qNat.AnnouncedLen())
	// Cast to scalar
	xPrime, err = scalar.Curve().Scalar().SetNat(xPrimeNat)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not set xPrime with nat")
	}
	xPrimePrime, err = scalar.Curve().Scalar().SetNat(xPrimePrimeNat)
	if err != nil {
		return nil, nil, errs.WrapFailed(err, "could not set xPrimePrime with nat")
	}
	return xPrime, xPrimePrime, nil
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
