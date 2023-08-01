package lindell17

import (
	crand "crypto/rand"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
	"io"
	"math/big"
)

func GetPointCoordinates(point curves.Point) (x *big.Int, y *big.Int) {
	affine := point.ToAffineUncompressed()
	return new(big.Int).SetBytes(affine[1:33]), new(big.Int).SetBytes(affine[33:65])
}

func GetCurveOrder(curve *curves.Curve) (*big.Int, error) {
	ec, err := curve.ToEllipticCurve()
	if err == nil {
		return ec.Params().N, nil
	}

	// fallback
	minusOne, err := curve.NewScalar().SetBigInt(big.NewInt(-1))
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot set scalar")
	}

	return new(big.Int).Add(minusOne.BigInt(), big.NewInt(1)), nil
}

func HashToInt(hash []byte, curve *curves.Curve) (*big.Int, error) {
	order, err := GetCurveOrder(curve)
	if err != nil {
		return nil, errs.WrapFailed(err, "cannot get curve order")
	}
	orderBits := order.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret, nil
}

// Split splits scalar x to x' and x” such that x = 3x' + x” and x', x” are in range [q/3, 2q/3)
func Split(scalar curves.Scalar, prng io.Reader) (xPrime curves.Scalar, xDoublePrime curves.Scalar, i int, err error) {
	curve, err := curves.GetCurveByName(scalar.CurveName())
	if err != nil {
		return nil, nil, 0, errs.WrapInvalidCurve(err, "invalid curve %s", scalar.CurveName())
	}
	order, err := GetCurveOrder(curve)
	if err != nil {
		return nil, nil, 0, errs.WrapFailed(err, "cannot get curve order")
	}

	i = 0
	l := new(big.Int).Div(order, big.NewInt(3))
	for {
		r, err := crand.Int(prng, l)
		if err != nil {
			return nil, nil, 0, errs.WrapFailed(err, "cannot generate random")
		}
		xPrimeInt := new(big.Int).Add(l, r)
		xPrime, err = curve.NewScalar().SetBigInt(xPrimeInt)
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
			return nil, nil, 0, errs.NewFailed("cannot find x' and x''")
		}
	}

	// double check
	if xPrime.Add(xPrime).Add(xPrime).Add(xDoublePrime).Cmp(scalar) != 0 {
		return nil, nil, 0, errs.NewFailed("split failed")
	}
	return xPrime, xDoublePrime, i, nil
}

// SplitDeterministically splits scalar x deterministically to x' and x” such that x = 3x' + x” and x', x” are in range [q/3, 2q/3)
func SplitDeterministically(scalar curves.Scalar, prng io.Reader) (xPrime curves.Scalar, xDoublePrime curves.Scalar, err error) {
	if inEighteenth(0, 3, scalar) {
		xPrime, err = randomInEighteenth(9, 10, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, err
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	} else if inEighteenth(3, 6, scalar) {
		xPrime, err = randomInEighteenth(10, 11, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, err
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	} else if inEighteenth(6, 9, scalar) {
		xPrime, err = randomInEighteenth(11, 12, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, err
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	} else if inEighteenth(9, 12, scalar) {
		xPrime, err = randomInEighteenth(6, 7, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, err
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	} else if inEighteenth(12, 15, scalar) {
		xPrime, err = randomInEighteenth(7, 8, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, err
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	} else if inEighteenth(15, 18, scalar) {
		xPrime, err = randomInEighteenth(8, 9, scalar.CurveName(), prng)
		if err != nil {
			return nil, nil, err
		}
		xDoublePrime = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)
	} else {
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

func IsInSecondThird(scalar curves.Scalar) bool {
	curve, err := curves.GetCurveByName(scalar.CurveName())
	if err != nil {
		return false
	}
	order, err := GetCurveOrder(curve)
	if err != nil {
		return false
	}
	l := new(big.Int).Div(order, big.NewInt(3))
	return scalar.BigInt().Cmp(l) >= 0 && scalar.BigInt().Cmp(new(big.Int).Add(l, l)) < 0
}

func inEighteenth(lowBoundInclusive int64, highBoundExclusive int64, x curves.Scalar) bool {
	curve, err := curves.GetCurveByName(x.CurveName())
	if err != nil {
		return false
	}
	order, err := GetCurveOrder(curve)
	if err != nil {
		return false
	}

	l := new(big.Int).Div(new(big.Int).Add(new(big.Int).Mul(order, big.NewInt(lowBoundInclusive)), big.NewInt(17)), big.NewInt(18))
	h := new(big.Int).Div(new(big.Int).Mul(order, big.NewInt(highBoundExclusive)), big.NewInt(18))
	return x.BigInt().Cmp(l) >= 0 && x.BigInt().Cmp(h) < 0
}

func randomInEighteenth(lowBoundInclusive int64, highBoundExclusive int64, curveName string, prng io.Reader) (curves.Scalar, error) {
	curve, err := curves.GetCurveByName(curveName)
	if err != nil {
		return nil, err
	}
	order, err := GetCurveOrder(curve)
	if err != nil {
		return nil, err
	}

	l := new(big.Int).Div(new(big.Int).Add(new(big.Int).Mul(order, big.NewInt(lowBoundInclusive)), big.NewInt(17)), big.NewInt(18))
	h := new(big.Int).Div(new(big.Int).Mul(order, big.NewInt(highBoundExclusive)), big.NewInt(18))

	x, err := crand.Int(prng, new(big.Int).Sub(h, l))
	if err != nil {
		return nil, err
	}
	x = new(big.Int).Add(l, x)

	xScalar, err := curve.NewScalar().SetBigInt(x)
	if err != nil {
		return nil, err
	}

	return xScalar, nil
}
