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
	if err != nil {
		return nil, errs.NewFailed("cannot get curve order")
	}
	return ec.Params().N, nil
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
func Split(scalar curves.Scalar, prng io.Reader) (xPrime curves.Scalar, xBis curves.Scalar, i int, err error) {
	curve, err := curves.GetCurveByName(scalar.Point().CurveName())
	if err != nil {
		return nil, nil, 0, errs.WrapInvalidCurve(err, "invalid curve %s", scalar.Point().CurveName())
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
		xBis = scalar.Sub(xPrime).Sub(xPrime).Sub(xPrime)

		if IsInSecondThird(xPrime) && IsInSecondThird(xBis) {
			break
		}

		i++ // failsafe
		if i > 974 {
			// probability of this happening is (5/6)^(974) =~ (1/2)^(256)
			return nil, nil, 0, errs.NewFailed("cannot find x' and x''")
		}
	}

	return xPrime, xBis, i, nil
}

func IsInSecondThird(scalar curves.Scalar) bool {
	curve, err := curves.GetCurveByName(scalar.Point().CurveName())
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
