package lindell17

import (
	"github.com/copperexchange/crypto-primitives-go/pkg/core/curves"
	"github.com/copperexchange/crypto-primitives-go/pkg/core/errs"
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
