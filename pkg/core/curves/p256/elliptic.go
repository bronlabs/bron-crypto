package p256

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	p256n "github.com/copperexchange/knox-primitives/pkg/core/curves/p256/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var (
	oldP256InitOnce sync.Once
	oldP256         NistP256
)

type NistP256 struct {
	*elliptic.CurveParams

	_ helper_types.Incomparable
}

func oldP256InitAll() {
	curve := elliptic.P256()
	oldP256.CurveParams = curve.Params()
	oldP256.P = curve.Params().P
	oldP256.N = curve.Params().N
	oldP256.Gx = curve.Params().Gx
	oldP256.Gy = curve.Params().Gy
	oldP256.B = curve.Params().B
	oldP256.BitSize = curve.Params().BitSize
	oldP256.Name = curve.Params().Name
}

func NewElliptic() *NistP256 {
	oldP256InitOnce.Do(oldP256InitAll)
	return &oldP256
}

func (curve *NistP256) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (*NistP256) IsOnCurve(x, y *big.Int) bool {
	_, err := p256n.PointNew().SetBigInt(x, y)
	return err == nil
}

func (*NistP256) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p1, err := p256n.PointNew().SetBigInt(x1, y1)
	if err != nil {
		return nil, nil
	}
	p2, err := p256n.PointNew().SetBigInt(x2, y2)
	if err != nil {
		return nil, nil
	}
	return p1.Add(p1, p2).BigInt()
}

func (*NistP256) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p1, err := p256n.PointNew().SetBigInt(x1, y1)
	if err != nil {
		return nil, nil
	}
	return p1.Double(p1).BigInt()
}

func (*NistP256) ScalarMul(Bx, By *big.Int, k []byte) (*big.Int, *big.Int) {
	p1, err := p256n.PointNew().SetBigInt(Bx, By)
	if err != nil {
		return nil, nil
	}
	if len(k) > 32 {
		panic("invalid scalar length")
	}
	var bytes_ [32]byte
	copy(bytes_[:], bitstring.ReverseBytes(k))
	s, err := fq.New().SetBytes(&bytes_)
	if err != nil {
		return nil, nil
	}
	return p1.Mul(p1, s).BigInt()
}

func (*NistP256) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	if len(k) > 32 {
		panic("invalid scalar length")
	}
	var bytes_ [32]byte
	copy(bytes_[:], bitstring.ReverseBytes(k))
	s, err := fq.New().SetBytes(&bytes_)
	if err != nil {
		return nil, nil
	}
	p1 := p256n.PointNew().Generator()
	return p1.Mul(p1, s).BigInt()
}
