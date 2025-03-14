package k256

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"github.com/cronokirby/saferith"

	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	saferithUtils "github.com/bronlabs/bron-crypto/pkg/base/utils/saferith"
)

var (
	oldK256Initonce sync.Once
	oldK256         Koblitz256
)

var _ elliptic.Curve = (*Koblitz256)(nil)

type Koblitz256 struct {
	*elliptic.CurveParams

	_ ds.Incomparable
}

func oldK256InitAll() {
	B := new(BaseFieldElement).SetNat(new(saferith.Nat).SetUint64(uint64(7)))
	curve := NewCurve()
	oldK256.CurveParams = new(elliptic.CurveParams)
	oldK256.P = curve.BaseField().Order().Big()
	oldK256.N = curve.SubGroupOrder().Big()
	oldK256.Gx = curve.Generator().AffineX().Nat().Big()
	oldK256.Gy = curve.Generator().AffineY().Nat().Big()
	oldK256.B = B.Nat().Big()
	oldK256.BitSize = k256Impl.FpBits
	oldK256.Name = Name
}

func NewElliptic() *Koblitz256 {
	oldK256Initonce.Do(oldK256InitAll)
	return &oldK256
}

func (curve *Koblitz256) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (*Koblitz256) IsOnCurve(x, y *big.Int) bool {
	c := NewCurve()
	x11 := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(x, k256BaseFieldModulus))
	y11 := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(y, k256BaseFieldModulus))
	_, err := c.NewPoint(x11, y11)
	return err == nil
}

func (*Koblitz256) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	c := NewCurve()
	x11 := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(x1, k256BaseFieldModulus))
	y11 := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(y1, k256BaseFieldModulus))
	p1, err := c.NewPoint(x11, y11)
	if err != nil {
		panic("set point")
	}
	x22 := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(x2, k256BaseFieldModulus))
	y22 := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(y2, k256BaseFieldModulus))
	p2, err := c.NewPoint(x22, y22)
	if err != nil {
		panic("set point")
	}
	p := p1.Add(p2)
	return p.AffineX().Nat().Big(), p.AffineY().Nat().Big()
}

func (*Koblitz256) Double(x1, y1 *big.Int) (x, y *big.Int) {
	c := NewCurve()
	x11 := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(x1, k256BaseFieldModulus))
	y11 := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(y1, k256BaseFieldModulus))
	p1, err := c.NewPoint(x11, y11)
	if err != nil {
		panic("set point")
	}
	result := p1.Double()
	return result.AffineX().Nat().Big(), result.AffineY().Nat().Big()
}

func (*Koblitz256) ScalarMult(Bx, By *big.Int, k []byte) (x, y *big.Int) {
	c := NewCurve()
	Bxx := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(Bx, k256BaseFieldModulus))
	Byy := NewBaseFieldElement(0).SetNat(saferithUtils.NatFromBigMod(By, k256BaseFieldModulus))
	p1, err := c.NewPoint(Bxx, Byy)
	if err != nil {
		panic(errs.WrapSerialisation(err, "set point"))
	}
	if len(k) > 32 {
		panic("invalid scalar length")
	}
	kk := c.Scalar().SetNat(saferithUtils.NatFromBigMod(new(big.Int).SetBytes(k), k256Order))
	result := p1.ScalarMul(kk)
	return result.AffineX().Nat().Big(), result.AffineY().Nat().Big()
}

func (*Koblitz256) ScalarBaseMult(k []byte) (x, y *big.Int) {
	if len(k) > 32 {
		panic("invalid scalar length")
	}
	c := NewCurve()
	kk := c.Scalar().SetNat(saferithUtils.NatFromBigMod(new(big.Int).SetBytes(k), k256Order))
	result := c.ScalarBaseMult(kk)
	return result.AffineX().Nat().Big(), result.AffineY().Nat().Big()
}
