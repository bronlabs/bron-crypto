package k256

import (
	"crypto/elliptic"
	"math/big"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/base"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/impl"
	secp256k1 "github.com/copperexchange/knox-primitives/pkg/base/curves/k256/impl"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256/impl/fp"
	"github.com/copperexchange/knox-primitives/pkg/base/curves/k256/impl/fq"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
)

var (
	oldK256Initonce sync.Once
	oldK256         Koblitz256
)

var _ elliptic.Curve = (*Koblitz256)(nil)

type Koblitz256 struct {
	*elliptic.CurveParams

	_ helper_types.Incomparable
}

func oldK256InitAll() {
	B, _ := new(FieldElement).SetNat(new(saferith.Nat).SetUint64(uint64(7)))
	curve := New()
	oldK256.CurveParams = new(elliptic.CurveParams)
	oldK256.P = curve.Profile().Field().Order().Big()
	oldK256.N = curve.Profile().SubGroupOrder().Big()
	oldK256.Gx = curve.Generator().X().Nat().Big()
	oldK256.Gy = curve.Generator().Y().Nat().Big()
	oldK256.B = B.Nat().Big()
	oldK256.BitSize = impl.FieldBytes * 8
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
	_, err := secp256k1.PointNew().SetNat(
		base.NatFromBig(x, fp.New().Params.Modulus),
		base.NatFromBig(y, fp.New().Params.Modulus),
	)
	return err == nil
}

func (*Koblitz256) Add(x1, y1, x2, y2 *big.Int) (x *big.Int, y *big.Int) {
	c := New()
	x11 := base.NatFromBig(x1, fp.New().Params.Modulus)
	y11 := base.NatFromBig(y1, fp.New().Params.Modulus)
	p1, err := c.Point().Set(x11, y11)
	if err != nil {
		panic("set point")
	}
	x22 := base.NatFromBig(x2, fp.New().Params.Modulus)
	y22 := base.NatFromBig(y2, fp.New().Params.Modulus)
	p2, err := c.Point().Set(x22, y22)
	if err != nil {
		panic("set point")
	}
	p := p1.Add(p2)
	return p.X().Nat().Big(), p.Y().Nat().Big()
}

func (*Koblitz256) Double(x1, y1 *big.Int) (x *big.Int, y *big.Int) {
	c := New()
	x11 := base.NatFromBig(x1, fp.New().Params.Modulus)
	y11 := base.NatFromBig(y1, fp.New().Params.Modulus)
	p1, err := c.Point().Set(x11, y11)
	if err != nil {
		panic("set point")
	}
	result := p1.Double()
	return result.X().Nat().Big(), result.Y().Nat().Big()
}

func (*Koblitz256) ScalarMult(Bx, By *big.Int, k []byte) (x *big.Int, y *big.Int) {
	c := New()
	Bxx := base.NatFromBig(Bx, fp.New().Params.Modulus)
	Byy := base.NatFromBig(By, fp.New().Params.Modulus)
	p1, err := c.Point().Set(Bxx, Byy)
	if err != nil {
		panic(errs.WrapSerializationError(err, "set pointt"))
	}
	if len(k) > 32 {
		panic("invalid scalar length")
	}
	kk, err := c.Scalar().SetNat(base.NatFromBig(new(big.Int).SetBytes(k), fq.New().Params.Modulus))
	if err != nil {
		return nil, nil
	}
	result := p1.Mul(kk)
	return result.X().Nat().Big(), result.Y().Nat().Big()
}

func (*Koblitz256) ScalarBaseMult(k []byte) (x *big.Int, y *big.Int) {
	if len(k) > 32 {
		panic("invalid scalar length")
	}
	c := New()
	kk, err := c.Scalar().SetNat(base.NatFromBig(new(big.Int).SetBytes(k), fq.New().Params.Modulus))
	if err != nil {
		panic("set scalar")
	}
	result := c.ScalarBaseMult(kk)
	return result.X().Nat().Big(), result.Y().Nat().Big()
}
