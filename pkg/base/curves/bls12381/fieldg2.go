package bls12381

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/base/curves"
	bimpl "github.com/copperexchange/knox-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/knox-primitives/pkg/base/errs"
	"github.com/copperexchange/knox-primitives/pkg/base/integration/helper_types"
)

var _ curves.FieldProfile = (*FieldProfileG2)(nil)

type FieldProfileG2 struct{}

func (*FieldProfileG2) Order() *saferith.Modulus {
	return saferith.ModulusFromNat(new(saferith.Nat).Mul(p.Nat(), p.Nat(), -1))
}

func (*FieldProfileG2) Characteristic() *saferith.Nat {
	return p.Nat()
}

func (*FieldProfileG2) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(2)
}

var _ curves.FieldElement = (*FieldElementG2)(nil)

type FieldElementG2 struct {
	v *bimpl.Fp2

	_ helper_types.Incomparable
}

func (*FieldElementG2) Value() curves.FieldValue {
	return nil
}

func (e *FieldElementG2) Modulus() *saferith.Modulus {
	return e.Profile().Order()
}

func (e *FieldElementG2) Clone() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).Set(e.v),
	}
}

func (*FieldElementG2) Cmp(rhs curves.FieldElement) int {
	panic("not implemented")
}

func (*FieldElementG2) Profile() curves.FieldProfile {
	return &FieldProfileG2{}
}

func (*FieldElementG2) Hash(x []byte) curves.FieldElement {
	return nil
}

func (*FieldElementG2) New(value uint64) curves.FieldElement {
	return nil
}

func (e *FieldElementG2) Random(prng io.Reader) curves.FieldElement {
	result, err := e.v.Random(prng)
	if err != nil {
		panic(err.Error())
	}
	return &FieldElementG2{v: result}
}

func (*FieldElementG2) Zero() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).SetZero(),
	}
}

func (*FieldElementG2) One() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).SetOne(),
	}
}

func (e *FieldElementG2) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e *FieldElementG2) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e *FieldElementG2) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *FieldElementG2) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *FieldElementG2) Square() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).Square(e.v),
	}
}

func (e *FieldElementG2) Double() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).Double(e.v),
	}
}

func (e *FieldElementG2) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := new(bimpl.Fp2).Sqrt(e.v)
	return &FieldElementG2{
		v: result,
	}, wasSquare == 1
}

func (e *FieldElementG2) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElementG2) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG2)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &FieldElementG2{
		v: new(bimpl.Fp2).Add(e.v, n.v),
	}
}

func (e *FieldElementG2) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG2)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &FieldElementG2{
		v: new(bimpl.Fp2).Sub(e.v, n.v),
	}
}

func (e *FieldElementG2) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG2)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &FieldElementG2{
		v: new(bimpl.Fp2).Mul(e.v, n.v),
	}
}

func (e *FieldElementG2) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElementG2) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElementG2)
	if ok {
		v, wasInverted := new(bimpl.Fp2).Invert(r.v)
		if wasInverted != 1 {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElementG2{v: v}
	} else {
		panic("rhs is not bls12381 G1 base field element")
	}
}

func (*FieldElementG2) Exp(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (e *FieldElementG2) Neg() curves.FieldElement {
	return &FieldElementG2{
		v: new(bimpl.Fp2).Neg(e.v),
	}
}

func (e *FieldElementG2) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	return e.SetBytes(value.Bytes())
}

func (*FieldElementG2) Nat() *saferith.Nat {
	return nil
}

func (*FieldElementG2) SetBytes(input []byte) (curves.FieldElement, error) {
	return nil, errs.NewFailed("not implemented")
}

func (*FieldElementG2) SetBytesWide(input []byte) (curves.FieldElement, error) {
	return nil, errs.NewFailed("not implemented")
}

func (*FieldElementG2) Bytes() []byte {
	return nil
}

func (*FieldElementG2) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	return nil, errs.NewFailed("not implemented")
}

func (*FieldElementG2) Scalar(curve curves.Curve) (curves.Scalar, error) {
	return nil, errs.NewFailed("not implemented")
}
