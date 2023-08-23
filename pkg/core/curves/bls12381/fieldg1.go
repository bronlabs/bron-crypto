package bls12381

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	bimpl "github.com/copperexchange/knox-primitives/pkg/core/curves/bls12381/impl"
	"github.com/copperexchange/knox-primitives/pkg/core/errs"
	"github.com/copperexchange/knox-primitives/pkg/core/integration/helper_types"
)

var _ curves.FieldProfile = (*FieldProfileG1)(nil)

type FieldProfileG1 struct{}

func (*FieldProfileG1) Order() *saferith.Modulus {
	return p
}

func (*FieldProfileG1) Characteristic() *saferith.Nat {
	return p.Nat()
}

func (*FieldProfileG1) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

var _ curves.FieldElement = (*FieldElementG1)(nil)

type FieldElementG1 struct {
	v *bimpl.Fp

	_ helper_types.Incomparable
}

func (e *FieldElementG1) Value() curves.FieldValue {
	return e.v[:]
}

func (*FieldElementG1) Modulus() *saferith.Modulus {
	return p
}

func (e *FieldElementG1) Clone() curves.FieldElement {
	return &FieldElementG1{
		v: new(bimpl.Fp).Set(e.v),
	}
}

func (e *FieldElementG1) Cmp(rhs curves.FieldElement) int {
	rhse, ok := rhs.(*FieldElementG1)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.v)
}

func (*FieldElementG1) Profile() curves.FieldProfile {
	return &FieldProfileG1{}
}

// IMPLEMENT
func (e *FieldElementG1) Hash(x []byte) curves.FieldElement {
	return &FieldElementG1{
		v: e.v.Hash(x),
	}
}

func (e *FieldElementG1) New(value uint64) curves.FieldElement {
	return &FieldElementG1{
		v: e.v.SetUint64(value),
	}
}

func (e *FieldElementG1) Random(prng io.Reader) curves.FieldElement {
	result, err := e.v.Random(prng)
	if err != nil {
		panic(err.Error())
	}
	return &FieldElementG1{v: result}
}

func (*FieldElementG1) Zero() curves.FieldElement {
	return &FieldElementG1{
		v: new(bimpl.Fp).SetZero(),
	}
}

func (*FieldElementG1) One() curves.FieldElement {
	return &FieldElementG1{
		v: new(bimpl.Fp).SetOne(),
	}
}

func (e *FieldElementG1) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e *FieldElementG1) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e *FieldElementG1) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *FieldElementG1) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *FieldElementG1) Square() curves.FieldElement {
	return &FieldElementG1{
		v: new(bimpl.Fp).Square(e.v),
	}
}

func (e *FieldElementG1) Double() curves.FieldElement {
	return &FieldElementG1{
		v: new(bimpl.Fp).Double(e.v),
	}
}

func (e *FieldElementG1) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := new(bimpl.Fp).Sqrt(e.v)
	return &FieldElementG1{
		v: result,
	}, wasSquare == 1
}

func (e *FieldElementG1) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElementG1) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG1)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &FieldElementG1{
		v: new(bimpl.Fp).Add(e.v, n.v),
	}
}

func (e *FieldElementG1) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG1)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &FieldElementG1{
		v: new(bimpl.Fp).Sub(e.v, n.v),
	}
}

func (e *FieldElementG1) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG1)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &FieldElementG1{
		v: new(bimpl.Fp).Mul(e.v, n.v),
	}
}

func (e *FieldElementG1) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElementG1) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElementG1)
	if ok {
		v, wasInverted := new(bimpl.Fp).Invert(r.v)
		if wasInverted != 1 {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElementG1{v: v}
	} else {
		panic("rhs is not bls12381 G1 base field element")
	}
}

func (e *FieldElementG1) Exp(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElementG1)
	if !ok {
		panic("not a bls12381 G1 base field element")
	}
	return &FieldElementG1{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e *FieldElementG1) Neg() curves.FieldElement {
	return &FieldElementG1{
		v: new(bimpl.Fp).Neg(e.v),
	}
}

func (e *FieldElementG1) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	return e.SetBytes(value.Bytes())
}

func (e *FieldElementG1) Nat() *saferith.Nat {
	return e.v.Nat()
}

func (e *FieldElementG1) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != bimpl.FieldBytes {
		return nil, errs.NewInvalidLength("input length is not 48 bytes")
	}
	var out [48]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result, ok := e.v.SetBytes(&out)
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	return &FieldElementG1{
		v: result,
	}, nil
}

func (e *FieldElementG1) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) != bimpl.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length is not 96 bytes")
	}
	var out [96]byte
	copy(out[:], bitstring.ReverseBytes(input))
	result := e.v.SetBytesWide(&out)
	return &FieldElementG1{
		v: result,
	}, nil
}

func (e *FieldElementG1) Bytes() []byte {
	v := e.v.Bytes()
	return v[:]
}

func (e *FieldElementG1) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a bls12381 G1 scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElementG1) Scalar(curve curves.Curve) (curves.Scalar, error) {
	results, err := curve.Scalar().SetBytes(e.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert field element to scalar")
	}
	return results, nil
}
