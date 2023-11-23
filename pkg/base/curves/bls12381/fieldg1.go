package bls12381

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bimpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
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

func (*FieldProfileG1) FieldBytes() int {
	return bimpl.FieldBytes
}

func (*FieldProfileG1) WideFieldBytes() int {
	return bimpl.WideFieldBytes
}

var _ curves.FieldElement = (*FieldElementG1)(nil)

type FieldElementG1 struct {
	v *bimpl.Fp

	_ types.Incomparable
}

func NewFieldElementG1() *FieldElementG1 {
	emptyElement := &FieldElementG1{}
	result, _ := emptyElement.One().(*FieldElementG1)
	return result
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

func (*FieldElementG1) Hash(x []byte) (curves.FieldElement, error) {
	els, err := NewG1().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "could not hash to field element in bls12381 G1")
	}
	return els[0], nil
}

func (e *FieldElementG1) New(value uint64) curves.FieldElement {
	return &FieldElementG1{
		v: e.v.SetUint64(value),
	}
}

func (e *FieldElementG1) SubfieldElement(index uint64) curves.FieldElement {
	return e
}

func (e *FieldElementG1) Random(prng io.Reader) (curves.FieldElement, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	result, err := e.v.Random(prng)
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not generate random field element")
	}
	return &FieldElementG1{v: result}, nil
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

func (*FieldElementG1) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != bimpl.FieldBytes {
		return nil, errs.NewInvalidLength("input length (%d != %d bytes)", len(input), bimpl.FieldBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result, ok := new(bimpl.Fp).SetBytes((*[bimpl.FieldBytes]byte)(buffer))
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	return &FieldElementG1{
		v: result,
	}, nil
}

func (*FieldElementG1) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) > bimpl.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length > %d bytes", bimpl.WideFieldBytes)
	}
	buffer := bitstring.ReverseAndPadBytes(input, bimpl.WideFieldBytes-len(input))
	result := new(bimpl.Fp).SetBytesWide((*[bimpl.WideFieldBytes]byte)(buffer))
	return &FieldElementG1{
		v: result,
	}, nil
}

func (e *FieldElementG1) Bytes() []byte {
	v := e.v.Bytes()
	return v[:]
}

func (e *FieldElementG1) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != NamePairing {
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
