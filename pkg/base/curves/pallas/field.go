package pallas

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/constants"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.FieldProfile = (*FieldProfile)(nil)

type FieldProfile struct{}

func (*FieldProfile) Curve() curves.Curve {
	return &pallasInstance
}

func (*FieldProfile) Order() *saferith.Modulus {
	return fp.Modulus
}

func (p *FieldProfile) Characteristic() *saferith.Nat {
	return p.Order().Nat()
}

func (*FieldProfile) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

func (*FieldProfile) FieldBytes() int {
	return constants.FieldBytes
}

func (*FieldProfile) WideFieldBytes() int {
	return constants.WideFieldBytes
}

var _ curves.FieldElement = (*FieldElement)(nil)

type FieldElement struct {
	v *fp.Fp

	_ types.Incomparable
}

func (e *FieldElement) Value() curves.FieldValue {
	v := e.v.ToRaw()
	return v[:]
}

func (*FieldElement) Modulus() *saferith.Modulus {
	return fp.Modulus
}

func (e *FieldElement) Clone() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).Set(e.v),
	}
}

func (e *FieldElement) Cmp(rhs curves.FieldElement) int {
	rhse, ok := rhs.(*FieldElement)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.v)
}

func (*FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

func (*FieldElement) Hash(x []byte) (curves.FieldElement, error) {
	els, err := New().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash to field element in pallas")
	}
	return els[0], nil
}

func (*FieldElement) New(value uint64) curves.FieldElement {
	t := new(fp.Fp)
	t.SetUint64(value)
	return &FieldElement{
		v: t,
	}
}

func (e *FieldElement) SubfieldElement(index uint64) curves.FieldElement {
	return e
}

func (e *FieldElement) Random(prng io.Reader) (curves.FieldElement, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [constants.WideFieldBytes]byte
	_, err := prng.Read(seed[:])
	if err != nil {
		return nil, errs.WrapRandomSampleFailed(err, "could not read from prng")
	}
	value, err := e.SetBytesWide(seed[:])
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not set bytes")
	}
	return value, nil
}

func (*FieldElement) Zero() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).SetZero(),
	}
}

func (*FieldElement) One() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).SetOne(),
	}
}

func (e *FieldElement) IsZero() bool {
	return e.v.IsZero()
}

func (e *FieldElement) IsOne() bool {
	return e.v.IsOne()
}

func (e *FieldElement) IsOdd() bool {
	return e.v.IsOdd()
}

func (e *FieldElement) IsEven() bool {
	return !e.v.IsOdd()
}

func (e *FieldElement) Square() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).Square(e.v),
	}
}

func (e *FieldElement) Double() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).Double(e.v),
	}
}

func (e *FieldElement) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := new(fp.Fp).Sqrt(e.v)
	return &FieldElement{
		v: result,
	}, wasSquare
}

func (e *FieldElement) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElement) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &FieldElement{
		v: new(fp.Fp).Add(e.v, n.v),
	}
}

func (e *FieldElement) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &FieldElement{
		v: new(fp.Fp).Sub(e.v, n.v),
	}
}

func (e *FieldElement) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &FieldElement{
		v: new(fp.Fp).Mul(e.v, n.v),
	}
}

func (e *FieldElement) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElement) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElement)
	if ok {
		v, wasInverted := new(fp.Fp).Invert(r.v)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElement{v: v}
	} else {
		panic("rhs is not pallas base field element")
	}
}

func (e *FieldElement) Exp(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a pallas base field element")
	}
	return &FieldElement{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e *FieldElement) Neg() curves.FieldElement {
	return &FieldElement{
		v: new(fp.Fp).Neg(e.v),
	}
}

func (e *FieldElement) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	e.v = new(fp.Fp).SetNat(value)
	return e, nil
}

func (e *FieldElement) Nat() *saferith.Nat {
	return e.v.Nat()
}

func (e *FieldElement) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != constants.FieldBytes {
		return nil, errs.NewInvalidLength("input length %d > %d bytes", len(input), constants.FieldBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result, err := e.v.SetBytes((*[constants.FieldBytes]byte)(buffer))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &FieldElement{
		v: result,
	}, nil
}

func (e *FieldElement) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) > constants.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length > %d bytes", constants.WideFieldBytes)
	}
	buffer := bitstring.ReverseAndPadBytes(input, constants.WideFieldBytes-len(input))
	result := e.v.SetBytesWide((*[constants.WideFieldBytes]byte)(buffer))
	return &FieldElement{
		v: result,
	}, nil
}

func (e *FieldElement) Bytes() []byte {
	v := e.v.Bytes()
	return v[:]
}

func (e *FieldElement) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a pallas scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElement) Scalar(curve curves.Curve) (curves.Scalar, error) {
	results, err := curve.Scalar().SetBytes(e.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert field element to scalar")
	}
	return results, nil
}
