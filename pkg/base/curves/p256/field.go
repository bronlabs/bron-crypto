package p256

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.FieldProfile = (*FieldProfile)(nil)

type FieldProfile struct{}

func (*FieldProfile) Curve() curves.Curve {
	return &p256Instance
}

func (*FieldProfile) Order() *saferith.Modulus {
	return fp.New().Params.Modulus
}

func (p *FieldProfile) Characteristic() *saferith.Nat {
	return p.Order().Nat()
}

func (*FieldProfile) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

func (*FieldProfile) FieldBytes() int {
	return base.FieldBytes
}

func (*FieldProfile) WideFieldBytes() int {
	return base.WideFieldBytes
}

var _ curves.FieldElement = (*FieldElement)(nil)

type FieldElement struct {
	v *impl.FieldValue

	_ types.Incomparable
}

func (e *FieldElement) FieldValue() *impl.FieldValue {
	return e.v
}

func (e *FieldElement) Value() curves.FieldValue {
	return e.v.Value[:]
}

func (e *FieldElement) Modulus() *saferith.Modulus {
	return e.v.Params.Modulus
}

func (e *FieldElement) Clone() curves.FieldElement {
	return &FieldElement{
		v: fp.New().Set(e.v),
	}
}

func (*FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

func (*FieldElement) New(value uint64) curves.FieldElement {
	t := fp.New()
	t.SetUint64(value)
	return &FieldElement{
		v: t,
	}
}

func (*FieldElement) Hash(x []byte) (curves.FieldElement, error) {
	els, err := New().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash to field element in p256")
	}
	return els[0], nil
}

func (e *FieldElement) Cmp(rhs curves.FieldElement) int {
	rhse, ok := rhs.(*FieldElement)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.FieldValue())
}

func (e *FieldElement) SubfieldElement(index uint64) curves.FieldElement {
	return e
}

func (e *FieldElement) Random(prng io.Reader) (curves.FieldElement, error) {
	if prng == nil {
		return nil, errs.NewIsNil("prng is nil")
	}
	var seed [base.WideFieldBytes]byte
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
		v: fp.New().SetZero(),
	}
}

func (*FieldElement) One() curves.FieldElement {
	return &FieldElement{
		v: fp.New().SetOne(),
	}
}

func (e *FieldElement) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e *FieldElement) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e *FieldElement) IsOdd() bool {
	return e.v.Bytes()[0]&1 == 1
}

func (e *FieldElement) IsEven() bool {
	return e.v.Bytes()[0]&1 == 0
}

func (e *FieldElement) Square() curves.FieldElement {
	return &FieldElement{
		v: e.v.Square(e.v),
	}
}

func (e *FieldElement) Double() curves.FieldElement {
	return &FieldElement{
		v: e.v.Double(e.v),
	}
}

func (e *FieldElement) Sqrt() (curves.FieldElement, bool) {
	result, wasSquare := fp.New().Sqrt(e.v)
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
		panic("not a p256 Fp element")
	}
	return &FieldElement{
		v: fp.New().Add(e.v, n.FieldValue()),
	}
}

func (e *FieldElement) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElement{
		v: fp.New().Sub(e.v, n.FieldValue()),
	}
}

func (e *FieldElement) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElement{
		v: fp.New().Mul(e.v, n.FieldValue()),
	}
}

func (e *FieldElement) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElement) Div(rhs curves.FieldElement) curves.FieldElement {
	r, ok := rhs.(*FieldElement)
	if ok {
		v, wasInverted := fp.New().Invert(r.v)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElement{v: v}
	} else {
		panic("rhs is not ElementP256")
	}
}

func (e *FieldElement) Exp(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElement{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e *FieldElement) Neg() curves.FieldElement {
	var out [impl.FieldLimbs]uint64
	e.v.Arithmetic.Neg(&out, &e.v.Value)
	return &FieldElement{
		v: e.v.Neg(e.v),
	}
}

func (e *FieldElement) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	e.v = fp.New().SetNat(value)
	return e, nil
}

func (e *FieldElement) Nat() *saferith.Nat {
	return e.v.Nat()
}

func (e *FieldElement) SetBytes(input []byte) (curves.FieldElement, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("input length %d != %d bytes", len(input), base.FieldBytes)
	}
	input = bitstring.ReverseBytes(input)
	result, err := e.v.SetBytes((*[base.FieldBytes]byte)(input))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &FieldElement{
		v: result,
	}, nil
}

func (e *FieldElement) SetBytesWide(input []byte) (curves.FieldElement, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length > %d bytes", base.WideFieldBytes)
	}
	buffer := bitstring.ReverseAndPadBytes(input, base.WideFieldBytes-len(input))
	result := e.v.SetBytesWide((*[base.WideFieldBytes]byte)(buffer))
	return &FieldElement{
		v: result,
	}, nil
}

// Bytes returns a BigEndian representation of the field element.
func (e *FieldElement) Bytes() []byte {
	result := e.v.Bytes() // FieldValue.Bytes() is LittleEndian. Reverse it.
	return bitstring.ReverseBytes(result[:])
}

func (e *FieldElement) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a P256 scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElement) Scalar(curve curves.Curve) (curves.Scalar, error) {
	s, err := curve.Scalar().SetNat(e.Nat())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert to scalar")
	}
	return s, nil
}
