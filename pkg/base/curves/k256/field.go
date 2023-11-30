package k256

import (
	"io"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.FieldProfile = (*FieldProfileK256)(nil)

type FieldProfileK256 struct{}

func (*FieldProfileK256) Curve() curves.Curve[CurveIdentifierK256] {
	return New()
}

func (*FieldProfileK256) Order() *saferith.Modulus {
	return fp.New().Params.Modulus
}

func (p *FieldProfileK256) Characteristic() *saferith.Nat {
	return p.Order().Nat()
}

func (*FieldProfileK256) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

func (*FieldProfileK256) FieldBytes() int {
	return base.FieldBytes
}

func (*FieldProfileK256) WideFieldBytes() int {
	return base.WideFieldBytes
}

var _ curves.FieldElement[CurveIdentifierK256] = (*FieldElementK256)(nil)

type FieldElementK256 struct {
	v *impl.FieldValue

	_ types.Incomparable
}

func NewFieldElement() curves.FieldElement[CurveIdentifierK256] {
	emptyElement := &FieldElementK256{}
	result, _ := emptyElement.One().(*FieldElementK256)
	return result
}

func (e *FieldElementK256) FieldValue() *impl.FieldValue {
	return e.v
}

func (e *FieldElementK256) Value() curves.FieldValue {
	return e.v.Value[:]
}

func (e *FieldElementK256) Modulus() *saferith.Modulus {
	return e.v.Params.Modulus
}

func (e *FieldElementK256) Clone() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: fp.New().Set(e.v),
	}
}

func (*FieldElementK256) Profile() curves.FieldProfile {
	return &FieldProfileK256{}
}

func (*FieldElementK256) New(value uint64) curves.FieldElement[CurveIdentifierK256] {
	t := fp.New()
	t.SetUint64(value)
	return &FieldElementK256{
		v: t,
	}
}

func (*FieldElementK256) Hash(x []byte) (curves.FieldElement[CurveIdentifierK256], error) {
	els, err := New().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash to field element in k256")
	}
	return els[0], nil
}

func (e *FieldElementK256) Cmp(rhs curves.FieldElement[CurveIdentifierK256]) int {
	rhsK256, ok := rhs.(*FieldElementK256)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhsK256.FieldValue())
}

func (e *FieldElementK256) SubfieldElement(index uint64) curves.FieldElement[CurveIdentifierK256] {
	return e
}

func (e *FieldElementK256) Random(prng io.Reader) (curves.FieldElement[CurveIdentifierK256], error) {
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

func (*FieldElementK256) Zero() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: fp.New().SetZero(),
	}
}

func (*FieldElementK256) One() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: fp.New().SetOne(),
	}
}

func (e *FieldElementK256) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e *FieldElementK256) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e *FieldElementK256) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *FieldElementK256) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *FieldElementK256) Square() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: e.v.Square(e.v),
	}
}

func (e *FieldElementK256) Double() curves.FieldElement[CurveIdentifierK256] {
	return &FieldElementK256{
		v: e.v.Double(e.v),
	}
}

func (e *FieldElementK256) Sqrt() (curves.FieldElement[CurveIdentifierK256], bool) {
	result, wasSquare := fp.New().Sqrt(e.v)
	return &FieldElementK256{
		v: result,
	}, wasSquare
}

func (e *FieldElementK256) Cube() curves.FieldElement[CurveIdentifierK256] {
	return e.Square().Mul(e)
}

func (e *FieldElementK256) Add(rhs curves.FieldElement[CurveIdentifierK256]) curves.FieldElement[CurveIdentifierK256] {
	n, ok := rhs.(*FieldElementK256)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElementK256{
		v: fp.New().Add(e.v, n.FieldValue()),
	}
}

func (e *FieldElementK256) Sub(rhs curves.FieldElement[CurveIdentifierK256]) curves.FieldElement[CurveIdentifierK256] {
	n, ok := rhs.(*FieldElementK256)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElementK256{
		v: fp.New().Sub(e.v, n.FieldValue()),
	}
}

func (e *FieldElementK256) Mul(rhs curves.FieldElement[CurveIdentifierK256]) curves.FieldElement[CurveIdentifierK256] {
	n, ok := rhs.(*FieldElementK256)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElementK256{
		v: fp.New().Mul(e.v, n.FieldValue()),
	}
}

func (e *FieldElementK256) MulAdd(y, z curves.FieldElement[CurveIdentifierK256]) curves.FieldElement[CurveIdentifierK256] {
	return e.Mul(y).Add(z)
}

func (e *FieldElementK256) Div(rhs curves.FieldElement[CurveIdentifierK256]) curves.FieldElement[CurveIdentifierK256] {
	r, ok := rhs.(*FieldElementK256)
	if ok {
		v, wasInverted := fp.New().Invert(r.v)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElementK256{v: v}
	} else {
		panic("rhs is not ElementK256")
	}
}

func (e *FieldElementK256) Exp(rhs curves.FieldElement[CurveIdentifierK256]) curves.FieldElement[CurveIdentifierK256] {
	n, ok := rhs.(*FieldElementK256)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &FieldElementK256{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e *FieldElementK256) Neg() curves.FieldElement[CurveIdentifierK256] {
	var out [impl.FieldLimbs]uint64
	e.v.Arithmetic.Neg(&out, &e.v.Value)
	return &FieldElementK256{
		v: e.v.Neg(e.v),
	}
}

func (e *FieldElementK256) SetNat(value *saferith.Nat) (curves.FieldElement[CurveIdentifierK256], error) {
	e.v = fp.New().SetNat(value)
	return e, nil
}

func (e *FieldElementK256) Nat() *saferith.Nat {
	return e.v.Nat()
}

func (e *FieldElementK256) SetBytes(input []byte) (curves.FieldElement[CurveIdentifierK256], error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("input length %d != %d bytes", len(input), base.FieldBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result, err := e.v.SetBytes((*[base.FieldBytes]byte)(buffer))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &FieldElementK256{
		v: result,
	}, nil
}

func (e *FieldElementK256) SetBytesWide(input []byte) (curves.FieldElement[CurveIdentifierK256], error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length > %d bytes", base.WideFieldBytes)
	}
	buffer := bitstring.ReverseAndPadBytes(input, base.WideFieldBytes-len(input))
	result := e.v.SetBytesWide((*[base.WideFieldBytes]byte)(buffer))
	return &FieldElementK256{
		v: result,
	}, nil
}

func (e *FieldElementK256) Bytes() []byte {
	result := e.v.Bytes()
	return result[:]
}

func (e *FieldElementK256) FromScalar(sc curves.Scalar[CurveIdentifierK256]) (curves.FieldElement[CurveIdentifierK256], error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a K256 scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElementK256) Scalar() (curves.Scalar[CurveIdentifierK256], error) {
	results, err := New().Scalar().SetBytes(e.Bytes())
	if err != nil {
		return nil, errs.WrapFailed(err, "could not convert field element to scalar")
	}
	return results, nil
}
