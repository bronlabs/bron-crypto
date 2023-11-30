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

func (*FieldProfile) Curve() curves.Curve[CurveIdentifierP256] {
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

var _ curves.FieldElement[CurveIdentifierP256] = (*FieldElementP256)(nil)

type FieldElementP256 struct {
	v *impl.FieldValue

	_ types.Incomparable
}

func NewFieldElement() curves.FieldElement[CurveIdentifierP256] {
	emptyElement := &FieldElementP256{}
	result, _ := emptyElement.One().(*FieldElementP256)
	return result
}

func (e *FieldElementP256) FieldValue() *impl.FieldValue {
	return e.v
}

func (e *FieldElementP256) Value() curves.FieldValue {
	return e.v.Value[:]
}

func (e *FieldElementP256) Modulus() *saferith.Modulus {
	return e.v.Params.Modulus
}

func (e *FieldElementP256) Clone() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: fp.New().Set(e.v),
	}
}

func (*FieldElementP256) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

func (*FieldElementP256) New(value uint64) curves.FieldElement[CurveIdentifierP256] {
	t := fp.New()
	t.SetUint64(value)
	return &FieldElementP256{
		v: t,
	}
}

func (*FieldElementP256) Hash(x []byte) (curves.FieldElement[CurveIdentifierP256], error) {
	els, err := New().HashToFieldElements(1, x, nil)
	if err != nil {
		return nil, errs.WrapHashingFailed(err, "could not hash to field element in p256")
	}
	return els[0], nil
}

func (e *FieldElementP256) Cmp(rhs curves.FieldElement[CurveIdentifierP256]) int {
	rhse, ok := rhs.(*FieldElementP256)
	if !ok {
		return -2
	}
	return e.v.Cmp(rhse.FieldValue())
}

func (e *FieldElementP256) SubfieldElement(index uint64) curves.FieldElement[CurveIdentifierP256] {
	return e
}

func (e *FieldElementP256) Random(prng io.Reader) (curves.FieldElement[CurveIdentifierP256], error) {
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

func (*FieldElementP256) Zero() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: fp.New().SetZero(),
	}
}

func (*FieldElementP256) One() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: fp.New().SetOne(),
	}
}

func (e *FieldElementP256) IsZero() bool {
	return e.v.IsZero() == 1
}

func (e *FieldElementP256) IsOne() bool {
	return e.v.IsOne() == 1
}

func (e *FieldElementP256) IsOdd() bool {
	return e.v.Bytes()[0]&1 == 1
}

func (e *FieldElementP256) IsEven() bool {
	return e.v.Bytes()[0]&1 == 0
}

func (e *FieldElementP256) Square() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: e.v.Square(e.v),
	}
}

func (e *FieldElementP256) Double() curves.FieldElement[CurveIdentifierP256] {
	return &FieldElementP256{
		v: e.v.Double(e.v),
	}
}

func (e *FieldElementP256) Sqrt() (curves.FieldElement[CurveIdentifierP256], bool) {
	result, wasSquare := fp.New().Sqrt(e.v)
	return &FieldElementP256{
		v: result,
	}, wasSquare
}

func (e *FieldElementP256) Cube() curves.FieldElement[CurveIdentifierP256] {
	return e.Square().Mul(e)
}

func (e *FieldElementP256) Add(rhs curves.FieldElement[CurveIdentifierP256]) curves.FieldElement[CurveIdentifierP256] {
	n, ok := rhs.(*FieldElementP256)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElementP256{
		v: fp.New().Add(e.v, n.FieldValue()),
	}
}

func (e *FieldElementP256) Sub(rhs curves.FieldElement[CurveIdentifierP256]) curves.FieldElement[CurveIdentifierP256] {
	n, ok := rhs.(*FieldElementP256)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElementP256{
		v: fp.New().Sub(e.v, n.FieldValue()),
	}
}

func (e *FieldElementP256) Mul(rhs curves.FieldElement[CurveIdentifierP256]) curves.FieldElement[CurveIdentifierP256] {
	n, ok := rhs.(*FieldElementP256)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElementP256{
		v: fp.New().Mul(e.v, n.FieldValue()),
	}
}

func (e *FieldElementP256) MulAdd(y, z curves.FieldElement[CurveIdentifierP256]) curves.FieldElement[CurveIdentifierP256] {
	return e.Mul(y).Add(z)
}

func (e *FieldElementP256) Div(rhs curves.FieldElement[CurveIdentifierP256]) curves.FieldElement[CurveIdentifierP256] {
	r, ok := rhs.(*FieldElementP256)
	if ok {
		v, wasInverted := fp.New().Invert(r.v)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.v)
		return &FieldElementP256{v: v}
	} else {
		panic("rhs is not ElementP256")
	}
}

func (e *FieldElementP256) Exp(rhs curves.FieldElement[CurveIdentifierP256]) curves.FieldElement[CurveIdentifierP256] {
	n, ok := rhs.(*FieldElementP256)
	if !ok {
		panic("not a p256 Fp element")
	}
	return &FieldElementP256{
		v: e.v.Exp(e.v, n.v),
	}
}

func (e *FieldElementP256) Neg() curves.FieldElement[CurveIdentifierP256] {
	var out [impl.FieldLimbs]uint64
	e.v.Arithmetic.Neg(&out, &e.v.Value)
	return &FieldElementP256{
		v: e.v.Neg(e.v),
	}
}

func (e *FieldElementP256) SetNat(value *saferith.Nat) (curves.FieldElement[CurveIdentifierP256], error) {
	e.v = fp.New().SetNat(value)
	return e, nil
}

func (e *FieldElementP256) Nat() *saferith.Nat {
	return e.v.Nat()
}

func (e *FieldElementP256) SetBytes(input []byte) (curves.FieldElement[CurveIdentifierP256], error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("input length %d != %d bytes", len(input), base.FieldBytes)
	}
	input = bitstring.ReverseBytes(input)
	result, err := e.v.SetBytes((*[base.FieldBytes]byte)(input))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &FieldElementP256{
		v: result,
	}, nil
}

func (e *FieldElementP256) SetBytesWide(input []byte) (curves.FieldElement[CurveIdentifierP256], error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length > %d bytes", base.WideFieldBytes)
	}
	buffer := bitstring.ReverseAndPadBytes(input, base.WideFieldBytes-len(input))
	result := e.v.SetBytesWide((*[base.WideFieldBytes]byte)(buffer))
	return &FieldElementP256{
		v: result,
	}, nil
}

// Bytes returns a BigEndian representation of the field element.
func (e *FieldElementP256) Bytes() []byte {
	result := e.v.Bytes() // FieldValue.Bytes() is LittleEndian. Reverse it.
	return bitstring.ReverseBytes(result[:])
}

func (e *FieldElementP256) FromScalar(sc curves.Scalar[CurveIdentifierP256]) (curves.FieldElement[CurveIdentifierP256], error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a P256 scalar")
	}
	result, err := e.SetBytes(sc.Bytes())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert from scalar")
	}
	return result, nil
}

func (e *FieldElementP256) Scalar() (curves.Scalar[CurveIdentifierP256], error) {
	s, err := New().Scalar().SetNat(e.Nat())
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not convert to scalar")
	}
	return s, nil
}
