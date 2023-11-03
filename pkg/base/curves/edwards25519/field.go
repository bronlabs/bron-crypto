package edwards25519

import (
	"encoding/binary"
	"io"

	"filippo.io/edwards25519/field"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

type FieldProfile struct{}

func (*FieldProfile) Curve() curves.Curve {
	return &edwards25519Instance
}

func (*FieldProfile) Order() *saferith.Modulus {
	return baseFieldOrder
}

func (*FieldProfile) Characteristic() *saferith.Nat {
	return baseFieldOrder.Nat()
}

func (*FieldProfile) ExtensionDegree() *saferith.Nat {
	return new(saferith.Nat).SetUint64(1)
}

var _ curves.FieldElement = (*FieldElement)(nil)

type FieldElement struct {
	v *field.Element

	_ types.Incomparable
}

func (*FieldElement) Profile() curves.FieldProfile {
	return &FieldProfile{}
}

// Hash TODO: implement
func (*FieldElement) Hash(x []byte) curves.FieldElement {
	return nil
}

func (*FieldElement) Value() curves.FieldValue {
	return nil
}

func (*FieldElement) Modulus() *saferith.Modulus {
	return baseFieldOrder
}

func (e *FieldElement) Clone() curves.FieldElement {
	return &FieldElement{
		v: e.v,
	}
}

func (e *FieldElement) Cmp(rhs curves.FieldElement) int {
	n, ok := rhs.(*FieldElement)
	if !ok {
		return -2
	}
	if e.v.Equal(n.v) == 1 {
		return 0
	}
	v := e.v.Subtract(e.v, n.v)
	if v.IsNegative() == 1 {
		return -1
	}
	return 1
}

func (e *FieldElement) SubfieldElement(index uint64) curves.FieldElement {
	return e
}

func (*FieldElement) New(value uint64) curves.FieldElement {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	el, err := new(field.Element).SetBytes(buf)
	if err != nil {
		panic(err)
	}
	return &FieldElement{
		v: el,
	}
}

func (*FieldElement) Random(prng io.Reader) curves.FieldElement {
	buf := make([]byte, 32)
	_, err := prng.Read(buf)
	if err != nil {
		panic(err)
	}
	el, err := new(field.Element).SetBytes(buf)
	if err != nil {
		panic(err)
	}
	return &FieldElement{
		v: el,
	}
}

func (e *FieldElement) Zero() curves.FieldElement {
	return &FieldElement{
		v: e.v.Zero(),
	}
}

func (e *FieldElement) One() curves.FieldElement {
	return &FieldElement{
		v: e.v.One(),
	}
}

func (e *FieldElement) IsZero() bool {
	return e.v.Equal(e.v.Zero()) == 1
}

func (e *FieldElement) IsOne() bool {
	return e.v.Equal(e.v.One()) == 1
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
	return e.Add(e)
}

func (e *FieldElement) Sqrt() (curves.FieldElement, bool) {
	res, ok := e.v.SqrtRatio(e.v, e.v.One())
	if ok == 1 {
		return &FieldElement{
			v: res,
		}, true
	}
	return nil, false
}

func (e *FieldElement) Cube() curves.FieldElement {
	return e.Square().Mul(e)
}

func (e *FieldElement) Add(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &FieldElement{
		v: e.v.Add(e.v, n.v),
	}
}

func (e *FieldElement) Sub(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &FieldElement{
		v: e.v.Subtract(e.v, n.v),
	}
}

func (e *FieldElement) Mul(rhs curves.FieldElement) curves.FieldElement {
	n, ok := rhs.(*FieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &FieldElement{
		v: e.v.Multiply(e.v, n.v),
	}
}

func (e *FieldElement) MulAdd(y, z curves.FieldElement) curves.FieldElement {
	return e.Mul(y).Add(z)
}

func (e *FieldElement) Div(rhs curves.FieldElement) curves.FieldElement {
	inverted := e.v.Invert(e.v)
	zero := new(field.Element).Zero()
	if inverted.Equal(zero) == 1 {
		panic("could not invert")
	}
	return &FieldElement{
		v: e.v.Multiply(e.v, inverted),
	}
}

func (*FieldElement) Exp(rhs curves.FieldElement) curves.FieldElement {
	return nil
}

func (e *FieldElement) Neg() curves.FieldElement {
	return &FieldElement{
		v: e.v.Negate(e.v),
	}
}

func (*FieldElement) SetNat(value *saferith.Nat) (curves.FieldElement, error) {
	return nil, nil
}

func (*FieldElement) Nat() *saferith.Nat {
	return nil
}

func (*FieldElement) SetBytes(input []byte) (curves.FieldElement, error) {
	result, err := new(field.Element).SetBytes(input)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not set bytes")
	}
	return &FieldElement{
		v: result,
	}, nil
}

func (e *FieldElement) SetBytesWide(input []byte) (curves.FieldElement, error) {
	result, err := e.v.SetBytes(input)
	if err != nil {
		return nil, errs.WrapSerializationError(err, "could not set bytes")
	}
	return &FieldElement{
		v: result,
	}, nil
}

func (e *FieldElement) Bytes() []byte {
	return e.v.Bytes()
}

func (e *FieldElement) FromScalar(sc curves.Scalar) (curves.FieldElement, error) {
	if sc.CurveName() != Name {
		return nil, errs.NewInvalidType("scalar is not a ed25519 scalar")
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
