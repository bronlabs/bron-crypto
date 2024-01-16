package edwards25519

import (
	"encoding/binary"

	filippo_field "filippo.io/edwards25519/field"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.BaseFieldElement = (*BaseFieldElement)(nil)

type BaseFieldElement struct {
	V *filippo_field.Element

	_ types.Incomparable
}

func NewBaseFieldElement(value uint64) *BaseFieldElement {
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint64(buf, value)
	el, err := new(filippo_field.Element).SetBytes(buf)
	if err != nil {
		panic(err)
	}
	return &BaseFieldElement{
		V: el,
	}
}

// === Basic Methods.

func (e *BaseFieldElement) Equal(rhs curves.BaseFieldElement) bool {
	return e.Cmp(rhs) == 0
}

func (e *BaseFieldElement) Clone() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Set(e.V),
	}
}

// === Additive Groupoid Methods.

func (e *BaseFieldElement) Add(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &BaseFieldElement{
		V: new(filippo_field.Element).Add(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplyAdd(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Add(x.Mul(reducedN))
}

func (e *BaseFieldElement) Double() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Add(e.V, e.V),
	}
}

func (e *BaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *BaseFieldElement) Mul(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &BaseFieldElement{
		V: new(filippo_field.Element).Multiply(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplyMul(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Mul(x.Exp(reducedN))
}

func (e *BaseFieldElement) Square() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Square(e.V),
	}
}

func (e *BaseFieldElement) Cube() curves.BaseFieldElement {
	eSq := new(filippo_field.Element).Square(e.V)
	return &BaseFieldElement{
		V: eSq.Multiply(eSq, e.V),
	}
}

// === Additive Monoid Methods.

func (e *BaseFieldElement) IsAdditiveIdentity() bool {
	return e.V.Equal(feZero) == 1
}

// === Multiplicative Monoid Methods.

func (e *BaseFieldElement) IsMultiplicativeIdentity() bool {
	return e.V.Equal(feOne) == 1
}

// === Additive Group Methods.

func (e *BaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Negate(e.V),
	}
}

func (e *BaseFieldElement) IsAdditiveInverse(of curves.BaseFieldElement) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *BaseFieldElement) Sub(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &BaseFieldElement{
		V: new(filippo_field.Element).Subtract(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplySub(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Sub(x.Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *BaseFieldElement) MultiplicativeInverse() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Invert(e.V),
	}
}

func (e *BaseFieldElement) IsMultiplicativeInverse(of curves.BaseFieldElement) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *BaseFieldElement) Div(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	rhsFe, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	inverted := new(filippo_field.Element).Invert(rhsFe.V)
	if inverted.Equal(feZero) == 1 {
		panic("inverse of rhs is zero. cannot divide")
	}
	return &BaseFieldElement{
		V: inverted.Multiply(e.V, inverted),
	}
}

func (e *BaseFieldElement) ApplyDiv(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Div(x.Exp(reducedN))
}

// === Ring Methods.

func (e *BaseFieldElement) MulAdd(y, z curves.BaseFieldElement) curves.BaseFieldElement {
	yFe, ok := y.(*BaseFieldElement)
	if !ok {
		panic("y is not an edwards25519 base field element")
	}
	zFe, ok := z.(*BaseFieldElement)
	if !ok {
		panic("y is not an edwards25519 base field element")
	}
	v := new(filippo_field.Element).Multiply(e.V, yFe.V)
	return &BaseFieldElement{
		V: v.Add(v, zFe.V),
	}
}

func (e *BaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	res, ok := e.V.SqrtRatio(e.V, feOne)
	if ok == 1 {
		return &BaseFieldElement{
			V: res,
		}, nil
	}
	return nil, errs.NewFailed("could compute sqrt")
}

// === Finite Field Methods.

func (e *BaseFieldElement) SubFieldElement(index uint) curves.BaseFieldElement {
	return e
}

func (e *BaseFieldElement) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *BaseFieldElement) Exp(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	return e.ApplyMul(e, rhs.Nat())
}

func (e *BaseFieldElement) Neg() curves.BaseFieldElement {
	return e.AdditiveInverse()
}

func (e *BaseFieldElement) IsZero() bool {
	return e.IsAdditiveIdentity()
}

func (e *BaseFieldElement) IsOne() bool {
	return e.IsMultiplicativeIdentity()
}

func (e *BaseFieldElement) IsOdd() bool {
	return e.V.Bytes()[0]&1 == 1
}

func (e *BaseFieldElement) IsEven() bool {
	return e.V.Bytes()[0]&1 == 0
}

func (e *BaseFieldElement) Increment() {
	ee, ok := e.Add(NewBaseFieldElement(1)).(*BaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	e.V = ee.V
}

func (e *BaseFieldElement) Decrement() {
	ee, ok := e.Sub(NewBaseFieldElement(1)).(*BaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	e.V = ee.V
}

// === Ordering Methods.

func (e *BaseFieldElement) Cmp(rhs curves.BaseFieldElement) algebra.Ordering {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		return algebra.Incomparable
	}
	if e.V.Equal(n.V) == 1 {
		return algebra.Equal
	}
	v := e.V.Subtract(e.V, n.V)
	if v.IsNegative() == 1 {
		return algebra.LessThan
	}
	return algebra.GreaterThan
}

func (e *BaseFieldElement) IsBottom() bool {
	return e.IsZero()
}

func (e *BaseFieldElement) IsTop() bool {
	return e.Add(e.BaseField().One()).IsZero()
}

func (e *BaseFieldElement) Join(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Max(rhs)
}

func (e *BaseFieldElement) Max(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	switch e.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan:
		return rhs
	case algebra.Equal, algebra.GreaterThan:
		return e
	default:
		panic("comparison output not supported")
	}
}

func (e *BaseFieldElement) Meet(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Min(rhs)
}

func (e *BaseFieldElement) Min(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	switch e.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan, algebra.Equal:
		return e
	case algebra.GreaterThan:
		return rhs
	default:
		panic("comparison output not supported")
	}
}

// === Curve Methods.

func (*BaseFieldElement) BaseField() curves.BaseField {
	return NewBaseField()
}

// === Serialisation.

func (e *BaseFieldElement) MarshalBinary() ([]byte, error) {
	res, err := serialisation.ScalarLikeMarshalBinary[curves.Scalar](e.BaseField().Curve().Name(), e.BaseField().FieldBytes(), e)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElement) UnmarshalBinary(input []byte) error {
	sc, err := serialisation.ScalarLikeUnmarshalBinary(Name, e.SetBytes, e.BaseField().FieldBytes(), input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	ss, ok := sc.(*BaseFieldElement)
	if !ok {
		return errs.NewInvalidType("invalid base field element")
	}
	e.V = ss.V
	return nil
}

func (e *BaseFieldElement) MarshalJSON() ([]byte, error) {
	res, err := serialisation.ScalarLikeMarshalJson[curves.BaseFieldElement](Name, e)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElement) UnmarshalJSON(input []byte) error {
	sc, err := serialisation.NewScalarLikeFromJSON(e.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*BaseFieldElement)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	e.V = S.V
	return nil
}

func (e *BaseFieldElement) Uint64() uint64 {
	return e.Nat().Uint64()
}

func (e *BaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	if value == nil {
		return nil
	}
	moddedValue := new(saferith.Nat).Mod(value, e.BaseField().Order())
	v, err := new(filippo_field.Element).SetBytes(bitstring.ReverseBytes(moddedValue.Bytes()))
	if err != nil {
		panic(errs.WrapSerialisation(err, "could not set nat bytes"))
	}
	return &BaseFieldElement{
		V: v,
	}
}

func (e *BaseFieldElement) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBytes(e.Bytes())
}

func (e *BaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("input length != %d bytes", base.FieldBytes)
	}
	result, err := e.V.SetBytes(bitstring.ReverseBytes(input))
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not set bytes")
	}
	return &BaseFieldElement{
		V: result,
	}, nil
}

func (e *BaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length > %d bytes", base.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), 64-len(input))
	result, err := e.V.SetWideBytes(buffer)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not set bytes")
	}
	return &BaseFieldElement{
		V: result,
	}, nil
}

func (e *BaseFieldElement) Bytes() []byte {
	result := e.V.Bytes()
	return bitstring.ReverseBytes(result[:])
}
