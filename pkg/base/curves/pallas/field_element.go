package pallas

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.BaseFieldElement = (*BaseFieldElement)(nil)
var _ encoding.BinaryMarshaler = (*BaseFieldElement)(nil)
var _ encoding.BinaryUnmarshaler = (*BaseFieldElement)(nil)
var _ json.Unmarshaler = (*BaseFieldElement)(nil)

type BaseFieldElement struct {
	V *fp.Fp

	_ types.Incomparable
}

func NewBaseFieldElement(value uint64) *BaseFieldElement {
	t := new(fp.Fp)
	t.SetUint64(value)
	return &BaseFieldElement{
		V: t,
	}
}

// === Basic Methods.

func (e *BaseFieldElement) Equal(rhs curves.BaseFieldElement) bool {
	return e.Cmp(rhs) == 0
}

func (e *BaseFieldElement) Clone() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(fp.Fp).Set(e.V),
	}
}

// === Additive Groupoid Methods.

func (e *BaseFieldElement) Add(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &BaseFieldElement{
		V: new(fp.Fp).Add(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplyAdd(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Add(x.Mul(reducedN))
}

func (e *BaseFieldElement) Double() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(fp.Fp).Double(e.V),
	}
}

func (e *BaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *BaseFieldElement) Mul(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &BaseFieldElement{
		V: new(fp.Fp).Mul(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplyMul(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Mul(x.Exp(reducedN))
}

func (e *BaseFieldElement) Square() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(fp.Fp).Square(e.V),
	}
}

func (e *BaseFieldElement) Cube() curves.BaseFieldElement {
	return e.Square().Mul(e)
}

// === Additive Monoid Methods.

func (e *BaseFieldElement) IsAdditiveIdentity() bool {
	return e.V.IsZero()
}

// === Multiplicative Monoid Methods.

func (e *BaseFieldElement) IsMultiplicativeIdentity() bool {
	return e.V.IsOne()
}

// === Additive Group Methods.

func (e *BaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(fp.Fp).Neg(e.V),
	}
}

func (e *BaseFieldElement) IsAdditiveInverse(of curves.BaseFieldElement) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *BaseFieldElement) Sub(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}
	return &BaseFieldElement{
		V: new(fp.Fp).Sub(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplySub(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Sub(x.Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *BaseFieldElement) MultiplicativeInverse() curves.BaseFieldElement {
	v, ok := new(fp.Fp).Invert(e.V)
	if !ok {
		panic("could not invert")
	}
	return &BaseFieldElement{
		V: v,
	}
}

func (e *BaseFieldElement) IsMultiplicativeInverse(of curves.BaseFieldElement) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *BaseFieldElement) Div(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	r, ok := rhs.(*BaseFieldElement)
	if ok {
		v, wasInverted := new(fp.Fp).Invert(r.V)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.V)
		return &BaseFieldElement{V: v}
	} else {
		panic("rhs is not pallas base field element")
	}
}

func (e *BaseFieldElement) ApplyDiv(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Div(x.Exp(reducedN))
}

// === Ring Methods.

func (e *BaseFieldElement) MulAdd(y, z curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Mul(y).Add(z)
}

func (e *BaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	result, wasSquare := new(fp.Fp).Sqrt(e.V)
	if !wasSquare {
		return nil, errs.NewFailed("element did not have a sqrt")
	}
	return &BaseFieldElement{
		V: result,
	}, nil
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
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a pallas base field element")
	}
	return &BaseFieldElement{
		V: e.V.Exp(e.V, n.V),
	}
}

func (e *BaseFieldElement) Neg() curves.BaseFieldElement {
	return e.AdditiveInverse()
}

func (e *BaseFieldElement) IsZero() bool {
	return e.V.IsZero()
}

func (e *BaseFieldElement) IsOne() bool {
	return e.V.IsOne()
}

func (e *BaseFieldElement) IsOdd() bool {
	return e.V.IsOdd()
}

func (e *BaseFieldElement) IsEven() bool {
	return !e.V.IsOdd()
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
	rhse, ok := rhs.(*BaseFieldElement)
	if !ok {
		return algebra.Incomparable
	}
	return algebra.Ordering(e.V.Cmp(rhse.V))
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
	res := impl.MarshalBinary(e.BaseField().Curve().Name(), e.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElement) UnmarshalBinary(input []byte) error {
	sc, err := impl.UnmarshalBinary(NewBaseFieldElement(0).SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != e.BaseField().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
	}
	ss, ok := sc.(*BaseFieldElement)
	if !ok {
		return errs.NewInvalidType("invalid base field element")
	}
	e.V = ss.V
	return nil
}

func (e *BaseFieldElement) MarshalJSON() ([]byte, error) {
	res, err := impl.MarshalJson(e.BaseField().Curve().Name(), e.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElement) UnmarshalJSON(input []byte) error {
	sc, err := impl.UnmarshalJson(e.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != e.BaseField().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
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

func (*BaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	if value == nil {
		return nil
	}
	v := new(fp.Fp).SetNat(value)
	return &BaseFieldElement{
		V: v,
	}
}

func (e *BaseFieldElement) Nat() *saferith.Nat {
	return e.V.Nat()
}

func (e *BaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("input length %d > %d bytes", len(input), base.FieldBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result, err := e.V.SetBytes((*[base.FieldBytes]byte)(buffer))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &BaseFieldElement{
		V: result,
	}, nil
}

func (e *BaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewInvalidLength("input length > %d bytes", base.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), base.WideFieldBytes-len(input))
	result := e.V.SetBytesWide((*[base.WideFieldBytes]byte)(buffer))
	return &BaseFieldElement{
		V: result,
	}, nil
}

func (e *BaseFieldElement) Bytes() []byte {
	v := e.V.Bytes()
	return bitstring.ReverseBytes(v[:])
}
