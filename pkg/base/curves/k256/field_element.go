package k256

import (
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/serialisation"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.BaseFieldElement = (*BaseFieldElement)(nil)

type BaseFieldElement struct {
	V *impl.FieldValue

	_ types.Incomparable
}

func NewBaseFieldElement(value uint64) *BaseFieldElement {
	t := fp.New()
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
		V: fp.New().Set(e.V),
	}
}

// === Additive Groupoid Methods.

func (e *BaseFieldElement) Add(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &BaseFieldElement{
		V: fp.New().Add(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplyAdd(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Add(x.Mul(reducedN))
}

func (e *BaseFieldElement) Double() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: e.V.Double(e.V),
	}
}

func (e *BaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *BaseFieldElement) Mul(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &BaseFieldElement{
		V: fp.New().Mul(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplyMul(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Mul(x.Exp(reducedN))
}

func (e *BaseFieldElement) Square() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: e.V.Square(e.V),
	}
}

func (e *BaseFieldElement) Cube() curves.BaseFieldElement {
	return e.Square().Mul(e)
}

// === Additive Monoid Methods.

func (e *BaseFieldElement) IsAdditiveIdentity() bool {
	return e.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (e *BaseFieldElement) IsMultiplicativeIdentity() bool {
	return e.V.IsOne() == 1
}

// === Additive Group Methods.

func (e *BaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: fp.New().Neg(e.V),
	}
}

func (e *BaseFieldElement) IsAdditiveInverse(of curves.BaseFieldElement) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *BaseFieldElement) Sub(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a k256 Fp element")
	}
	return &BaseFieldElement{
		V: fp.New().Sub(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplySub(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Sub(x.Mul(reducedN))
}

// === Mulitplicative Group Methods.

func (e *BaseFieldElement) MultiplicativeInverse() curves.BaseFieldElement {
	value, wasInverted := fp.New().Invert(e.V)
	if !wasInverted {
		panic(errs.NewFailed("multiplicative inverse doesn't exist"))
	}
	return &BaseFieldElement{
		V: value,
	}
}

func (e *BaseFieldElement) IsMultiplicativeInverse(of curves.BaseFieldElement) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *BaseFieldElement) Div(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	r, ok := rhs.(*BaseFieldElement)
	if ok {
		v, wasInverted := fp.New().Invert(r.V)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.V)
		return &BaseFieldElement{V: v}
	} else {
		panic("rhs is not ElementK256")
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
	result, wasSquare := fp.New().Sqrt(e.V)
	if !wasSquare {
		return nil, errs.NewFailed("element did not have a quadratic residue")
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
		panic("not a k256 Fp element")
	}
	return &BaseFieldElement{
		V: e.V.Exp(e.V, n.V),
	}
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

func (e *BaseFieldElement) IsEven() bool {
	return e.V.Bytes()[0]&1 == 0
}

func (e *BaseFieldElement) IsOdd() bool {
	return e.V.Bytes()[0]&1 == 1
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
	rhsK256, ok := rhs.(*BaseFieldElement)
	if !ok {
		return -2
	}
	return algebra.Ordering(e.V.Cmp(rhsK256.V))
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

// === Curve methods.

func (*BaseFieldElement) BaseField() curves.BaseField {
	return NewBaseField()
}

// === Serialisation.

func (e *BaseFieldElement) MarshalBinary() ([]byte, error) {
	res, err := serialisation.ScalarLikeMarshalBinary[curves.BaseFieldElement](e.BaseField().Curve().Name(), e.BaseField().FieldBytes(), e)
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

func (*BaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	if value == nil {
		return nil
	}
	return &BaseFieldElement{
		V: fp.New().SetNat(value),
	}
}

func (e *BaseFieldElement) Nat() *saferith.Nat {
	return e.V.Nat()
}

func (e *BaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewInvalidLength("input length %d != %d bytes", len(input), base.FieldBytes)
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
	result := e.V.Bytes()
	return bitstring.ReverseBytes(result[:])
}
