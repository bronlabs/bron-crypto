package curve25519

import (
	"crypto/subtle"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.BaseFieldElement = (*BaseFieldElement)(nil)

type BaseFieldElement struct {
	V [base.FieldBytes]byte

	_ types.Incomparable
}

func NewBaseFieldElement(value uint64) *BaseFieldElement {
	panic("not implemented")
}

// === Basic Methods.

func (e *BaseFieldElement) Equal(rhs curves.BaseFieldElement) bool {
	r, ok := rhs.(*BaseFieldElement)
	return ok && subtle.ConstantTimeCompare(e.V[:], r.V[:]) == 1
}

func (e *BaseFieldElement) Clone() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: e.V,
	}
}

// === Additive Groupoid Methods.

func (*BaseFieldElement) Add(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) ApplyAdd(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Add(x.Mul(reducedN))
}

func (*BaseFieldElement) Double() curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (*BaseFieldElement) Mul(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) ApplyMul(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Mul(x.Exp(reducedN))
}

func (*BaseFieldElement) Square() curves.BaseFieldElement {
	panic("not implemented")
}

func (*BaseFieldElement) Cube() curves.BaseFieldElement {
	panic("not implemented")
}

// === Additive Monoid Methods.

func (*BaseFieldElement) IsAdditiveIdentity() bool {
	panic("not implemented")
}

// === Multiplicative Monoid Methods.

func (*BaseFieldElement) IsMultiplicativeIdentity() bool {
	panic("not implemented")
}

// === Additive Group Methods.

func (*BaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) IsAdditiveInverse(of curves.BaseFieldElement) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (*BaseFieldElement) Sub(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) ApplySub(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Sub(x.Mul(reducedN))
}

// === Multiplicative Group Methods.

func (*BaseFieldElement) MultiplicativeInverse() curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) IsMultiplicativeInverse(of curves.BaseFieldElement) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (*BaseFieldElement) Div(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) ApplyDiv(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Div(x.Exp(reducedN))
}

// === Ring Methods.

func (*BaseFieldElement) MulAdd(y, z curves.BaseFieldElement) curves.BaseFieldElement {
	panic("not implemented")
}

func (*BaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	panic("not implemented")
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

func (*BaseFieldElement) IsOdd() bool {
	panic("not implemented")
}

func (*BaseFieldElement) IsEven() bool {
	panic("not implemented")
}

func (*BaseFieldElement) Increment() {
	panic("not implemented")
}

func (*BaseFieldElement) Decrement() {
	panic("not implemented")
}

// === Ordering Methods.

func (*BaseFieldElement) Cmp(rhs curves.BaseFieldElement) algebra.Ordering {
	panic("not implemented")
}

func (*BaseFieldElement) IsBottom() bool {
	panic("not implemented")
}

func (*BaseFieldElement) IsTop() bool {
	panic("not implemented")
}

func (*BaseFieldElement) Join(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	panic("not implemented")
}

func (*BaseFieldElement) Max(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	panic("not implemented")
}

func (*BaseFieldElement) Meet(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	panic("not implemented")
}

func (*BaseFieldElement) Min(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	panic("not implemented")
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
	sc, err := impl.UnmarshalBinary(e.SetBytes, input)
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
	panic("not implemented")
}

func (e *BaseFieldElement) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBytes(e.Bytes())
}

func (*BaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	panic("not implemented")
}

func (*BaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	panic("not implemented")
}

func (e *BaseFieldElement) Bytes() []byte {
	return e.V[:]
}
