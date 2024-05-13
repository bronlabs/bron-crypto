package curve25519

import (
	"crypto/subtle"
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

var _ curves.BaseFieldElement = (*BaseFieldElement)(nil)
var _ encoding.BinaryMarshaler = (*BaseFieldElement)(nil)
var _ encoding.BinaryUnmarshaler = (*BaseFieldElement)(nil)
var _ json.Unmarshaler = (*BaseFieldElement)(nil)

type BaseFieldElement struct {
	integer.Number[curves.BaseFieldElement]
	algebra.BoundedOrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]
	V [base.FieldBytes]byte

	_ ds.Incomparable
}

func (*BaseFieldElement) Mod(m curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	panic("implement me")
}

func NewBaseFieldElement(value uint64) *BaseFieldElement {
	panic("not implemented")
}

func (*BaseFieldElement) Structure() curves.BaseField {
	return NewBaseField()
}

func (e *BaseFieldElement) Unwrap() curves.BaseFieldElement {
	return e
}
func (*BaseFieldElement) Operate(op algebra.Operator, rhs algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	panic("implement me")
}
func (*BaseFieldElement) CanGenerateAllElements(under algebra.Operator) bool {
	panic("implement me")
}
func (*BaseFieldElement) IsInvolution(under algebra.Operator) (bool, error) {
	panic("implement me")
}
func (*BaseFieldElement) IsInvolutionUnderAddition() bool {
	panic("implement me")
}
func (*BaseFieldElement) IsInvolutionUnderMultiplication() bool {
	panic("implement me")
}

func (*BaseFieldElement) Order(operator algebra.Operator) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Apply(operator algebra.Operator, x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsIdentity(under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Inverse(under algebra.Operator) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsInverse(of algebra.GroupElement[curves.BaseField, curves.BaseFieldElement], under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsTorsionElement(order *saferith.Modulus, under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) CoPrime(x curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) GCD(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) LCM(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Factorise() []curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) EuclideanDiv(x curves.BaseFieldElement) (quotient, reminder curves.BaseFieldElement) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Lattice() algebra.OrderTheoreticLattice[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Next() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Previous() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Chain() algebra.Chain[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

// func (*BaseFieldElement) Int() integer.Int {
// 	//TODO implement me
// 	panic("implement me")
// }

// func (*BaseFieldElement) FromInt(v integer.Int) curves.BaseFieldElement {
// 	//TODO implement me
// 	panic("implement me")
// }

func (*BaseFieldElement) Not() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) ExclusiveDisjunctiveInverse() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Lsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Rsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) SetBytesLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) SetBytesWideLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Conjugate() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

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

func (*BaseFieldElement) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (*BaseFieldElement) Double() curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (*BaseFieldElement) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
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

func (e *BaseFieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (*BaseFieldElement) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	panic("not implemented")
}

func (e *BaseFieldElement) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (*BaseFieldElement) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	panic("not implemented")
}

func (e *BaseFieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (*BaseFieldElement) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	panic("not implemented")
}

func (e *BaseFieldElement) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (*BaseFieldElement) MulAdd(y algebra.RgElement[curves.BaseField, curves.BaseFieldElement], z algebra.RgElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	panic("not implemented")
}

func (*BaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	panic("not implemented")
}

// === Finite Field Methods.

func (e *BaseFieldElement) SubFieldElement(index uint) (curves.BaseFieldElement, error) {
	return e, nil
}

func (e *BaseFieldElement) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *BaseFieldElement) Exp(exp *saferith.Nat) curves.BaseFieldElement {
	return e.ApplyMul(e, exp)
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

func (*BaseFieldElement) Increment() curves.BaseFieldElement {
	panic("not implemented")
}

func (*BaseFieldElement) Decrement() curves.BaseFieldElement {
	panic("not implemented")
}

// === Ordering Methods.

func (*BaseFieldElement) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	panic("not implemented")
}

func (*BaseFieldElement) IsBottom() bool {
	panic("not implemented")
}

func (*BaseFieldElement) IsTop() bool {
	panic("not implemented")
}

func (e *BaseFieldElement) Join(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Max(rhs.Unwrap())
}

func (e *BaseFieldElement) Max(rhs algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	switch e.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan:
		return rhs.Unwrap()
	case algebra.Equal, algebra.GreaterThan:
		return e
	default:
		panic("comparison output not supported")
	}
}

func (e *BaseFieldElement) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Min(rhs.Unwrap())
}

func (e *BaseFieldElement) Min(rhs algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	switch e.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan, algebra.Equal:
		return e
	case algebra.GreaterThan:
		return rhs.Unwrap()
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
		return errs.NewType("name %s is not supported", name)
	}
	ss, ok := sc.(*BaseFieldElement)
	if !ok {
		return errs.NewType("invalid base field element")
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
		return errs.NewType("name %s is not supported", name)
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
	return &BaseFieldElement{
		V: *(*[base.FieldBytes]byte)(value.Bytes()),
	}
}

func (e *BaseFieldElement) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBytes(e.Bytes())
}

func (*BaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	var result BaseFieldElement
	copy(result.V[:], input)
	return &result, nil
}

func (*BaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	panic("not implemented")
}

func (e *BaseFieldElement) Bytes() []byte {
	return e.V[:]
}
func (e *BaseFieldElement) HashCode() uint64 {
	return e.Uint64()
}
