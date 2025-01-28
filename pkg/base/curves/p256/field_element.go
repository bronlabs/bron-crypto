package p256

import (
	"encoding"
	"encoding/json"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/ct"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	curvesImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl"
	fieldsImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl/fields"
	p256Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/p256/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var _ curves.BaseFieldElement = (*BaseFieldElement)(nil)
var _ encoding.BinaryMarshaler = (*BaseFieldElement)(nil)
var _ encoding.BinaryUnmarshaler = (*BaseFieldElement)(nil)
var _ json.Unmarshaler = (*BaseFieldElement)(nil)

type BaseFieldElement struct {
	V p256Impl.Fp

	_ ds.Incomparable
}

func NewBaseFieldElement(value uint64) *BaseFieldElement {
	t := new(BaseFieldElement)
	t.V.SetUint64(value)
	return t
}

func (*BaseFieldElement) Structure() curves.BaseField {
	return NewBaseField()
}

func (e *BaseFieldElement) Unwrap() curves.BaseFieldElement {
	return e
}

func (*BaseFieldElement) Order(operator algebra.BinaryOperator[curves.BaseFieldElement]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) ApplyOp(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsIdentity(under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) Inverse(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsInverse(of algebra.GroupElement[curves.BaseField, curves.BaseFieldElement], under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
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

func (*BaseFieldElement) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElement) FromInt(v algebra.Int) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

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

// === Basic Methods.

func (e *BaseFieldElement) Equal(rhs curves.BaseFieldElement) bool {
	rhse, ok := rhs.(*BaseFieldElement)
	if !ok {
		return false
	}
	return e.V.Equals(&rhse.V) == 1
}

func (e *BaseFieldElement) Clone() curves.BaseFieldElement {
	clone := new(BaseFieldElement)
	clone.V.Set(&e.V)
	return clone
}

// === Additive Groupoid Methods.

func (e *BaseFieldElement) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a p256 Fp element")
	}

	result := new(BaseFieldElement)
	result.V.Add(&e.V, &n.V)
	return result
}

func (e *BaseFieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *BaseFieldElement) Double() curves.BaseFieldElement {
	return e.Add(e)
}

func (e *BaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *BaseFieldElement) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a p256 Fp element")
	}

	result := new(BaseFieldElement)
	result.V.Mul(&e.V, &n.V)
	return result
}

func (e *BaseFieldElement) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *BaseFieldElement) Square() curves.BaseFieldElement {
	result := new(BaseFieldElement)
	result.V.Square(&e.V)
	return result
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
	result := new(BaseFieldElement)
	result.V.Neg(&e.V)
	return result
}

func (e *BaseFieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *BaseFieldElement) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("not a p256 Fp element")
	}

	result := new(BaseFieldElement)
	result.V.Sub(&e.V, &n.V)
	return result
}

func (e *BaseFieldElement) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Mulitplicative Group Methods.

func (e *BaseFieldElement) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	result := new(BaseFieldElement)
	wasInverted := result.V.Inv(&e.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("multiplicative inverse doesn't exist")
	}

	return result, nil
}

func (e *BaseFieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *BaseFieldElement) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	r, ok := rhs.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewFailed("rhs is not ElementP256")
	}

	result := new(BaseFieldElement)
	wasInverted := result.V.Div(&e.V, &r.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("cannot invert rhs")
	}
	return result, nil
}

func (e *BaseFieldElement) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (e *BaseFieldElement) MulAdd(y algebra.RingElement[curves.BaseField, curves.BaseFieldElement], z algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Mul(y).Add(z)
}

func (e *BaseFieldElement) IsQuadraticResidue() bool {
	_, err := e.Sqrt()
	return err != nil
}

func (e *BaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	result := new(BaseFieldElement)
	wasSquare := result.V.Sqrt(&e.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("element did not have a quadratic residue")
	}

	return result, nil
}

// === Finite Field Methods.
func (e *BaseFieldElement) SubFieldElement(i uint) (curves.BaseFieldElement, error) {
	return e, nil
}

func (e *BaseFieldElement) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *BaseFieldElement) Exp(exponent *saferith.Nat) curves.BaseFieldElement {
	eBytes := exponent.Bytes()
	slices.Reverse(eBytes)
	result := new(BaseFieldElement)
	fieldsImpl.Pow(&result.V, &e.V, eBytes)
	return result
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

func (e *BaseFieldElement) Increment() curves.BaseFieldElement {
	ee, ok := e.Add(NewBaseFieldElement(1)).(*BaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

func (e *BaseFieldElement) Decrement() curves.BaseFieldElement {
	ee, ok := e.Sub(NewBaseFieldElement(1)).(*BaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

// === Ordering Methods.

func (e *BaseFieldElement) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	rhsP256, ok := rhs.(*BaseFieldElement)
	if !ok {
		return -2
	}

	lhsLimbs := e.V.Limbs()
	rhsLimv := rhsP256.V.Limbs()
	return algebra.Ordering(ct.SliceCmpLE(lhsLimbs, rhsLimv))
}

func (e *BaseFieldElement) IsBottom() bool {
	return e.IsZero()
}

func (e *BaseFieldElement) IsTop() bool {
	return e.Add(e.BaseField().One()).IsZero()
}

func (e *BaseFieldElement) Join(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Max(rhs.Unwrap())
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

func (e *BaseFieldElement) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Min(rhs.Unwrap())
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
	res := curvesImpl.MarshalBinary(e.BaseField().Curve().Name(), e.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElement) UnmarshalBinary(input []byte) error {
	sc, err := curvesImpl.UnmarshalBinary(NewBaseFieldElement(0).SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	name, _, err := curvesImpl.ParseBinary(input)
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
	e.V.Set(&ss.V)
	return nil
}

func (e *BaseFieldElement) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(e.BaseField().Curve().Name(), e.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElement) UnmarshalJSON(input []byte) error {
	sc, err := curvesImpl.UnmarshalJson(e.BaseField().Name(), e.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*BaseFieldElement)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	e.V.Set(&S.V)
	return nil
}

func (e *BaseFieldElement) Uint64() uint64 {
	return e.Nat().Uint64()
}

func (*BaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	if value == nil {
		return nil
	}

	reducedNat := new(saferith.Nat).Mod(value, p256BaseFieldModulus)
	natBytes := reducedNat.Bytes()
	slices.Reverse(natBytes)
	result := new(BaseFieldElement)
	ok := result.V.SetBytesWide(natBytes)
	if ok != 1 {
		panic("this should never happen")
	}
	return result
}

func (e *BaseFieldElement) Nat() *saferith.Nat {
	eBytes := e.V.Bytes()
	slices.Reverse(eBytes)
	return new(saferith.Nat).SetBytes(eBytes)
}

func (*BaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != p256Impl.FpBytes {
		return nil, errs.NewLength("input length %d != %d bytes", len(input), p256Impl.FpBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result := new(BaseFieldElement)
	ok := result.V.SetBytes(buffer)
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}

	return result, nil
}

func (*BaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > p256Impl.FpWideBytes {
		return nil, errs.NewLength("input length > %d bytes", p256Impl.FpWideBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result := new(BaseFieldElement)
	ok := result.V.SetBytesWide(buffer)
	if ok != 1 {
		return nil, errs.NewFailed("could not set wide byte")
	}

	return result, nil
}

func (e *BaseFieldElement) Bytes() []byte {
	result := e.V.Bytes()
	slices.Reverse(result)
	return result
}

func (e *BaseFieldElement) HashCode() uint64 {
	return e.Uint64()
}
