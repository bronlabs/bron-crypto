package pasta

import (
	"encoding"
	"encoding/json"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/bitstring"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	curvesImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl"
	fieldsImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/fields"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

var _ curves.BaseFieldElement = (*PallasBaseFieldElement)(nil)
var _ encoding.BinaryMarshaler = (*PallasBaseFieldElement)(nil)
var _ encoding.BinaryUnmarshaler = (*PallasBaseFieldElement)(nil)
var _ json.Unmarshaler = (*PallasBaseFieldElement)(nil)

type PallasBaseFieldElement struct {
	V pastaImpl.Fp

	_ ds.Incomparable
}

func NewPallasBaseFieldElement(value uint64) *PallasBaseFieldElement {
	t := new(PallasBaseFieldElement)
	t.V.SetUint64(value)
	return t
}

func (*PallasBaseFieldElement) Structure() curves.BaseField {
	return NewPallasBaseField()
}

func (e *PallasBaseFieldElement) Unwrap() curves.BaseFieldElement {
	return e
}

func (*PallasBaseFieldElement) Order(operator algebra.BinaryOperator[curves.BaseFieldElement]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) ApplyOp(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsIdentity(under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Inverse(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsInverse(of algebra.GroupElement[curves.BaseField, curves.BaseFieldElement], under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) CoPrime(x curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) GCD(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) LCM(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Factorise() []curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) EuclideanDiv(x curves.BaseFieldElement) (quotient, reminder curves.BaseFieldElement) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Lattice() algebra.OrderTheoreticLattice[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Next() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Previous() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Chain() algebra.Chain[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) FromInt(v algebra.Int) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Not() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) ExclusiveDisjunctiveInverse() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Lsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Rsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) SetBytesLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) SetBytesWideLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PallasBaseFieldElement) Conjugate() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (e *PallasBaseFieldElement) Equal(rhs curves.BaseFieldElement) bool {
	rhse, ok := rhs.(*PallasBaseFieldElement)
	if !ok {
		return false
	}
	return e.V.Equals(&rhse.V) == 1
}

func (e *PallasBaseFieldElement) Clone() curves.BaseFieldElement {
	result := new(PallasBaseFieldElement)
	result.V.Set(&e.V)
	return result
}

// === Additive Groupoid Methods.

func (e *PallasBaseFieldElement) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*PallasBaseFieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}

	result := new(PallasBaseFieldElement)
	result.V.Add(&e.V, &n.V)
	return result
}

func (e *PallasBaseFieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(PallasBaseFieldElement).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *PallasBaseFieldElement) Double() curves.BaseFieldElement {
	return e.Add(e)
}

func (e *PallasBaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *PallasBaseFieldElement) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*PallasBaseFieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}

	result := new(PallasBaseFieldElement)
	result.V.Mul(&e.V, &n.V)
	return result
}

func (e *PallasBaseFieldElement) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *PallasBaseFieldElement) Square() curves.BaseFieldElement {
	result := new(PallasBaseFieldElement)
	result.V.Square(&e.V)
	return result
}

func (e *PallasBaseFieldElement) Cube() curves.BaseFieldElement {
	return e.Square().Mul(e)
}

// === Additive Monoid Methods.

func (e *PallasBaseFieldElement) IsAdditiveIdentity() bool {
	return e.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (e *PallasBaseFieldElement) IsMultiplicativeIdentity() bool {
	return e.V.IsOne() == 1
}

// === Additive Group Methods.

func (e *PallasBaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	result := new(PallasBaseFieldElement)
	result.V.Neg(&e.V)
	return result
}

func (e *PallasBaseFieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *PallasBaseFieldElement) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*PallasBaseFieldElement)
	if !ok {
		panic("not a pallas Fp element")
	}

	result := new(PallasBaseFieldElement)
	result.V.Sub(&e.V, &n.V)
	return result
}

func (e *PallasBaseFieldElement) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(PallasBaseFieldElement).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *PallasBaseFieldElement) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	result := new(PallasBaseFieldElement)
	ok := result.V.Inv(&e.V)
	if ok != 1 {
		return nil, errs.NewFailed("division by zero")
	}

	return result, nil
}

func (e *PallasBaseFieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *PallasBaseFieldElement) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	r, ok := rhs.(*PallasBaseFieldElement)
	if !ok {
		return nil, errs.NewFailed("rhs is not pallas base field element")
	}

	result := new(PallasBaseFieldElement)
	wasInverted := result.V.Div(&e.V, &r.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("cannot invert rhs")
	}
	return result, nil
}

func (e *PallasBaseFieldElement) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (e *PallasBaseFieldElement) MulAdd(y algebra.RingElement[curves.BaseField, curves.BaseFieldElement], z algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Mul(y).Add(z)
}

func (e *PallasBaseFieldElement) IsQuadraticResidue() bool {
	_, err := e.Sqrt()
	return err != nil
}

func (e *PallasBaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	result := new(PallasBaseFieldElement)
	wasSquare := result.V.Sqrt(&e.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("element did not have a sqrt")
	}
	return result, nil
}

// === Finite Field Methods.

func (e *PallasBaseFieldElement) SubFieldElement(i uint) (curves.BaseFieldElement, error) {
	return e, nil
}

func (e *PallasBaseFieldElement) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *PallasBaseFieldElement) Exp(exponent *saferith.Nat) curves.BaseFieldElement {
	eBytes := exponent.Bytes()
	slices.Reverse(eBytes)
	result := new(PallasBaseFieldElement)
	fieldsImpl.Pow(&result.V, &e.V, eBytes)
	return result
}

func (e *PallasBaseFieldElement) Neg() curves.BaseFieldElement {
	return e.AdditiveInverse()
}

func (e *PallasBaseFieldElement) IsZero() bool {
	return e.V.IsZero() == 1
}

func (e *PallasBaseFieldElement) IsOne() bool {
	return e.V.IsOne() == 1
}

func (e *PallasBaseFieldElement) IsOdd() bool {
	return e.V.Bytes()[0]&0b1 == 1
}

func (e *PallasBaseFieldElement) IsEven() bool {
	return !e.IsOdd()
}

func (e *PallasBaseFieldElement) Increment() curves.BaseFieldElement {
	ee, ok := e.Add(NewPallasBaseFieldElement(1)).(*PallasBaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

func (e *PallasBaseFieldElement) Decrement() curves.BaseFieldElement {
	ee, ok := e.Sub(NewPallasBaseFieldElement(1)).(*PallasBaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

// === Ordering Methods.

func (e *PallasBaseFieldElement) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	rhse, ok := rhs.(*PallasBaseFieldElement)
	if !ok {
		return algebra.Incomparable
	}

	return algebra.Ordering(ct.SliceCmpLE(e.V.Limbs(), rhse.V.Limbs()))
}

func (e *PallasBaseFieldElement) IsBottom() bool {
	return e.IsZero()
}

func (e *PallasBaseFieldElement) IsTop() bool {
	return e.Add(e.BaseField().One()).IsZero()
}

func (e *PallasBaseFieldElement) Join(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Max(rhs.Unwrap())
}

func (e *PallasBaseFieldElement) Max(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (e *PallasBaseFieldElement) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Min(rhs.Unwrap())
}

func (e *PallasBaseFieldElement) Min(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*PallasBaseFieldElement) BaseField() curves.BaseField {
	return NewPallasBaseField()
}

// === Serialisation.

func (e *PallasBaseFieldElement) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(e.BaseField().Curve().Name(), e.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (e *PallasBaseFieldElement) UnmarshalBinary(input []byte) error {
	sc, err := curvesImpl.UnmarshalBinary(NewPallasBaseFieldElement(0).SetBytes, input)
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
	ss, ok := sc.(*PallasBaseFieldElement)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	e.V.Set(&ss.V)
	return nil
}

func (e *PallasBaseFieldElement) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(e.BaseField().Curve().Name(), e.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *PallasBaseFieldElement) UnmarshalJSON(input []byte) error {
	sc, err := curvesImpl.UnmarshalJson(e.BaseField().Name(), e.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*PallasBaseFieldElement)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	e.V.Set(&S.V)
	return nil
}

func (e *PallasBaseFieldElement) Uint64() uint64 {
	return e.Nat().Uint64()
}

func (*PallasBaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	valueReduced := new(saferith.Nat).Mod(value, pallasBaseFieldModulus)
	valueBytes := valueReduced.Bytes()
	slices.Reverse(valueBytes)

	result := new(PallasBaseFieldElement)
	ok := result.V.SetBytesWide(valueBytes)
	if ok != 1 {
		panic("this should never happen")
	}
	return result
}

func (e *PallasBaseFieldElement) Nat() *saferith.Nat {
	eBytes := e.V.Bytes()
	slices.Reverse(eBytes)
	return new(saferith.Nat).SetBytes(eBytes)
}

func (*PallasBaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != pastaImpl.FpBytes {
		return nil, errs.NewLength("input length %d > %d bytes", len(input), pastaImpl.FpBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result := new(PallasBaseFieldElement)
	ok := result.V.SetBytes(buffer)
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	return result, nil
}

func (*PallasBaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > pastaImpl.FpWideBytes {
		return nil, errs.NewLength("input length > %d bytes", pastaImpl.FpWideBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result := new(PallasBaseFieldElement)
	ok := result.V.SetBytesWide(buffer)
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	return result, nil
}

func (e *PallasBaseFieldElement) Bytes() []byte {
	v := e.V.Bytes()
	slices.Reverse(v)
	return v
}
func (e *PallasBaseFieldElement) HashCode() uint64 {
	return e.Uint64()
}
