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

var _ curves.BaseFieldElement = (*VestaBaseFieldElement)(nil)
var _ encoding.BinaryMarshaler = (*VestaBaseFieldElement)(nil)
var _ encoding.BinaryUnmarshaler = (*VestaBaseFieldElement)(nil)
var _ json.Unmarshaler = (*VestaBaseFieldElement)(nil)

type VestaBaseFieldElement struct {
	V pastaImpl.Fq

	_ ds.Incomparable
}

func NewVestaBaseFieldElement(value uint64) *VestaBaseFieldElement {
	t := new(VestaBaseFieldElement)
	t.V.SetUint64(value)
	return t
}

func (*VestaBaseFieldElement) Structure() curves.BaseField {
	return NewVestaBaseField()
}

func (e *VestaBaseFieldElement) Unwrap() curves.BaseFieldElement {
	return e
}

func (*VestaBaseFieldElement) Order(operator algebra.BinaryOperator[curves.BaseFieldElement]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) ApplyOp(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsIdentity(under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Inverse(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsInverse(of algebra.GroupElement[curves.BaseField, curves.BaseFieldElement], under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) CoPrime(x curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) GCD(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) LCM(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Factorise() []curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) EuclideanDiv(x curves.BaseFieldElement) (quotient, reminder curves.BaseFieldElement) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Lattice() algebra.OrderTheoreticLattice[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Next() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Previous() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Chain() algebra.Chain[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) FromInt(v algebra.Int) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Not() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) ExclusiveDisjunctiveInverse() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Lsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Rsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) SetBytesLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) SetBytesWideLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*VestaBaseFieldElement) Conjugate() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (e *VestaBaseFieldElement) Equal(rhs curves.BaseFieldElement) bool {
	rhse, ok := rhs.(*VestaBaseFieldElement)
	if !ok {
		return false
	}
	return e.V.Equals(&rhse.V) == 1
}

func (e *VestaBaseFieldElement) Clone() curves.BaseFieldElement {
	result := new(VestaBaseFieldElement)
	result.V.Set(&e.V)
	return result
}

// === Additive Groupoid Methods.

func (e *VestaBaseFieldElement) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*VestaBaseFieldElement)
	if !ok {
		panic("not a vesta Fp element")
	}

	result := new(VestaBaseFieldElement)
	result.V.Add(&e.V, &n.V)
	return result
}

func (e *VestaBaseFieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(VestaBaseFieldElement).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *VestaBaseFieldElement) Double() curves.BaseFieldElement {
	return e.Add(e)
}

func (e *VestaBaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *VestaBaseFieldElement) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*VestaBaseFieldElement)
	if !ok {
		panic("not a vesta Fp element")
	}

	result := new(VestaBaseFieldElement)
	result.V.Mul(&e.V, &n.V)
	return result
}

func (e *VestaBaseFieldElement) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *VestaBaseFieldElement) Square() curves.BaseFieldElement {
	result := new(VestaBaseFieldElement)
	result.V.Square(&e.V)
	return result
}

func (e *VestaBaseFieldElement) Cube() curves.BaseFieldElement {
	return e.Square().Mul(e)
}

// === Additive Monoid Methods.

func (e *VestaBaseFieldElement) IsAdditiveIdentity() bool {
	return e.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (e *VestaBaseFieldElement) IsMultiplicativeIdentity() bool {
	return e.V.IsOne() == 1
}

// === Additive Group Methods.

func (e *VestaBaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	result := new(VestaBaseFieldElement)
	result.V.Neg(&e.V)
	return result
}

func (e *VestaBaseFieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *VestaBaseFieldElement) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*VestaBaseFieldElement)
	if !ok {
		panic("not a vesta Fp element")
	}

	result := new(VestaBaseFieldElement)
	result.V.Sub(&e.V, &n.V)
	return result
}

func (e *VestaBaseFieldElement) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(VestaBaseFieldElement).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *VestaBaseFieldElement) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	result := new(VestaBaseFieldElement)
	ok := result.V.Inv(&e.V)
	if ok != 1 {
		return nil, errs.NewFailed("division by zero")
	}

	return result, nil
}

func (e *VestaBaseFieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *VestaBaseFieldElement) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	r, ok := rhs.(*VestaBaseFieldElement)
	if !ok {
		return nil, errs.NewFailed("rhs is not vesta base field element")
	}

	result := new(VestaBaseFieldElement)
	wasInverted := result.V.Div(&e.V, &r.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("cannot invert rhs")
	}
	return result, nil
}

func (e *VestaBaseFieldElement) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (e *VestaBaseFieldElement) MulAdd(y algebra.RingElement[curves.BaseField, curves.BaseFieldElement], z algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Mul(y).Add(z)
}

func (e *VestaBaseFieldElement) IsQuadraticResidue() bool {
	_, err := e.Sqrt()
	return err != nil
}

func (e *VestaBaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	result := new(VestaBaseFieldElement)
	wasSquare := result.V.Sqrt(&e.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("element did not have a sqrt")
	}
	return result, nil
}

// === Finite Field Methods.

func (e *VestaBaseFieldElement) SubFieldElement(i uint) (curves.BaseFieldElement, error) {
	return e, nil
}

func (e *VestaBaseFieldElement) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *VestaBaseFieldElement) Exp(exponent *saferith.Nat) curves.BaseFieldElement {
	eBytes := exponent.Bytes()
	slices.Reverse(eBytes)
	result := new(VestaBaseFieldElement)
	fieldsImpl.Pow(&result.V, &e.V, eBytes)
	return result
}

func (e *VestaBaseFieldElement) Neg() curves.BaseFieldElement {
	return e.AdditiveInverse()
}

func (e *VestaBaseFieldElement) IsZero() bool {
	return e.V.IsZero() == 1
}

func (e *VestaBaseFieldElement) IsOne() bool {
	return e.V.IsOne() == 1
}

func (e *VestaBaseFieldElement) IsOdd() bool {
	return e.V.Bytes()[0]&0b1 == 1
}

func (e *VestaBaseFieldElement) IsEven() bool {
	return !e.IsOdd()
}

func (e *VestaBaseFieldElement) Increment() curves.BaseFieldElement {
	ee, ok := e.Add(NewVestaBaseFieldElement(1)).(*VestaBaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

func (e *VestaBaseFieldElement) Decrement() curves.BaseFieldElement {
	ee, ok := e.Sub(NewVestaBaseFieldElement(1)).(*VestaBaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

// === Ordering Methods.

func (e *VestaBaseFieldElement) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	rhse, ok := rhs.(*VestaBaseFieldElement)
	if !ok {
		return algebra.Incomparable
	}

	return algebra.Ordering(ct.SliceCmpLE(e.V.Limbs(), rhse.V.Limbs()))
}

func (e *VestaBaseFieldElement) IsBottom() bool {
	return e.IsZero()
}

func (e *VestaBaseFieldElement) IsTop() bool {
	return e.Add(e.BaseField().One()).IsZero()
}

func (e *VestaBaseFieldElement) Join(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Max(rhs.Unwrap())
}

func (e *VestaBaseFieldElement) Max(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (e *VestaBaseFieldElement) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Min(rhs.Unwrap())
}

func (e *VestaBaseFieldElement) Min(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*VestaBaseFieldElement) BaseField() curves.BaseField {
	return NewVestaBaseField()
}

// === Serialisation.

func (e *VestaBaseFieldElement) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(e.BaseField().Curve().Name(), e.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (e *VestaBaseFieldElement) UnmarshalBinary(input []byte) error {
	sc, err := curvesImpl.UnmarshalBinary(NewVestaBaseFieldElement(0).SetBytes, input)
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
	ss, ok := sc.(*VestaBaseFieldElement)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	e.V.Set(&ss.V)
	return nil
}

func (e *VestaBaseFieldElement) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(e.BaseField().Curve().Name(), e.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *VestaBaseFieldElement) UnmarshalJSON(input []byte) error {
	sc, err := curvesImpl.UnmarshalJson(e.BaseField().Name(), e.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*VestaBaseFieldElement)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	e.V.Set(&S.V)
	return nil
}

func (e *VestaBaseFieldElement) Uint64() uint64 {
	return e.Nat().Uint64()
}

func (*VestaBaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	valueReduced := new(saferith.Nat).Mod(value, vestaBaseFieldModulus)
	valueBytes := valueReduced.Bytes()
	slices.Reverse(valueBytes)

	result := new(VestaBaseFieldElement)
	ok := result.V.SetBytesWide(valueBytes)
	if ok != 1 {
		panic("this should never happen")
	}
	return result
}

func (e *VestaBaseFieldElement) Nat() *saferith.Nat {
	eBytes := e.V.Bytes()
	slices.Reverse(eBytes)
	return new(saferith.Nat).SetBytes(eBytes)
}

func (*VestaBaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != pastaImpl.FqBytes {
		return nil, errs.NewLength("input length %d > %d bytes", len(input), pastaImpl.FqBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result := new(VestaBaseFieldElement)
	ok := result.V.SetBytes(buffer)
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	return result, nil
}

func (*VestaBaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > pastaImpl.FqWideBytes {
		return nil, errs.NewLength("input length > %d bytes", pastaImpl.FqWideBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result := new(VestaBaseFieldElement)
	ok := result.V.SetBytesWide(buffer)
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	return result, nil
}

func (e *VestaBaseFieldElement) Bytes() []byte {
	v := e.V.Bytes()
	slices.Reverse(v)
	return v
}
func (e *VestaBaseFieldElement) HashCode() uint64 {
	return e.Uint64()
}
