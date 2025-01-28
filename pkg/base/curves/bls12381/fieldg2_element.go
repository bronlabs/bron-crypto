package bls12381

import (
	"encoding"
	"encoding/json"
	"slices"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/krypton-primitives/pkg/base/algebra"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves"
	bls12381Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/bls12381/impl"
	curvesImpl "github.com/bronlabs/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/bronlabs/krypton-primitives/pkg/base/datastructures"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

var _ curves.BaseFieldElement = (*BaseFieldElementG2)(nil)
var _ encoding.BinaryMarshaler = (*BaseFieldElementG1)(nil)
var _ encoding.BinaryUnmarshaler = (*BaseFieldElementG1)(nil)
var _ json.Unmarshaler = (*BaseFieldElementG2)(nil)

type BaseFieldElementG2 struct {
	V bls12381Impl.Fp2

	_ ds.Incomparable
}

func NewBaseFieldElementG2(value uint64) *BaseFieldElementG2 {
	v := new(BaseFieldElementG2)
	v.V.U0.SetUint64(value)
	v.V.U1.SetZero()
	return v
}

func (*BaseFieldElementG2) Structure() curves.BaseField {
	return NewBaseFieldG2()
}

func (e *BaseFieldElementG2) Unwrap() curves.BaseFieldElement {
	return e
}

func (*BaseFieldElementG2) Order(operator algebra.BinaryOperator[curves.BaseFieldElement]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) ApplyOp(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsIdentity(under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Inverse(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsInverse(of algebra.GroupElement[curves.BaseField, curves.BaseFieldElement], under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) CoPrime(x curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) GCD(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) LCM(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Factorise() []curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) EuclideanDiv(x curves.BaseFieldElement) (quotient, reminder curves.BaseFieldElement) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Lattice() algebra.OrderTheoreticLattice[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Next() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Previous() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Chain() algebra.Chain[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) FromInt(v algebra.Int) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Not() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) ExclusiveDisjunctiveInverse() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Lsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Rsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) SetBytesLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) SetBytesWideLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG2) Conjugate() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (e *BaseFieldElementG2) Equal(rhs curves.BaseFieldElement) bool {
	rhse, ok := rhs.(*BaseFieldElementG2)
	if !ok {
		return false
	}
	return e.V.Equals(&rhse.V) == 1
}

func (e *BaseFieldElementG2) Clone() curves.BaseFieldElement {
	clone := new(BaseFieldElementG2)
	clone.V.Set(&e.V)
	return clone
}

// === Additive Groupoid Methods.

func (e *BaseFieldElementG2) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG2)
	if !ok {
		panic("not a bls12381 G2 Fp2 element")
	}

	result := new(BaseFieldElementG2)
	result.V.Add(&e.V, &n.V)
	return result
}

func (e *BaseFieldElementG2) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElementG2).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *BaseFieldElementG2) Double() curves.BaseFieldElement {
	return e.Add(e)
}

func (e *BaseFieldElementG2) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *BaseFieldElementG2) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG2)
	if !ok {
		panic("not a bls12381 G2 Fp2 element")
	}

	result := new(BaseFieldElementG2)
	result.V.Mul(&e.V, &n.V)
	return result
}

func (e *BaseFieldElementG2) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *BaseFieldElementG2) Square() curves.BaseFieldElement {
	result := new(BaseFieldElementG2)
	result.V.Square(&e.V)
	return result
}

func (e *BaseFieldElementG2) Cube() curves.BaseFieldElement {
	return e.Square().Mul(e)
}

// === Additive Monoid Methods.

func (e *BaseFieldElementG2) IsAdditiveIdentity() bool {
	return e.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (e *BaseFieldElementG2) IsMultiplicativeIdentity() bool {
	return e.V.IsOne() == 1
}

// === Additive Group Methods.

func (e *BaseFieldElementG2) AdditiveInverse() curves.BaseFieldElement {
	result := new(BaseFieldElementG2)
	result.V.Neg(&e.V)
	return result
}

func (e *BaseFieldElementG2) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *BaseFieldElementG2) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG2)
	if !ok {
		panic("not a bls12381 G2 Fp2 element")
	}

	result := new(BaseFieldElementG2)
	result.V.Sub(&e.V, &n.V)
	return result
}

func (e *BaseFieldElementG2) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElementG2).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *BaseFieldElementG2) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	value := new(BaseFieldElementG2)
	wasInverted := value.V.Inv(&e.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("multiplicative inverse doesn't exist")
	}

	return value, nil
}

func (e *BaseFieldElementG2) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *BaseFieldElementG2) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	rhse, ok := rhs.(*BaseFieldElementG2)
	if !ok {
		return nil, errs.NewFailed("rhs is not bls12381 G2 Fp2 field element")
	}

	v := new(BaseFieldElementG2)
	wasInverted := v.V.Div(&e.V, &rhse.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("cannot invert rhs")
	}

	return v, nil
}

func (e *BaseFieldElementG2) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (e *BaseFieldElementG2) IsQuadraticResidue() bool {
	_, err := e.Sqrt()
	return err != nil
}

func (e *BaseFieldElementG2) Sqrt() (curves.BaseFieldElement, error) {
	result := new(BaseFieldElementG2)
	wasSquare := result.V.Sqrt(&e.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("element was not a square")
	}
	return result, nil
}

func (e *BaseFieldElementG2) MulAdd(y algebra.RingElement[curves.BaseField, curves.BaseFieldElement], z algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Mul(y).Add(z)
}

// === Finite Field Methods.

func (e *BaseFieldElementG2) SubFieldElement(index uint) (curves.BaseFieldElement, error) {
	switch index {
	case 0:
		return &BaseFieldElementG1{
			V: e.V.U0,
		}, nil
	case 1:
		return &BaseFieldElementG1{
			V: e.V.U1,
		}, nil
	default:
		panic("invalid index")
	}
}

func (e *BaseFieldElementG2) Norm() curves.BaseFieldElement {
	r, _ := e.SubFieldElement(0)
	i, _ := e.SubFieldElement(1)
	return r.Square().Add(i.Square())
}

// === Zp Methods.

func (*BaseFieldElementG2) Exp(rhs *saferith.Nat) curves.BaseFieldElement {
	return nil
}

func (e *BaseFieldElementG2) Neg() curves.BaseFieldElement {
	return e.AdditiveInverse()
}

func (e *BaseFieldElementG2) IsZero() bool {
	return e.IsAdditiveIdentity()
}

func (e *BaseFieldElementG2) IsOne() bool {
	return e.IsMultiplicativeIdentity()
}

func (e *BaseFieldElementG2) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *BaseFieldElementG2) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *BaseFieldElementG2) Increment() curves.BaseFieldElement {
	ee, ok := e.Add(NewBaseFieldElementG2(1)).(*BaseFieldElementG2)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

func (e *BaseFieldElementG2) Decrement() curves.BaseFieldElement {
	ee, ok := e.Sub(NewBaseFieldElementG2(1)).(*BaseFieldElementG2)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

// === Ordering Methods.

func (e *BaseFieldElementG2) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	other, ok := rhs.(*BaseFieldElementG2)
	if !ok || rhs == nil {
		return algebra.Incomparable
	}
	// TODO: do we need to check norm if we compare subelements?
	normCheck := e.Norm().Cmp(other.Norm())
	if normCheck != algebra.Equal {
		return normCheck
	}

	lhsReal, err := e.SubFieldElement(0)
	if err != nil {
		panic("invalid subfield")
	}
	rhsReal, err := rhs.Unwrap().SubFieldElement(0)
	if err != nil {
		panic("invalid subfield")
	}
	realCheck := lhsReal.Cmp(rhsReal)
	if realCheck != algebra.Equal {
		return realCheck
	}

	lhsImag, err := e.SubFieldElement(1)
	if err != nil {
		panic("invalid subfield")
	}
	rhsImag, err := rhs.Unwrap().SubFieldElement(1)
	if err != nil {
		panic("invalid subfield")
	}

	imaginaryCheck := lhsImag.Cmp(rhsImag)
	if imaginaryCheck != algebra.Equal {
		return imaginaryCheck
	}

	return algebra.Equal
}

func (e *BaseFieldElementG2) IsBottom() bool {
	return e.IsZero()
}

func (e *BaseFieldElementG2) IsTop() bool {
	return e.Add(e.BaseField().One()).IsZero()
}

func (e *BaseFieldElementG2) Join(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Max(rhs.Unwrap())
}

func (e *BaseFieldElementG2) Max(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (e *BaseFieldElementG2) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Min(rhs.Unwrap())
}

func (e *BaseFieldElementG2) Min(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*BaseFieldElementG2) BaseField() curves.BaseField {
	return NewBaseFieldG2()
}

// === Serialisation.

func (e *BaseFieldElementG2) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(e.BaseField().Curve().Name(), e.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElementG2) UnmarshalBinary(input []byte) error {
	sc, err := curvesImpl.UnmarshalBinary(NewBaseFieldElementG2(0).SetBytes, input)
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
	ss, ok := sc.(*BaseFieldElementG2)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	e.V.Set(&ss.V)
	return nil
}

func (e *BaseFieldElementG2) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(e.BaseField().Curve().Name(), e.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElementG2) UnmarshalJSON(input []byte) error {
	sc, err := curvesImpl.UnmarshalJson(e.BaseField().Name(), e.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*BaseFieldElementG2)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	e.V.Set(&S.V)
	return nil
}

func (*BaseFieldElementG2) Uint64() uint64 {
	panic("not supported")
}

func (*BaseFieldElementG2) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	natReduced := new(saferith.Nat).Mod(value, g1BaseFieldOrder)
	natBytes := natReduced.Bytes()
	slices.Reverse(natBytes)

	result := new(BaseFieldElementG2)
	result.V.U1.SetZero()
	ok := result.V.U0.SetBytesWide(natBytes)
	if ok != 1 {
		panic("this should never happen")
	}

	return result
}

func (*BaseFieldElementG2) Nat() *saferith.Nat {
	panic("not supported")
}

func (*BaseFieldElementG2) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != 2*bls12381Impl.FpBytes {
		return nil, errs.NewLength("input length (%d != %d bytes)", len(input), bls12381Impl.FpBytes)
	}
	reData := bitstring.ReverseBytes(input[:bls12381Impl.FpBytes])
	imData := bitstring.ReverseBytes(input[bls12381Impl.FpBytes:])
	result := new(BaseFieldElementG2)
	ok0 := result.V.U0.SetBytes(reData)
	ok1 := result.V.U1.SetBytes(imData)
	if ok0 != 1 || ok1 != 0 {
		errs.NewHashing("could not set bytes of bls12381 G2 Fp2 field element B")
	}

	return result, nil
}

func (e *BaseFieldElementG2) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > 2*bls12381Impl.FpWideBytes {
		return nil, errs.NewLength("input length %d > %d bytes", len(input), 2*bls12381Impl.FpWideBytes)
	}

	// this is nonsense
	var bufferA, bufferB [bls12381Impl.FpWideBytes]byte                         // Split in halves and pad them with zeros
	copy(bufferA[bls12381Impl.FpWideBytes-len(input)/2:], input[:len(input)/2]) // First half is A (real)
	copy(bufferB[bls12381Impl.FpWideBytes-len(input)/2:], input[len(input)/2:]) // Second half is B (imaginary)

	a, err := NewG1().BaseFieldElement().SetBytesWide(bufferA[:])
	if err != nil {
		return nil, errs.WrapHashing(err, "could not set bytes of bls12381 G2 Fp2 field element A")
	}
	b, err := NewG1().BaseFieldElement().SetBytesWide(bufferB[:])
	if err != nil {
		return nil, errs.WrapHashing(err, "could not set bytes of bls12381 G2 Fp2 field element B")
	}
	result, err := e.SetComponents(a, b)
	return result, err
}

func (*BaseFieldElementG2) SetComponents(a, b curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	aa, ok := a.(*BaseFieldElementG1)
	if !ok {
		return nil, errs.NewType("a is not the right type")
	}
	bb, ok := b.(*BaseFieldElementG1)
	if !ok {
		return nil, errs.NewType("b is not the right type")
	}
	if aa == nil || bb == nil {
		return nil, errs.NewIsNil("arguments can't be nil or have nil components")
	}

	result := new(BaseFieldElementG2)
	result.V.U0.Set(&aa.V)
	result.V.U1.Set(&bb.V)
	return result, nil
}

func (e *BaseFieldElementG2) Bytes() []byte {
	reData := e.V.U0.Bytes()
	slices.Reverse(reData)
	imData := e.V.U1.Bytes()
	slices.Reverse(imData)
	return slices.Concat(reData, imData)
}
func (e *BaseFieldElementG2) HashCode() uint64 {
	return e.Uint64()
}
