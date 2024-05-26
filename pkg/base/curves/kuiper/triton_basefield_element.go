package kuiper

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	curvesImpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var (
	_ curves.BaseFieldElement    = (*TritonBaseFieldElement)(nil)
	_ encoding.BinaryMarshaler   = (*TritonBaseFieldElement)(nil)
	_ encoding.BinaryUnmarshaler = (*TritonBaseFieldElement)(nil)
	_ json.Unmarshaler           = (*TritonBaseFieldElement)(nil)
)

type TritonBaseFieldElement struct {
	V impl.Fp2

	_ ds.Incomparable
}

func NewTritonBaseFieldElement(value uint64) *TritonBaseFieldElement {
	z := new(TritonBaseFieldElement)
	z.V.A.SetUint64(value)
	z.V.B.SetZero()
	return z
}

func (*TritonBaseFieldElement) Structure() curves.BaseField {
	return NewTritonBaseField()
}

func (e *TritonBaseFieldElement) Unwrap() curves.BaseFieldElement {
	return e
}

func (*TritonBaseFieldElement) Order(operator algebra.BinaryOperator[curves.BaseFieldElement]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) ApplyOp(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsIdentity(under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Inverse(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsInverse(of algebra.GroupElement[curves.BaseField, curves.BaseFieldElement], under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) CoPrime(x curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) GCD(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) LCM(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Factorise() []curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) EuclideanDiv(x curves.BaseFieldElement) (quotient, reminder curves.BaseFieldElement) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Lattice() algebra.OrderTheoreticLattice[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Next() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Previous() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Chain() algebra.Chain[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) FromInt(v algebra.Int) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Not() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) ExclusiveDisjunctiveInverse() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Lsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Rsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) SetBytesLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) SetBytesWideLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*TritonBaseFieldElement) Conjugate() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (e *TritonBaseFieldElement) Equal(rhs curves.BaseFieldElement) bool {
	rhse, ok := rhs.(*TritonBaseFieldElement)
	return e.V.Equal(&rhse.V) == 1 && ok
}

func (e *TritonBaseFieldElement) Clone() curves.BaseFieldElement {
	return &TritonBaseFieldElement{
		V: e.V,
	}
}

// === Additive Groupoid Methods.

func (e *TritonBaseFieldElement) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*TritonBaseFieldElement)
	if !ok {
		panic("not a Triton Fp2 element")
	}
	z := new(TritonBaseFieldElement)
	z.V.Add(&e.V, &n.V)
	return z
}

func (e *TritonBaseFieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(TritonBaseFieldElement).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *TritonBaseFieldElement) Double() curves.BaseFieldElement {
	z := new(TritonBaseFieldElement)
	z.V.Double(&e.V)
	return z
}

func (e *TritonBaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *TritonBaseFieldElement) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*TritonBaseFieldElement)
	if !ok {
		panic("not a Triton Fp2 element")
	}
	z := new(TritonBaseFieldElement)
	z.V.Mul(&e.V, &n.V)
	return z
}

func (e *TritonBaseFieldElement) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *TritonBaseFieldElement) Square() curves.BaseFieldElement {
	z := new(TritonBaseFieldElement)
	z.V.Square(&e.V)
	return z
}

func (e *TritonBaseFieldElement) Cube() curves.BaseFieldElement {
	return e.Square().Mul(e)
}

// === Additive Monoid Methods.

func (e *TritonBaseFieldElement) IsAdditiveIdentity() bool {
	return e.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (e *TritonBaseFieldElement) IsMultiplicativeIdentity() bool {
	return e.V.IsOne() == 1
}

// === Additive Group Methods.

func (e *TritonBaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	z := new(TritonBaseFieldElement)
	z.V.Neg(&e.V)
	return z
}

func (e *TritonBaseFieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *TritonBaseFieldElement) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*TritonBaseFieldElement)
	if !ok {
		panic("not a Triton Fp2 element")
	}
	z := new(TritonBaseFieldElement)
	z.V.Sub(&e.V, &n.V)
	return z
}

func (e *TritonBaseFieldElement) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(TritonBaseFieldElement).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *TritonBaseFieldElement) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	value, wasInverted := new(impl.Fp2).Invert(&e.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("multiplicative inverse doesn't exist")
	}

	return &TritonBaseFieldElement{
		V: *value,
	}, nil
}

func (e *TritonBaseFieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *TritonBaseFieldElement) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	r, ok := rhs.(*TritonBaseFieldElement)
	if ok {
		v, wasInverted := new(impl.Fp2).Invert(&r.V)
		if wasInverted != 1 {
			return nil, errs.NewFailed("cannot invert rhs")
		}
		v.Mul(v, &e.V)
		return &TritonBaseFieldElement{V: *v}, nil
	} else {
		return nil, errs.NewFailed("rhs is not Triton Fp2 field element")
	}
}

func (e *TritonBaseFieldElement) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (e *TritonBaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	result, wasSquare := new(impl.Fp2).Sqrt(&e.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("element was not a square")
	}
	return &TritonBaseFieldElement{
		V: *result,
	}, nil
}

func (e *TritonBaseFieldElement) MulAdd(y algebra.RingElement[curves.BaseField, curves.BaseFieldElement], z algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Mul(y).Add(z)
}

// === Finite Field Methods.

func (e *TritonBaseFieldElement) SubFieldElement(index uint) (curves.BaseFieldElement, error) {
	switch index {
	case 0:
		return &PlutoBaseFieldElement{
			V: e.V.A,
		}, nil
	case 1:
		return &PlutoBaseFieldElement{
			V: e.V.B,
		}, nil
	default:
		panic("invalid index")
	}
}

func (e *TritonBaseFieldElement) Norm() curves.BaseFieldElement {
	r, _ := e.SubFieldElement(0)
	i, _ := e.SubFieldElement(1)
	return r.Square().Add(i.Square())
}

// === Zp Methods.

func (*TritonBaseFieldElement) Exp(rhs *saferith.Nat) curves.BaseFieldElement {
	return nil
}

func (e *TritonBaseFieldElement) Neg() curves.BaseFieldElement {
	return e.AdditiveInverse()
}

func (e *TritonBaseFieldElement) IsZero() bool {
	return e.IsAdditiveIdentity()
}

func (e *TritonBaseFieldElement) IsOne() bool {
	return e.IsMultiplicativeIdentity()
}

func (e *TritonBaseFieldElement) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *TritonBaseFieldElement) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *TritonBaseFieldElement) Increment() curves.BaseFieldElement {
	ee, ok := e.Add(NewTritonBaseFieldElement(1)).(*TritonBaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

func (e *TritonBaseFieldElement) Decrement() curves.BaseFieldElement {
	ee, ok := e.Sub(NewTritonBaseFieldElement(1)).(*TritonBaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

// === Ordering Methods.

func (e *TritonBaseFieldElement) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	other, ok := rhs.(*TritonBaseFieldElement)
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

func (e *TritonBaseFieldElement) IsBottom() bool {
	return e.IsZero()
}

func (e *TritonBaseFieldElement) IsTop() bool {
	return e.Add(e.BaseField().One()).IsZero()
}

func (e *TritonBaseFieldElement) Join(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Max(rhs.Unwrap())
}

func (e *TritonBaseFieldElement) Max(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (e *TritonBaseFieldElement) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Min(rhs.Unwrap())
}

func (e *TritonBaseFieldElement) Min(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*TritonBaseFieldElement) BaseField() curves.BaseField {
	return NewTritonBaseField()
}

// === Serialisation.

func (e *TritonBaseFieldElement) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(e.BaseField().Curve().Name(), e.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (e *TritonBaseFieldElement) UnmarshalBinary(input []byte) error {
	sc, err := curvesImpl.UnmarshalBinary(NewTritonBaseFieldElement(0).SetBytes, input)
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
	ss, ok := sc.(*TritonBaseFieldElement)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	e.V = ss.V
	return nil
}

func (e *TritonBaseFieldElement) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(e.BaseField().Curve().Name(), e.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *TritonBaseFieldElement) UnmarshalJSON(input []byte) error {
	sc, err := curvesImpl.UnmarshalJson(e.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	name, _, err := curvesImpl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != e.BaseField().Name() {
		return errs.NewType("name %s is not supported", name)
	}
	S, ok := sc.(*TritonBaseFieldElement)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	e.V = S.V
	return nil
}

func (e *TritonBaseFieldElement) Uint64() uint64 {
	return e.Nat().Uint64()
}

func (e *TritonBaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	if value == nil {
		return nil
	}
	a := new(saferith.Nat).Mod(value, e.BaseField().Order())
	b := new(saferith.Nat).Div(
		new(saferith.Nat).Sub(value, a, -1),
		e.BaseField().Order(),
		-1,
	)
	aa := NewPlutoBaseField().Element().SetNat(a)
	bb := NewPlutoBaseField().Element().SetNat(b)
	result, err := e.SetComponents(aa, bb)
	if err != nil {
		panic(errs.WrapSerialisation(err, "failed to set nat"))
	}
	return result
}

func (e *TritonBaseFieldElement) Nat() *saferith.Nat {
	aNat := e.V.A.Nat()
	bNat := e.V.B.Nat()
	nat := new(saferith.Nat).Add(
		aNat,
		new(saferith.Nat).Mul(bNat, e.BaseField().Order().Nat(), impl.FieldBytesFp2),
		impl.FieldBytesFp2,
	)
	return nat
}

func (e *TritonBaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != impl.FieldBytesFp2 {
		return nil, errs.NewLength("input length (%d != %d bytes)", len(input), impl.FieldBytesFp2)
	}
	a, err := NewPlutoBaseField().Element().SetBytes(input[:impl.FieldBytes])
	if err != nil {
		return nil, errs.WrapHashing(err, "could not set bytes of Triton Fp2 field element A")
	}
	b, err := NewPlutoBaseField().Element().SetBytes(input[impl.FieldBytes:impl.FieldBytesFp2])
	if err != nil {
		return nil, errs.WrapHashing(err, "could not set bytes of Triton Fp2 field element B")
	}
	result, err := e.SetComponents(a, b)
	return result, err
}

func (e *TritonBaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > impl.WideFieldBytesFp2 {
		return nil, errs.NewLength("input length %d > %d bytes", len(input), impl.WideFieldBytesFp2)
	}

	var bufferA, bufferB [impl.WideFieldBytes]byte                         // Split in halves and pad them with zeros
	copy(bufferA[impl.WideFieldBytes-len(input)/2:], input[:len(input)/2]) // First half is A (real)
	copy(bufferB[impl.WideFieldBytes-len(input)/2:], input[len(input)/2:]) // Second half is B (imaginary)

	a, err := NewPlutoBaseField().Element().SetBytesWide(bufferA[:])
	if err != nil {
		return nil, errs.WrapHashing(err, "could not set bytes of Triton Fp2 field element A")
	}
	b, err := NewPlutoBaseField().Element().SetBytesWide(bufferB[:])
	if err != nil {
		return nil, errs.WrapHashing(err, "could not set bytes of Triton Fp2 field element B")
	}
	result, err := e.SetComponents(a, b)
	return result, err
}

func (*TritonBaseFieldElement) SetComponents(a, b curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	aa, ok := a.(*PlutoBaseFieldElement)
	if !ok {
		return nil, errs.NewType("a is not the right type")
	}
	bb, ok := b.(*PlutoBaseFieldElement)
	if !ok {
		return nil, errs.NewType("b is not the right type")
	}
	if aa == nil || bb == nil {
		return nil, errs.NewIsNil("arguments can't be nil or have nil components")
	}
	return &TritonBaseFieldElement{
		V: impl.Fp2{
			A: aa.V,
			B: bb.V,
		},
	}, nil
}

func (e *TritonBaseFieldElement) Bytes() []byte {
	var out [impl.FieldBytesFp2]byte
	bytes := e.V.A.Bytes()
	copy(out[:impl.FieldBytes], bitstring.ReverseBytes(bytes[:]))
	bytes = e.V.B.Bytes()
	copy(out[impl.FieldBytes:impl.FieldBytesFp2], bitstring.ReverseBytes(bytes[:]))
	return out[:]
}
func (e *TritonBaseFieldElement) HashCode() uint64 {
	return e.Uint64()
}
