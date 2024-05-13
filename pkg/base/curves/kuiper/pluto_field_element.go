package kuiper

import (
	"encoding"
	"encoding/json"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl/arithmetic/limb7"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/kuiper/impl/fp"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	curvesImpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var (
	_ curves.BaseFieldElement    = (*PlutoBaseFieldElement)(nil)
	_ encoding.BinaryMarshaler   = (*PlutoBaseFieldElement)(nil)
	_ encoding.BinaryUnmarshaler = (*PlutoBaseFieldElement)(nil)
	_ json.Unmarshaler           = (*PlutoBaseFieldElement)(nil)
)

type PlutoBaseFieldElement struct {
	V *limb7.FieldValue

	_ ds.Incomparable
}

func NewPlutoBaseFieldElement(value uint64) *PlutoBaseFieldElement {
	return &PlutoBaseFieldElement{
		V: fp.NewFp(),
	}
}

func (*PlutoBaseFieldElement) Structure() curves.BaseField {
	return NewPlutoBaseField()
}

func (e *PlutoBaseFieldElement) Unwrap() curves.BaseFieldElement {
	return e
}

func (*PlutoBaseFieldElement) Order(operator algebra.BinaryOperator[curves.BaseFieldElement]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) ApplyOp(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsIdentity(under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Inverse(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsInverse(of algebra.GroupElement[curves.BaseField, curves.BaseFieldElement], under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) CoPrime(x curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) GCD(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) LCM(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Factorise() []curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) EuclideanDiv(x curves.BaseFieldElement) (quotient, reminder curves.BaseFieldElement) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Lattice() algebra.OrderTheoreticLattice[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Next() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Previous() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Chain() algebra.Chain[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) FromInt(v algebra.Int) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Not() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) ExclusiveDisjunctiveInverse() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Lsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Rsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) SetBytesLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) SetBytesWideLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*PlutoBaseFieldElement) Conjugate() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (e *PlutoBaseFieldElement) Equal(rhs curves.BaseFieldElement) bool {
	return e.Cmp(rhs) == 0
}

func (e *PlutoBaseFieldElement) Clone() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: fp.NewFp().Set(e.V),
	}
}

// === Additive Groupoid Methods.

func (e *PlutoBaseFieldElement) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*PlutoBaseFieldElement)
	if !ok {
		panic("not a Pluto Fp element")
	}
	return &PlutoBaseFieldElement{
		V: fp.NewFp().Add(e.V, n.V),
	}
}

func (e *PlutoBaseFieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(PlutoBaseFieldElement).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *PlutoBaseFieldElement) Double() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: fp.NewFp().Double(e.V),
	}
}

func (e *PlutoBaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *PlutoBaseFieldElement) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*PlutoBaseFieldElement)
	if !ok {
		panic("not a Pluto Fp element")
	}
	return &PlutoBaseFieldElement{
		V: fp.NewFp().Mul(e.V, n.V),
	}
}

func (e *PlutoBaseFieldElement) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *PlutoBaseFieldElement) Square() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: fp.NewFp().Square(e.V),
	}
}

func (e *PlutoBaseFieldElement) Cube() curves.BaseFieldElement {
	return e.Square().Mul(e)
}

// === Additive Monoid Methods.

func (e *PlutoBaseFieldElement) IsAdditiveIdentity() bool {
	return e.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (e *PlutoBaseFieldElement) IsMultiplicativeIdentity() bool {
	return e.V.IsOne() == 1
}

// == Additive Group Methods.

func (e *PlutoBaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	return &PlutoBaseFieldElement{
		V: fp.NewFp().Neg(e.V),
	}
}

func (e *PlutoBaseFieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *PlutoBaseFieldElement) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*PlutoBaseFieldElement)
	if !ok {
		panic("not a Pluto G1 Fp element")
	}
	return &PlutoBaseFieldElement{
		V: fp.NewFp().Sub(e.V, n.V),
	}
}

func (e *PlutoBaseFieldElement) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(PlutoBaseFieldElement).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *PlutoBaseFieldElement) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	value, wasInverted := fp.NewFp().Invert(e.V)
	if !wasInverted {
		return nil, errs.NewFailed("multiplicative inverse doesn't exist")
	}

	return &PlutoBaseFieldElement{
		V: value,
	}, nil
}

func (e *PlutoBaseFieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *PlutoBaseFieldElement) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	r, ok := rhs.(*PlutoBaseFieldElement)
	if ok {
		v, wasInverted := fp.NewFp().Invert(r.V)
		if !wasInverted {
			return nil, errs.NewFailed("cannot invert rhs")
		}
		v.Mul(v, e.V)
		return &PlutoBaseFieldElement{V: v}, nil
	} else {
		return nil, errs.NewFailed("rhs is not Pluto base field element")
	}
}

func (e *PlutoBaseFieldElement) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (e *PlutoBaseFieldElement) MulAdd(y algebra.RingElement[curves.BaseField, curves.BaseFieldElement], z algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Mul(y).Add(z)
}

func (e *PlutoBaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	result, wasSquare := fp.NewFp().Sqrt(e.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("element was not a square")
	}
	return &PlutoBaseFieldElement{
		V: result,
	}, nil
}

// === Finite Field Methods.

func (e *PlutoBaseFieldElement) SubFieldElement(i uint) (curves.BaseFieldElement, error) {
	return e, nil
}

func (e *PlutoBaseFieldElement) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *PlutoBaseFieldElement) Exp(rhs *saferith.Nat) curves.BaseFieldElement {
	n, ok := e.Structure().Element().SetNat(rhs).(*PlutoBaseFieldElement)
	if !ok {
		panic("not a Pluto G1 base field element")
	}
	return &PlutoBaseFieldElement{
		V: e.V.Exp(e.V, n.V),
	}
}

func (e *PlutoBaseFieldElement) Neg() curves.BaseFieldElement {
	return e.AdditiveInverse()
}

func (e *PlutoBaseFieldElement) IsZero() bool {
	return e.IsAdditiveIdentity()
}

func (e *PlutoBaseFieldElement) IsOne() bool {
	return e.IsMultiplicativeIdentity()
}

func (e *PlutoBaseFieldElement) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *PlutoBaseFieldElement) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *PlutoBaseFieldElement) Increment() curves.BaseFieldElement {
	ee, ok := e.Add(NewPlutoBaseFieldElement(1)).(*PlutoBaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

func (e *PlutoBaseFieldElement) Decrement() curves.BaseFieldElement {
	ee, ok := e.Sub(NewPlutoBaseFieldElement(1)).(*PlutoBaseFieldElement)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

// === Ordering Methods.

func (e *PlutoBaseFieldElement) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	rhse, ok := rhs.(*PlutoBaseFieldElement)
	if !ok {
		return algebra.Incomparable
	}
	return algebra.Ordering(e.V.Cmp(rhse.V))
}

func (e *PlutoBaseFieldElement) IsBottom() bool {
	return e.IsZero()
}

func (e *PlutoBaseFieldElement) IsTop() bool {
	return e.Add(e.BaseField().One()).IsZero()
}

func (e *PlutoBaseFieldElement) Join(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Max(rhs.Unwrap())
}

func (e *PlutoBaseFieldElement) Max(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (e *PlutoBaseFieldElement) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Min(rhs.Unwrap())
}

func (e *PlutoBaseFieldElement) Min(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*PlutoBaseFieldElement) BaseField() curves.BaseField {
	return NewPlutoBaseField()
}

// === Serialisation.

func (e *PlutoBaseFieldElement) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(e.BaseField().Curve().Name(), e.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (e *PlutoBaseFieldElement) UnmarshalBinary(input []byte) error {
	sc, err := curvesImpl.UnmarshalBinary(NewPlutoBaseFieldElement(0).SetBytes, input)
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
	ss, ok := sc.(*PlutoBaseFieldElement)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	e.V = ss.V
	return nil
}

func (e *PlutoBaseFieldElement) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(e.BaseField().Curve().Name(), e.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *PlutoBaseFieldElement) UnmarshalJSON(input []byte) error {
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
	S, ok := sc.(*PlutoBaseFieldElement)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	e.V = S.V
	return nil
}

func (e *PlutoBaseFieldElement) Uint64() uint64 {
	return e.Nat().Uint64()
}

func (*PlutoBaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	if value == nil {
		return nil
	}
	return &PlutoBaseFieldElement{
		V: fp.NewFp().SetNat(value),
	}
}

func (e *PlutoBaseFieldElement) Nat() *saferith.Nat {
	return e.V.Nat()
}

func (*PlutoBaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != limb7.FieldBytes {
		return nil, errs.NewLength("input length (%d != %d bytes)", len(input), limb7.FieldBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result, err := fp.NewFp().SetBytes((*[limb7.FieldBytes]byte)(buffer))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set byte")
	}
	return &PlutoBaseFieldElement{
		V: result,
	}, nil
}

func (*PlutoBaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > limb7.WideFieldBytes {
		return nil, errs.NewLength("input length > %d bytes", limb7.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), limb7.WideFieldBytes-len(input))
	result := fp.NewFp().SetBytesWide((*[limb7.WideFieldBytes]byte)(buffer))
	return &PlutoBaseFieldElement{
		V: result,
	}, nil
}

func (e *PlutoBaseFieldElement) Bytes() []byte {
	v := e.V.Bytes()
	return bitstring.ReverseBytes(v[:])
}
func (e *PlutoBaseFieldElement) HashCode() uint64 {
	return e.Uint64()
}
