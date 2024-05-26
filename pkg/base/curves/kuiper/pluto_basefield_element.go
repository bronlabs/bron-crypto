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
	_ curves.BaseFieldElement    = (*PlutoBaseFieldElement)(nil)
	_ encoding.BinaryMarshaler   = (*PlutoBaseFieldElement)(nil)
	_ encoding.BinaryUnmarshaler = (*PlutoBaseFieldElement)(nil)
	_ json.Unmarshaler           = (*PlutoBaseFieldElement)(nil)
)

type PlutoBaseFieldElement struct {
	V impl.Fp

	_ ds.Incomparable
}

func NewPlutoBaseFieldElement(value uint64) *PlutoBaseFieldElement {
	r := new(PlutoBaseFieldElement)
	r.V.SetUint64(value)
	return r
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
	y := rhs.(*PlutoBaseFieldElement)
	return e.V.Equal(&y.V) == 1
}

func (e *PlutoBaseFieldElement) Clone() curves.BaseFieldElement {
	z := new(PlutoBaseFieldElement)
	z.V.Set(&e.V)
	return z
}

// === Additive Groupoid Methods.

func (e *PlutoBaseFieldElement) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*PlutoBaseFieldElement)
	if !ok {
		panic("not a Pluto Fp element")
	}
	z := new(PlutoBaseFieldElement)
	z.V.Add(&e.V, &n.V)
	return z
}

func (e *PlutoBaseFieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(PlutoBaseFieldElement).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *PlutoBaseFieldElement) Double() curves.BaseFieldElement {
	z := new(PlutoBaseFieldElement)
	z.V.Double(&e.V)
	return z
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
	z := new(PlutoBaseFieldElement)
	z.V.Mul(&e.V, &n.V)
	return z
}

func (e *PlutoBaseFieldElement) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *PlutoBaseFieldElement) Square() curves.BaseFieldElement {
	z := new(PlutoBaseFieldElement)
	z.V.Square(&e.V)
	return z
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
	z := new(PlutoBaseFieldElement)
	z.V.Neg(&e.V)
	return z
}

func (e *PlutoBaseFieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *PlutoBaseFieldElement) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*PlutoBaseFieldElement)
	if !ok {
		panic("not a Pluto Fp element")
	}
	z := new(PlutoBaseFieldElement)
	z.V.Sub(&e.V, &n.V)
	return z
}

func (e *PlutoBaseFieldElement) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(PlutoBaseFieldElement).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *PlutoBaseFieldElement) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	value, wasInverted := new(impl.Fp).Invert(&e.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("multiplicative inverse doesn't exist")
	}

	z := new(PlutoBaseFieldElement)
	z.V.Set(value)
	return z, nil
}

func (e *PlutoBaseFieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *PlutoBaseFieldElement) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	r, ok := rhs.(*PlutoBaseFieldElement)
	if ok {
		v, wasInverted := new(impl.Fp).Invert(&r.V)
		if wasInverted != 1 {
			return nil, errs.NewFailed("cannot invert rhs")
		}
		v.Mul(v, &e.V)
		z := new(PlutoBaseFieldElement)
		z.V.Set(v)
		return z, nil
	} else {
		return nil, errs.NewFailed("rhs is not bls12381 G1 base field element")
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
	result, wasSquare := new(impl.Fp).Sqrt(&e.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("element was not a square")
	}
	z := new(PlutoBaseFieldElement)
	z.V.Set(result)
	return z, nil
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
		panic("not a Pluto Fp element")
	}
	z := new(PlutoBaseFieldElement)
	z.V.Exp(&e.V, &n.V)
	return z
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
	z := new(PlutoBaseFieldElement)
	z.V.Add(&e.V, &impl.FpOne)
	return z
}

func (e *PlutoBaseFieldElement) Decrement() curves.BaseFieldElement {
	z := new(PlutoBaseFieldElement)
	z.V.Sub(&e.V, &impl.FpOne)
	return z
}

// === Ordering Methods.

func (e *PlutoBaseFieldElement) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	rhse, ok := rhs.(*PlutoBaseFieldElement)
	if !ok {
		return algebra.Incomparable
	}
	return algebra.Ordering(e.V.Cmp(&rhse.V))
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
	z := new(PlutoBaseFieldElement)
	z.V.SetNat(value)
	return z
}

func (e *PlutoBaseFieldElement) Nat() *saferith.Nat {
	return e.V.Nat()
}

func (*PlutoBaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != impl.FieldBytes {
		return nil, errs.NewLength("input length (%d != %d bytes)", len(input), impl.FieldBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result, ok := new(impl.Fp).SetBytes((*[impl.FieldBytes]byte)(buffer))
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	z := new(PlutoBaseFieldElement)
	z.V.Set(result)
	return z, nil
}

func (*PlutoBaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > impl.WideFieldBytes {
		return nil, errs.NewLength("input length > %d bytes", impl.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), impl.WideFieldBytes-len(input))
	result := new(impl.Fp).SetBytesWide((*[impl.WideFieldBytes]byte)(buffer))
	z := new(PlutoBaseFieldElement)
	z.V.Set(result)
	return z, nil
}

func (e *PlutoBaseFieldElement) Bytes() []byte {
	v := e.V.Bytes()
	return bitstring.ReverseBytes(v[:])
}
func (e *PlutoBaseFieldElement) HashCode() uint64 {
	return e.Uint64()
}
