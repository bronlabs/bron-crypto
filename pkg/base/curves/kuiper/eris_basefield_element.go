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
	_ curves.BaseFieldElement    = (*ErisBaseFieldElement)(nil)
	_ encoding.BinaryMarshaler   = (*ErisBaseFieldElement)(nil)
	_ encoding.BinaryUnmarshaler = (*ErisBaseFieldElement)(nil)
	_ json.Unmarshaler           = (*ErisBaseFieldElement)(nil)
)

type ErisBaseFieldElement struct {
	V impl.Fq

	_ ds.Incomparable
}

func NewErisBaseFieldElement(value uint64) *ErisBaseFieldElement {
	r := new(ErisBaseFieldElement)
	r.V.SetUint64(value)
	return r
}

func (*ErisBaseFieldElement) Structure() curves.BaseField {
	return NewErisBaseField()
}

func (e *ErisBaseFieldElement) Unwrap() curves.BaseFieldElement {
	return e
}

func (*ErisBaseFieldElement) Order(operator algebra.BinaryOperator[curves.BaseFieldElement]) (*saferith.Modulus, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) ApplyOp(operator algebra.BinaryOperator[curves.BaseFieldElement], x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsIdentity(under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Inverse(under algebra.BinaryOperator[curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsInverse(of algebra.GroupElement[curves.BaseField, curves.BaseFieldElement], under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsTorsionElement(order *saferith.Modulus, under algebra.BinaryOperator[curves.BaseFieldElement]) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) CoPrime(x curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) GCD(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) LCM(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Factorise() []curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) EuclideanDiv(x curves.BaseFieldElement) (quotient, reminder curves.BaseFieldElement) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Lattice() algebra.OrderTheoreticLattice[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Next() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Previous() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Chain() algebra.Chain[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Int() algebra.Int {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) FromInt(v algebra.Int) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Not() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) ExclusiveDisjunctiveInverse() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Lsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Rsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) SetBytesLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) SetBytesWideLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*ErisBaseFieldElement) Conjugate() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (e *ErisBaseFieldElement) Equal(rhs curves.BaseFieldElement) bool {
	y := rhs.(*ErisBaseFieldElement)
	return e.V.Equal(&y.V) == 1
}

func (e *ErisBaseFieldElement) Clone() curves.BaseFieldElement {
	z := new(ErisBaseFieldElement)
	z.V.Set(&e.V)
	return z
}

// === Additive Groupoid Methods.

func (e *ErisBaseFieldElement) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*ErisBaseFieldElement)
	if !ok {
		panic("not an Eris Fq element")
	}
	z := new(ErisBaseFieldElement)
	z.V.Add(&e.V, &n.V)
	return z
}

func (e *ErisBaseFieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(ErisBaseFieldElement).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *ErisBaseFieldElement) Double() curves.BaseFieldElement {
	z := new(ErisBaseFieldElement)
	z.V.Double(&e.V)
	return z
}

func (e *ErisBaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *ErisBaseFieldElement) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*ErisBaseFieldElement)
	if !ok {
		panic("not a Eris Fq element")
	}
	z := new(ErisBaseFieldElement)
	z.V.Mul(&e.V, &n.V)
	return z
}

func (e *ErisBaseFieldElement) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *ErisBaseFieldElement) Square() curves.BaseFieldElement {
	z := new(ErisBaseFieldElement)
	z.V.Square(&e.V)
	return z
}

func (e *ErisBaseFieldElement) Cube() curves.BaseFieldElement {
	return e.Square().Mul(e)
}

// === Additive Monoid Methods.

func (e *ErisBaseFieldElement) IsAdditiveIdentity() bool {
	return e.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (e *ErisBaseFieldElement) IsMultiplicativeIdentity() bool {
	return e.V.IsOne() == 1
}

// == Additive Group Methods.

func (e *ErisBaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	z := new(ErisBaseFieldElement)
	z.V.Neg(&e.V)
	return z
}

func (e *ErisBaseFieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *ErisBaseFieldElement) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*ErisBaseFieldElement)
	if !ok {
		panic("not a Eris Fq element")
	}
	z := new(ErisBaseFieldElement)
	z.V.Sub(&e.V, &n.V)
	return z
}

func (e *ErisBaseFieldElement) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(ErisBaseFieldElement).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *ErisBaseFieldElement) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	value, wasInverted := new(impl.Fq).Invert(&e.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("multiplicative inverse doesn't exist")
	}

	z := new(ErisBaseFieldElement)
	z.V.Set(value)
	return z, nil
}

func (e *ErisBaseFieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *ErisBaseFieldElement) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	r, ok := rhs.(*ErisBaseFieldElement)
	if ok {
		v, wasInverted := new(impl.Fq).Invert(&r.V)
		if wasInverted != 1 {
			return nil, errs.NewFailed("cannot invert rhs")
		}
		v.Mul(v, &e.V)
		z := new(ErisBaseFieldElement)
		z.V.Set(v)
		return z, nil
	} else {
		return nil, errs.NewFailed("rhs is not bls12381 G1 base field element")
	}
}

func (e *ErisBaseFieldElement) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (e *ErisBaseFieldElement) MulAdd(y algebra.RingElement[curves.BaseField, curves.BaseFieldElement], z algebra.RingElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Mul(y).Add(z)
}

func (e *ErisBaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	result, wasSquare := new(impl.Fq).Sqrt(&e.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("element was not a square")
	}
	z := new(ErisBaseFieldElement)
	z.V.Set(result)
	return z, nil
}

// === Finite Field Methods.

func (e *ErisBaseFieldElement) SubFieldElement(i uint) (curves.BaseFieldElement, error) {
	return e, nil
}

func (e *ErisBaseFieldElement) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *ErisBaseFieldElement) Exp(rhs *saferith.Nat) curves.BaseFieldElement {
	n, ok := e.Structure().Element().SetNat(rhs).(*ErisBaseFieldElement)
	if !ok {
		panic("not an Eris Fq element")
	}
	z := new(ErisBaseFieldElement)
	z.V.Exp(&e.V, &n.V)
	return z
}

func (e *ErisBaseFieldElement) Neg() curves.BaseFieldElement {
	return e.AdditiveInverse()
}

func (e *ErisBaseFieldElement) IsZero() bool {
	return e.IsAdditiveIdentity()
}

func (e *ErisBaseFieldElement) IsOne() bool {
	return e.IsMultiplicativeIdentity()
}

func (e *ErisBaseFieldElement) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *ErisBaseFieldElement) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *ErisBaseFieldElement) Increment() curves.BaseFieldElement {
	z := new(ErisBaseFieldElement)
	z.V.Add(&e.V, &impl.FqOne)
	return z
}

func (e *ErisBaseFieldElement) Decrement() curves.BaseFieldElement {
	z := new(ErisBaseFieldElement)
	z.V.Sub(&e.V, &impl.FqOne)
	return z
}

// === Ordering Methods.

func (e *ErisBaseFieldElement) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	rhse, ok := rhs.(*ErisBaseFieldElement)
	if !ok {
		return algebra.Incomparable
	}
	return algebra.Ordering(e.V.Cmp(&rhse.V))
}

func (e *ErisBaseFieldElement) IsBottom() bool {
	return e.IsZero()
}

func (e *ErisBaseFieldElement) IsTop() bool {
	return e.Add(e.BaseField().One()).IsZero()
}

func (e *ErisBaseFieldElement) Join(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Max(rhs.Unwrap())
}

func (e *ErisBaseFieldElement) Max(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (e *ErisBaseFieldElement) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Min(rhs.Unwrap())
}

func (e *ErisBaseFieldElement) Min(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (*ErisBaseFieldElement) BaseField() curves.BaseField {
	return NewErisBaseField()
}

// === Serialisation.

func (e *ErisBaseFieldElement) MarshalBinary() ([]byte, error) {
	res := curvesImpl.MarshalBinary(e.BaseField().Curve().Name(), e.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (e *ErisBaseFieldElement) UnmarshalBinary(input []byte) error {
	sc, err := curvesImpl.UnmarshalBinary(NewErisBaseFieldElement(0).SetBytes, input)
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
	ss, ok := sc.(*ErisBaseFieldElement)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	e.V = ss.V
	return nil
}

func (e *ErisBaseFieldElement) MarshalJSON() ([]byte, error) {
	res, err := curvesImpl.MarshalJson(e.BaseField().Curve().Name(), e.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *ErisBaseFieldElement) UnmarshalJSON(input []byte) error {
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
	S, ok := sc.(*ErisBaseFieldElement)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	e.V = S.V
	return nil
}

func (e *ErisBaseFieldElement) Uint64() uint64 {
	return e.Nat().Uint64()
}

func (*ErisBaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	if value == nil {
		return nil
	}
	z := new(ErisBaseFieldElement)
	z.V.SetNat(value)
	return z
}

func (e *ErisBaseFieldElement) Nat() *saferith.Nat {
	return e.V.Nat()
}

func (*ErisBaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != impl.FieldBytes {
		return nil, errs.NewLength("input length (%d != %d bytes)", len(input), impl.FieldBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result, ok := new(impl.Fq).SetBytes((*[impl.FieldBytes]byte)(buffer))
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	z := new(ErisBaseFieldElement)
	z.V.Set(result)
	return z, nil
}

func (*ErisBaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > impl.WideFieldBytes {
		return nil, errs.NewLength("input length > %d bytes", impl.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), impl.WideFieldBytes-len(input))
	result := new(impl.Fq).SetBytesWide((*[impl.WideFieldBytes]byte)(buffer))
	z := new(ErisBaseFieldElement)
	z.V.Set(result)
	return z, nil
}

func (e *ErisBaseFieldElement) Bytes() []byte {
	v := e.V.Bytes()
	return bitstring.ReverseBytes(v[:])
}
func (e *ErisBaseFieldElement) HashCode() uint64 {
	return e.Uint64()
}
