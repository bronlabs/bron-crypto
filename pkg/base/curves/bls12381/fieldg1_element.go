package bls12381

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bimpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/integer"
)

var _ curves.BaseFieldElement = (*BaseFieldElementG1)(nil)
var _ encoding.BinaryMarshaler = (*BaseFieldElementG1)(nil)
var _ encoding.BinaryUnmarshaler = (*BaseFieldElementG1)(nil)
var _ json.Unmarshaler = (*BaseFieldElementG1)(nil)

type BaseFieldElementG1 struct {
	integer.Number[curves.BaseFieldElement]
	algebra.BoundedOrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]
	V *bimpl.Fp

	_ ds.Incomparable
}

func NewBaseFieldElementG1(value uint64) *BaseFieldElementG1 {
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).SetUint64(value),
	}
}
func (*BaseFieldElementG1) Mod(m integer.NaturalRigElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	panic("implement me")
}
func (e *BaseFieldElementG1) Abs() curves.BaseFieldElement {
	return e
}

func (*BaseFieldElementG1) Structure() curves.BaseField {
	return NewBaseFieldG1()
}

func (e *BaseFieldElementG1) Unwrap() curves.BaseFieldElement {
	return e
}

func (*BaseFieldElementG1) Operate(op algebra.Operator, rhs algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	panic("implement me")
}
func (*BaseFieldElementG1) CanGenerateAllElements(under algebra.Operator) bool {
	panic("implement me")
}
func (*BaseFieldElementG1) IsInvolution(under algebra.Operator) (bool, error) {
	panic("implement me")
}
func (*BaseFieldElementG1) IsInvolutionUnderAddition() bool {
	panic("implement me")
}
func (*BaseFieldElementG1) IsInvolutionUnderMultiplication() bool {
	panic("implement me")
}

func (*BaseFieldElementG1) Order(operator algebra.Operator) (*saferith.Nat, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Apply(operator algebra.Operator, x algebra.GroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsIdentity(under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Inverse(under algebra.Operator) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsInverse(of algebra.GroupElement[curves.BaseField, curves.BaseFieldElement], under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsTorsionElement(order *saferith.Modulus, under algebra.Operator) (bool, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsTorsionElementUnderAddition(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) CoPrime(x curves.BaseFieldElement) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) GCD(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) LCM(x curves.BaseFieldElement) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Factorise() []curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) EuclideanDiv(x curves.BaseFieldElement) (quotient, reminder curves.BaseFieldElement) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsTorsionElementUnderMultiplication(order *saferith.Modulus) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Lattice() algebra.OrderTheoreticLattice[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Next() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Previous() (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Chain() algebra.Chain[curves.BaseField, curves.BaseFieldElement] {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsNonZero() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsPositive() bool {
	//TODO implement me
	panic("implement me")
}

// func (*BaseFieldElementG1) Int() integer.Int {
// 	//TODO implement me
// 	panic("implement me")
// }

// func (*BaseFieldElementG1) FromInt(v integer.Int) curves.BaseFieldElement {
// 	//TODO implement me
// 	panic("implement me")
// }

func (*BaseFieldElementG1) Not() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) And(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) ApplyAnd(x algebra.ConjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsConjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Or(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) ApplyOr(x algebra.DisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Xor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], ys ...algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) ApplyXor(x algebra.ExclusiveDisjunctiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsExclusiveDisjunctiveIdentity() bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) ExclusiveDisjunctiveInverse() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) IsExclusiveDisjunctiveInverse(of algebra.ExclusiveDisjunctiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Lsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Rsh(bits uint) curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) BytesLE() []byte {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) SetBytesLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) SetBytesWideLE(bytes []byte) (curves.BaseFieldElement, error) {
	//TODO implement me
	panic("implement me")
}

func (*BaseFieldElementG1) Conjugate() curves.BaseFieldElement {
	//TODO implement me
	panic("implement me")
}

func (e *BaseFieldElementG1) Equal(rhs curves.BaseFieldElement) bool {
	return e.Cmp(rhs) == 0
}

func (e *BaseFieldElementG1) Clone() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Set(e.V),
	}
}

// === Additive Groupoid Methods.

func (e *BaseFieldElementG1) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG1)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Add(e.V, n.V),
	}
}

func (e *BaseFieldElementG1) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElementG1).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *BaseFieldElementG1) Double() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Double(e.V),
	}
}

func (e *BaseFieldElementG1) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *BaseFieldElementG1) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG1)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Mul(e.V, n.V),
	}
}

func (e *BaseFieldElementG1) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *BaseFieldElementG1) Square() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Square(e.V),
	}
}

func (e *BaseFieldElementG1) Cube() curves.BaseFieldElement {
	return e.Square().Mul(e)
}

// === Additive Monoid Methods.

func (e *BaseFieldElementG1) IsAdditiveIdentity() bool {
	return e.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (e *BaseFieldElementG1) IsMultiplicativeIdentity() bool {
	return e.V.IsOne() == 1
}

// == Additive Group Methods.

func (e *BaseFieldElementG1) AdditiveInverse() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Neg(e.V),
	}
}

func (e *BaseFieldElementG1) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *BaseFieldElementG1) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG1)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Sub(e.V, n.V),
	}
}

func (e *BaseFieldElementG1) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElementG1).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *BaseFieldElementG1) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	value, wasInverted := new(bimpl.Fp).Invert(e.V)
	if wasInverted != 1 {
		return nil, errs.NewFailed("multiplicative inverse doesn't exist")
	}

	return &BaseFieldElementG1{
		V: value,
	}, nil
}

func (e *BaseFieldElementG1) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *BaseFieldElementG1) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	r, ok := rhs.(*BaseFieldElementG1)
	if ok {
		v, wasInverted := new(bimpl.Fp).Invert(r.V)
		if wasInverted != 1 {
			return nil, errs.NewFailed("cannot invert rhs")
		}
		v.Mul(v, e.V)
		return &BaseFieldElementG1{V: v}, nil
	} else {
		return nil, errs.NewFailed("rhs is not bls12381 G1 base field element")
	}
}

func (e *BaseFieldElementG1) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (e *BaseFieldElementG1) MulAdd(y algebra.RgElement[curves.BaseField, curves.BaseFieldElement], z algebra.RgElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Mul(y).Add(z)
}

func (e *BaseFieldElementG1) Sqrt() (curves.BaseFieldElement, error) {
	result, wasSquare := new(bimpl.Fp).Sqrt(e.V)
	if wasSquare != 1 {
		return nil, errs.NewFailed("element was not a square")
	}
	return &BaseFieldElementG1{
		V: result,
	}, nil
}

// === Finite Field Methods.

func (e *BaseFieldElementG1) SubFieldElement(i uint) (curves.BaseFieldElement, error) {
	return e, nil
}

func (e *BaseFieldElementG1) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *BaseFieldElementG1) Exp(rhs *saferith.Nat) curves.BaseFieldElement {
	n, ok := e.Structure().Element().SetNat(rhs).(*BaseFieldElementG1)
	if !ok {
		panic("not a bls12381 G1 base field element")
	}
	return &BaseFieldElementG1{
		V: e.V.Exp(e.V, n.V),
	}
}

func (e *BaseFieldElementG1) Neg() curves.BaseFieldElement {
	return e.AdditiveInverse()
}

func (e *BaseFieldElementG1) IsZero() bool {
	return e.IsAdditiveIdentity()
}

func (e *BaseFieldElementG1) IsOne() bool {
	return e.IsMultiplicativeIdentity()
}

func (e *BaseFieldElementG1) IsOdd() bool {
	return e.Bytes()[0]&1 == 1
}

func (e *BaseFieldElementG1) IsEven() bool {
	return e.Bytes()[0]&1 == 0
}

func (e *BaseFieldElementG1) Increment() curves.BaseFieldElement {
	ee, ok := e.Add(NewBaseFieldElementG1(1)).(*BaseFieldElementG1)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

func (e *BaseFieldElementG1) Decrement() curves.BaseFieldElement {
	ee, ok := e.Sub(NewBaseFieldElementG1(1)).(*BaseFieldElementG1)
	if !ok {
		panic("this should not happen")
	}
	return ee
}

// === Ordering Methods.

func (e *BaseFieldElementG1) Cmp(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) algebra.Ordering {
	rhse, ok := rhs.(*BaseFieldElementG1)
	if !ok {
		return algebra.Incomparable
	}
	return algebra.Ordering(e.V.Cmp(rhse.V))
}

func (e *BaseFieldElementG1) IsBottom() bool {
	return e.IsZero()
}

func (e *BaseFieldElementG1) IsTop() bool {
	return e.Add(e.BaseField().One()).IsZero()
}

func (e *BaseFieldElementG1) Join(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Max(rhs.Unwrap())
}

func (e *BaseFieldElementG1) Max(rhs algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
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

func (e *BaseFieldElementG1) Meet(rhs algebra.OrderTheoreticLatticeElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	return e.Min(rhs.Unwrap())
}

func (e *BaseFieldElementG1) Min(rhs algebra.ChainElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
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

func (*BaseFieldElementG1) BaseField() curves.BaseField {
	return NewBaseFieldG1()
}

// === Serialisation.

func (e *BaseFieldElementG1) MarshalBinary() ([]byte, error) {
	res := impl.MarshalBinary(e.BaseField().Curve().Name(), e.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElementG1) UnmarshalBinary(input []byte) error {
	sc, err := impl.UnmarshalBinary(NewBaseFieldElementG1(0).SetBytes, input)
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
	ss, ok := sc.(*BaseFieldElementG1)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	e.V = ss.V
	return nil
}

func (e *BaseFieldElementG1) MarshalJSON() ([]byte, error) {
	res, err := impl.MarshalJson(e.BaseField().Curve().Name(), e.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (e *BaseFieldElementG1) UnmarshalJSON(input []byte) error {
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
	S, ok := sc.(*BaseFieldElementG1)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	e.V = S.V
	return nil
}

func (e *BaseFieldElementG1) Uint64() uint64 {
	return e.Nat().Uint64()
}

func (*BaseFieldElementG1) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	if value == nil {
		return nil
	}
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).SetNat(value),
	}
}

func (e *BaseFieldElementG1) Nat() *saferith.Nat {
	return e.V.Nat()
}

func (*BaseFieldElementG1) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != bimpl.FieldBytes {
		return nil, errs.NewLength("input length (%d != %d bytes)", len(input), bimpl.FieldBytes)
	}
	buffer := bitstring.ReverseBytes(input)
	result, ok := new(bimpl.Fp).SetBytes((*[bimpl.FieldBytes]byte)(buffer))
	if ok != 1 {
		return nil, errs.NewFailed("could not set byte")
	}
	return &BaseFieldElementG1{
		V: result,
	}, nil
}

func (*BaseFieldElementG1) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > bimpl.WideFieldBytes {
		return nil, errs.NewLength("input length > %d bytes", bimpl.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), bimpl.WideFieldBytes-len(input))
	result := new(bimpl.Fp).SetBytesWide((*[bimpl.WideFieldBytes]byte)(buffer))
	return &BaseFieldElementG1{
		V: result,
	}, nil
}

func (e *BaseFieldElementG1) Bytes() []byte {
	v := e.V.Bytes()
	return bitstring.ReverseBytes(v[:])
}
func (e *BaseFieldElementG1) HashCode() uint64 {
	return e.Uint64()
}
