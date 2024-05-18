package edwards25519

import (
	"encoding"
	"encoding/binary"
	"encoding/json"

	filippo_field "filippo.io/edwards25519/field"
	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
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
	V *filippo_field.Element

	_ ds.Incomparable
}

func NewBaseFieldElement(value uint64) *BaseFieldElement {
	buf := make([]byte, 32)
	binary.LittleEndian.PutUint64(buf, value)
	el, err := new(filippo_field.Element).SetBytes(buf)
	if err != nil {
		panic(err)
	}
	return &BaseFieldElement{
		V: el,
	}
}
func (*BaseFieldElement) Mod(m integer.NaturalSemiRingElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	panic("implement me")
}
func (e *BaseFieldElement) Abs() curves.BaseFieldElement {
	return e
}
func (*BaseFieldElement) IsUnit() bool {
	panic("implement me")
}
func (*BaseFieldElement) IsPrime() bool {
	panic("implement me")
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
	return e.Cmp(rhs) == 0
}

func (e *BaseFieldElement) Clone() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Set(e.V),
	}
}

// === Additive Groupoid Methods.

func (e *BaseFieldElement) Add(rhs algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &BaseFieldElement{
		V: new(filippo_field.Element).Add(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplyAdd(x algebra.AdditiveGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Add(x.Unwrap().Mul(reducedN))
}

func (e *BaseFieldElement) Double() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Add(e.V, e.V),
	}
}

func (e *BaseFieldElement) Triple() curves.BaseFieldElement {
	return e.Double().Add(e)
}

// === Multiplicative Groupoid Methods.

func (e *BaseFieldElement) Mul(rhs algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &BaseFieldElement{
		V: new(filippo_field.Element).Multiply(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplyMul(x algebra.MultiplicativeGroupoidElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	return e.Mul(x.Exp(n))
}

func (e *BaseFieldElement) Square() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Square(e.V),
	}
}

func (e *BaseFieldElement) Cube() curves.BaseFieldElement {
	eSq := new(filippo_field.Element).Square(e.V)
	return &BaseFieldElement{
		V: eSq.Multiply(eSq, e.V),
	}
}

// === Additive Monoid Methods.

func (e *BaseFieldElement) IsAdditiveIdentity() bool {
	return e.V.Equal(feZero) == 1
}

// === Multiplicative Monoid Methods.

func (e *BaseFieldElement) IsMultiplicativeIdentity() bool {
	return e.V.Equal(feOne) == 1
}

// === Additive Group Methods.

func (e *BaseFieldElement) AdditiveInverse() curves.BaseFieldElement {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Negate(e.V),
	}
}

func (e *BaseFieldElement) IsAdditiveInverse(of algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *BaseFieldElement) Sub(rhs algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		panic("rhs is not an edwards25519 base field element")
	}
	return &BaseFieldElement{
		V: new(filippo_field.Element).Subtract(e.V, n.V),
	}
}

func (e *BaseFieldElement) ApplySub(x algebra.AdditiveGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElement).SetNat(n)
	return e.Sub(x.Unwrap().Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *BaseFieldElement) MultiplicativeInverse() (curves.BaseFieldElement, error) {
	return &BaseFieldElement{
		V: new(filippo_field.Element).Invert(e.V),
	}, nil
}

func (e *BaseFieldElement) IsMultiplicativeInverse(of algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *BaseFieldElement) Div(rhs algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement]) (curves.BaseFieldElement, error) {
	rhsFe, ok := rhs.(*BaseFieldElement)
	if !ok {
		return nil, errs.NewFailed("rhs is not an edwards25519 base field element")
	}
	inverted := new(filippo_field.Element).Invert(rhsFe.V)
	if inverted.Equal(feZero) == 1 {
		return nil, errs.NewFailed("inverse of rhs is zero. cannot divide")
	}

	return &BaseFieldElement{
		V: inverted.Multiply(e.V, inverted),
	}, nil
}

func (e *BaseFieldElement) ApplyDiv(x algebra.MultiplicativeGroupElement[curves.BaseField, curves.BaseFieldElement], n *saferith.Nat) (curves.BaseFieldElement, error) {
	return e.Div(x.Exp(n))
}

// === Ring Methods.

func (e *BaseFieldElement) MulAdd(y algebra.PreSemiRingElement[curves.BaseField, curves.BaseFieldElement], z algebra.PreSemiRingElement[curves.BaseField, curves.BaseFieldElement]) curves.BaseFieldElement {
	yFe, ok := y.(*BaseFieldElement)
	if !ok {
		panic("y is not an edwards25519 base field element")
	}
	zFe, ok := z.(*BaseFieldElement)
	if !ok {
		panic("y is not an edwards25519 base field element")
	}
	v := new(filippo_field.Element).Multiply(e.V, yFe.V)
	return &BaseFieldElement{
		V: v.Add(v, zFe.V),
	}
}

func (e *BaseFieldElement) Sqrt() (curves.BaseFieldElement, error) {
	res, ok := e.V.SqrtRatio(e.V, feOne)
	if ok == 1 {
		return &BaseFieldElement{
			V: res,
		}, nil
	}
	return nil, errs.NewFailed("could compute sqrt")
}

// === Finite Field Methods.

func (e *BaseFieldElement) SubFieldElement(i uint) (curves.BaseFieldElement, error) {
	return e, nil
}

func (e *BaseFieldElement) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *BaseFieldElement) Exp(exp *saferith.Nat) curves.BaseFieldElement {
	r := new(saferith.Nat).Exp(e.Nat(), exp, e.BaseField().Order())
	return e.BaseField().Element().SetNat(r)
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

func (e *BaseFieldElement) IsOdd() bool {
	return e.V.Bytes()[0]&1 == 1
}

func (e *BaseFieldElement) IsEven() bool {
	return e.V.Bytes()[0]&1 == 0
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
	n, ok := rhs.(*BaseFieldElement)
	if !ok {
		return algebra.Incomparable
	}
	if e.V.Equal(n.V) == 1 {
		return algebra.Equal
	}
	v := e.V.Subtract(e.V, n.V)
	if v.IsNegative() == 1 {
		return algebra.LessThan
	}
	return algebra.GreaterThan
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

func (e *BaseFieldElement) SetNat(value *saferith.Nat) curves.BaseFieldElement {
	if value == nil {
		return nil
	}
	moddedValue := new(saferith.Nat).Mod(value, e.BaseField().Order())
	v, err := new(filippo_field.Element).SetBytes(bitstring.ReverseBytes(moddedValue.Bytes()))
	if err != nil {
		panic(errs.WrapSerialisation(err, "could not set nat bytes"))
	}
	return &BaseFieldElement{
		V: v,
	}
}

func (e *BaseFieldElement) Nat() *saferith.Nat {
	return new(saferith.Nat).SetBytes(e.Bytes())
}

func (e *BaseFieldElement) SetBytes(input []byte) (curves.BaseFieldElement, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewLength("input length != %d bytes", base.FieldBytes)
	}
	result, err := e.V.SetBytes(bitstring.ReverseBytes(input))
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not set bytes")
	}
	return &BaseFieldElement{
		V: result,
	}, nil
}

func (e *BaseFieldElement) SetBytesWide(input []byte) (curves.BaseFieldElement, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewLength("input length > %d bytes", base.WideFieldBytes)
	}
	inputLE := bitstring.ReverseBytes(input)
	buffer := bitstring.PadToRight(inputLE, base.WideFieldBytes-len(input))
	result, err := e.V.SetWideBytes(buffer)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not set bytes")
	}
	return &BaseFieldElement{
		V: result,
	}, nil
}

func (e *BaseFieldElement) Bytes() []byte {
	result := e.V.Bytes()
	return bitstring.ReverseBytes(result)
}
func (e *BaseFieldElement) HashCode() uint64 {
	return e.Uint64()
}
