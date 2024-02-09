package bls12381

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bimpl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
	"github.com/copperexchange/krypton-primitives/pkg/base/utils"
)

var _ curves.BaseFieldElement = (*BaseFieldElementG1)(nil)
var _ encoding.BinaryMarshaler = (*BaseFieldElementG1)(nil)
var _ encoding.BinaryUnmarshaler = (*BaseFieldElementG1)(nil)
var _ json.Unmarshaler = (*BaseFieldElementG1)(nil)

type BaseFieldElementG1 struct {
	V *bimpl.Fp

	_ types.Incomparable
}

func NewBaseFieldElementG1(value uint64) *BaseFieldElementG1 {
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).SetUint64(value),
	}
}

// === Basic Methods.

func (e *BaseFieldElementG1) Equal(rhs curves.BaseFieldElement) bool {
	return e.Cmp(rhs) == 0
}

func (e *BaseFieldElementG1) Clone() curves.BaseFieldElement {
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Set(e.V),
	}
}

// === Additive Groupoid Methods.

func (e *BaseFieldElementG1) Add(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG1)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Add(e.V, n.V),
	}
}

func (e *BaseFieldElementG1) ApplyAdd(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElementG1).SetNat(n)
	return e.Add(x.Mul(reducedN))
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

func (e *BaseFieldElementG1) Mul(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG1)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Mul(e.V, n.V),
	}
}

func (e *BaseFieldElementG1) ApplyMul(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElementG1).SetNat(n)
	return e.Mul(x.Exp(reducedN))
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

func (e *BaseFieldElementG1) IsAdditiveInverse(of curves.BaseFieldElement) bool {
	return e.Add(of).IsAdditiveIdentity()
}

func (e *BaseFieldElementG1) Sub(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG1)
	if !ok {
		panic("not a bls12381 G1 Fp element")
	}
	return &BaseFieldElementG1{
		V: new(bimpl.Fp).Sub(e.V, n.V),
	}
}

func (e *BaseFieldElementG1) ApplySub(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElementG1).SetNat(n)
	return e.Sub(x.Mul(reducedN))
}

// === Multiplicative Group Methods.

func (e *BaseFieldElementG1) MultiplicativeInverse() curves.BaseFieldElement {
	value, wasInverted := new(bimpl.Fp).Invert(e.V)
	if wasInverted != 1 {
		panic(errs.NewFailed("multiplicative inverse doesn't exist"))
	}
	return &BaseFieldElementG1{
		V: value,
	}
}

func (e *BaseFieldElementG1) IsMultiplicativeInverse(of curves.BaseFieldElement) bool {
	return e.Mul(of).IsMultiplicativeIdentity()
}

func (e *BaseFieldElementG1) Div(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	r, ok := rhs.(*BaseFieldElementG1)
	if ok {
		v, wasInverted := new(bimpl.Fp).Invert(r.V)
		if wasInverted != 1 {
			panic("cannot invert rhs")
		}
		v.Mul(v, e.V)
		return &BaseFieldElementG1{V: v}
	} else {
		panic("rhs is not bls12381 G1 base field element")
	}
}

func (e *BaseFieldElementG1) ApplyDiv(x curves.BaseFieldElement, n *saferith.Nat) curves.BaseFieldElement {
	reducedN := new(BaseFieldElementG1).SetNat(n)
	return e.Div(x.Exp(reducedN))
}

// === Ring Methods.

func (e *BaseFieldElementG1) MulAdd(y, z curves.BaseFieldElement) curves.BaseFieldElement {
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

func (e *BaseFieldElementG1) SubFieldElement(index uint) curves.BaseFieldElement {
	return e
}

func (e *BaseFieldElementG1) Norm() curves.BaseFieldElement {
	return e
}

// === Zp Methods.

func (e *BaseFieldElementG1) Exp(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	n, ok := rhs.(*BaseFieldElementG1)
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

func (e *BaseFieldElementG1) Increment() {
	ee, ok := e.Add(NewBaseFieldElementG1(1)).(*BaseFieldElementG1)
	if !ok {
		panic("this should not happen")
	}
	e.V = ee.V
}

func (e *BaseFieldElementG1) Decrement() {
	ee, ok := e.Sub(NewBaseFieldElementG1(1)).(*BaseFieldElementG1)
	if !ok {
		panic("this should not happen")
	}
	e.V = ee.V
}

// === Ordering Methods.

func (e *BaseFieldElementG1) Cmp(rhs curves.BaseFieldElement) algebra.Ordering {
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

func (e *BaseFieldElementG1) Join(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Max(rhs)
}

func (e *BaseFieldElementG1) Max(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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

func (e *BaseFieldElementG1) Meet(rhs curves.BaseFieldElement) curves.BaseFieldElement {
	return e.Min(rhs)
}

func (e *BaseFieldElementG1) Min(rhs curves.BaseFieldElement) curves.BaseFieldElement {
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
	if name != e.BaseField().Curve().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
	}
	ss, ok := sc.(*BaseFieldElementG1)
	if !ok {
		return errs.NewInvalidType("invalid base field element")
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
	if name != e.BaseField().Curve().Name() {
		return errs.NewInvalidType("name %s is not supported", name)
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
		return nil, errs.NewInvalidLength("input length (%d != %d bytes)", len(input), bimpl.FieldBytes)
	}
	buffer := utils.SliceReverse(input)
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
		return nil, errs.NewInvalidLength("input length > %d bytes", bimpl.WideFieldBytes)
	}
	buffer := utils.SlicePadRight(utils.SliceReverse(input), bimpl.WideFieldBytes-len(input))
	result := new(bimpl.Fp).SetBytesWide((*[bimpl.WideFieldBytes]byte)(buffer))
	return &BaseFieldElementG1{
		V: result,
	}, nil
}

func (e *BaseFieldElementG1) Bytes() []byte {
	v := e.V.Bytes()
	return utils.SliceReverse(v[:])
}
