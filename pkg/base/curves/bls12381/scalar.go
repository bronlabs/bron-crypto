package bls12381

import (
	"encoding"
	"encoding/json"
	"fmt"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	bls12381impl "github.com/copperexchange/krypton-primitives/pkg/base/curves/bls12381/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	saferithUtils "github.com/copperexchange/krypton-primitives/pkg/base/utils/saferith"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	V *impl.FieldValue
	G curves.Curve

	_ ds.Incomparable
}

func NewScalar(subgroup curves.Curve, value uint64) (*Scalar, error) {
	if subgroup.Name() != NewG1().Name() && subgroup.Name() != NewG2().Name() {
		return nil, errs.NewCurve("subgroup %s is not one of the bls source subgroups", subgroup.Name())
	}
	return &Scalar{
		V: bls12381impl.FqNew().SetUint64(value),
		G: subgroup,
	}, nil
}

// === Basic Methods.

func (s *Scalar) Equal(rhs curves.Scalar) bool {
	return s.Cmp(rhs) == 0
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		V: bls12381impl.FqNew().Set(s.V),
		G: s.G,
	}
}

// === Additive Groupoid Methods.

func (s *Scalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: bls12381impl.FqNew().Add(s.V, r.V),
			G: s.G,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) ApplyAdd(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n).(*Scalar)
	reducedN.G = s.G
	return s.Add(x.Mul(reducedN))
}

func (s *Scalar) Double() curves.Scalar {
	v := bls12381impl.FqNew().Double(s.V)
	return &Scalar{
		V: v,
		G: s.G,
	}
}

func (s *Scalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (s *Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: bls12381impl.FqNew().Mul(s.V, r.V),
			G: s.G,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) ApplyMul(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n).(*Scalar)
	reducedN.G = s.G
	return s.Mul(x.Exp(reducedN))
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		V: bls12381impl.FqNew().Square(s.V),
		G: s.G,
	}
}

func (s *Scalar) Cube() curves.Scalar {
	value := bls12381impl.FqNew().Square(s.V)
	value.Mul(value, s.V)
	return &Scalar{
		V: value,
		G: s.G,
	}
}

// === Additive Monoid Methods.

func (s *Scalar) IsAdditiveIdentity() bool {
	return s.V.IsZero() == 1
}

// === Multiplicative Monoid Methods.

func (s *Scalar) IsMultiplicativeIdentity() bool {
	return s.V.IsOne() == 1
}

// === Additive Group Methods.

func (s *Scalar) AdditiveInverse() curves.Scalar {
	return &Scalar{
		V: bls12381impl.FqNew().Neg(s.V),
		G: s.G,
	}
}

func (s *Scalar) IsAdditiveInverse(of curves.Scalar) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: bls12381impl.FqNew().Sub(s.V, r.V),
			G: s.G,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) ApplySub(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n).(*Scalar)
	reducedN.G = s.G
	return s.Sub(x.Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *Scalar) MultiplicativeInverse() curves.Scalar {
	value, wasInverted := bls12381impl.FqNew().Invert(s.V)
	if !wasInverted {
		panic(errs.NewFailed("inverse doesn't exist"))
	}
	return &Scalar{
		V: value,
		G: s.G,
	}
}

func (s *Scalar) IsMultiplicativeInverse(of curves.Scalar) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *Scalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		v, wasInverted := bls12381impl.FqNew().Invert(r.V)
		if !wasInverted {
			panic("cannot invert scalar")
		}
		v.Mul(v, s.V)
		return &Scalar{
			V: v,
			G: s.G,
		}
	} else {
		panic("rhs is not ScalarBls12381")
	}
}

func (s *Scalar) ApplyDiv(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n).(*Scalar)
	reducedN.G = s.G
	return s.Div(x.Exp(reducedN))
}

// === Ring Methods.

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := bls12381impl.FqNew().Sqrt(s.V)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		V: value,
		G: s.G,
	}, nil
}

func (s *Scalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	return s.Mul(y).Add(z)
}

// === Finite Field Methods.

func (s *Scalar) SubFieldElement(index uint) curves.Scalar {
	return s
}

func (s *Scalar) Norm() curves.Scalar {
	return s
}

// === Zp Methods.

func (s *Scalar) Exp(k curves.Scalar) curves.Scalar {
	exp, ok := k.(*Scalar)
	if !ok {
		panic("rhs is not ScalarBls12381")
	}

	value := bls12381impl.FqNew().Exp(s.V, exp.V)
	return &Scalar{
		V: value,
		G: s.G,
	}
}

func (s *Scalar) Neg() curves.Scalar {
	return s.AdditiveInverse()
}

func (s *Scalar) IsZero() bool {
	return s.V.IsZero() == 1
}

func (s *Scalar) IsOne() bool {
	return s.V.IsOne() == 1
}

func (s *Scalar) IsOdd() bool {
	bytes_ := s.V.Bytes()
	return bytes_[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	bytes_ := s.V.Bytes()
	return bytes_[0]&1 == 0
}

func (s *Scalar) Increment() {
	ee, ok := s.Add(s.ScalarField().One()).(*Scalar)
	if !ok {
		panic("invalid type")
	}
	s.V = ee.V
}

func (s *Scalar) Decrement() {
	ee, ok := s.Sub(s.ScalarField().One()).(*Scalar)
	if !ok {
		panic("invalid type")
	}
	s.V = ee.V
}

// === Ordering Methods.

func (s *Scalar) Cmp(rhs curves.Scalar) algebra.Ordering {
	r, ok := rhs.(*Scalar)
	if ok {
		// TODO: debug Cmp for BLS
		gt, eq, lt := s.Nat().Cmp(r.Nat())
		if gt == 1 {
			return 1
		}
		if eq == 1 {
			return 0
		}
		if lt == 1 {
			return -1
		}
		return algebra.Incomparable
	} else {
		return algebra.Incomparable
	}
}

func (s *Scalar) IsBottom() bool {
	return s.IsZero()
}

func (s *Scalar) IsTop() bool {
	return s.Add(s.ScalarField().One()).IsZero()
}

func (s *Scalar) Join(rhs curves.Scalar) curves.Scalar {
	return s.Max(rhs)
}

func (s *Scalar) Max(rhs curves.Scalar) curves.Scalar {
	switch s.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan:
		return rhs
	case algebra.Equal, algebra.GreaterThan:
		return s
	default:
		panic("comparison output not supported")
	}
}

func (s *Scalar) Meet(rhs curves.Scalar) curves.Scalar {
	return s.Min(rhs)
}

func (s *Scalar) Min(rhs curves.Scalar) curves.Scalar {
	switch s.Cmp(rhs) {
	case algebra.Incomparable:
		panic("incomparable")
	case algebra.LessThan, algebra.Equal:
		return s
	case algebra.GreaterThan:
		return rhs
	default:
		panic("comparison output not supported")
	}
}

// === Curve Methods.

func (s *Scalar) ScalarField() curves.ScalarField {
	switch s.G.Name() {
	case NewG1().Name():
		return NewScalarFieldG1()
	case NewG2().Name():
		return NewScalarFieldG2()
	default:
		panic(fmt.Sprintf("subgroup %s is not a bls source subgroup", s.G.Name()))
	}
}

// === Serialisation.

func (s *Scalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (s *Scalar) SetNat(v *saferith.Nat) curves.Scalar {
	if v == nil {
		return nil
	}
	return &Scalar{
		V: bls12381impl.FqNew().SetNat(v),
		G: s.G,
	}
}

func (s *Scalar) Nat() *saferith.Nat {
	return s.V.Nat()
}

func (s *Scalar) Bytes() []byte {
	t := s.V.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (s *Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewLength("invalid length")
	}
	reducedInput := saferithUtils.NatFromBytesMod(input, r)
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(reducedInput.Bytes()), base.FieldBytes-len(reducedInput.Bytes()))
	value, err := bls12381impl.FqNew().SetBytes((*[base.FieldBytes]byte)(buffer))
	if err != nil {
		return nil, errs.WrapSerialisation(err, "couldn't set bytes")
	}
	return &Scalar{
		V: value,
		G: s.G,
	}, nil
}

func (s *Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewLength("invalid length > %d", base.WideFieldBytes)
	}
	buffer := bitstring.PadToRight(bitstring.ReverseBytes(input), base.WideFieldBytes-len(input))
	value := bls12381impl.FqNew().SetBytesWide((*[base.WideFieldBytes]byte)(buffer))
	return &Scalar{
		V: value,
		G: s.G,
	}, nil
}

func (s *Scalar) MarshalBinary() ([]byte, error) {
	res := impl.MarshalBinary(s.ScalarField().Curve().Name(), s.Bytes)
	if len(res) < 1 {
		return nil, errs.NewSerialisation("could not marshal")
	}
	return res, nil
}

func (s *Scalar) UnmarshalBinary(input []byte) error {
	sc, err := impl.UnmarshalBinary(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not unmarshal")
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V = ss.V
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't extract name from input")
	}
	switch name {
	case NameG1:
		s.G = NewG1()
	case NameG2:
		s.G = NewG2()
	default:
		return errs.NewType("name %s is not supported", name)
	}
	return nil
}

func (s *Scalar) MarshalJSON() ([]byte, error) {
	res, err := impl.MarshalJson(s.ScalarField().Curve().Name(), s.Bytes)
	if err != nil {
		return nil, errs.WrapSerialisation(err, "could not marshal")
	}
	return res, nil
}

func (s *Scalar) UnmarshalJSON(input []byte) error {
	name, _, err := impl.ParseJSON(input)
	if err != nil {
		return errs.WrapSerialisation(err, "couldn't extract name from input")
	}
	switch name {
	case NameG1:
		s.G = NewG1()
	case NameG2:
		s.G = NewG2()
	default:
		return errs.NewType("name %s is not supported", name)
	}
	sc, err := impl.UnmarshalJson(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V = S.V
	return nil
}
func (s *Scalar) HashCode() uint64 {
	return s.Uint64()
}
