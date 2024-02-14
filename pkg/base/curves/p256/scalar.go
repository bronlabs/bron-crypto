package p256

import (
	"encoding"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256/impl/fq"
	ds "github.com/copperexchange/krypton-primitives/pkg/base/datastructures"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	V *impl.FieldValue

	_ ds.Incomparable
}

func NewScalar(value uint64) *Scalar {
	return &Scalar{
		V: fq.New().SetUint64(value),
	}
}

// === Basic Methods.

func (s *Scalar) Equal(rhs curves.Scalar) bool {
	return s.Cmp(rhs) == 0
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		V: fq.New().Set(s.V),
	}
}

// === Additive Groupoid Methods.

func (s *Scalar) Add(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: fq.New().Add(s.V, r.V),
		}
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (s *Scalar) ApplyAdd(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Add(x.Mul(reducedN))
}

func (s *Scalar) Double() curves.Scalar {
	return &Scalar{
		V: fq.New().Double(s.V),
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
			V: fq.New().Mul(s.V, r.V),
		}
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (s *Scalar) ApplyMul(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Mul(x.Exp(reducedN))
}

func (s *Scalar) Square() curves.Scalar {
	return &Scalar{
		V: fq.New().Square(s.V),
	}
}

func (s *Scalar) Cube() curves.Scalar {
	value := fq.New().Mul(s.V, s.V)
	value.Mul(value, s.V)
	return &Scalar{
		V: value,
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
		V: fq.New().Neg(s.V),
	}
}

func (s *Scalar) IsAdditiveInverse(of curves.Scalar) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (s *Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		return &Scalar{
			V: fq.New().Sub(s.V, r.V),
		}
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (s *Scalar) ApplySub(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Sub(x.Mul(reducedN))
}

// === Multiplicative Group Methods.

func (s *Scalar) MultiplicativeInverse() curves.Scalar {
	value, wasInverted := fq.New().Invert(s.V)
	if !wasInverted {
		panic(errs.NewFailed("inverse doesn't exist"))
	}
	return &Scalar{
		V: value,
	}
}

func (s *Scalar) IsMultiplicativeInverse(of curves.Scalar) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (s *Scalar) Div(rhs curves.Scalar) curves.Scalar {
	r, ok := rhs.(*Scalar)
	if ok {
		v, wasInverted := fq.New().Invert(r.V)
		if !wasInverted {
			panic("cannot invert rhs")
		}
		v.Mul(v, s.V)
		return &Scalar{V: v}
	} else {
		panic("rhs is not ScalarP256")
	}
}

func (s *Scalar) ApplyDiv(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Div(x.Exp(reducedN))
}

// === Ring Methods.

func (s *Scalar) Sqrt() (curves.Scalar, error) {
	value, wasSquare := fq.New().Sqrt(s.V)
	if !wasSquare {
		return nil, errs.NewFailed("not a square")
	}
	return &Scalar{
		V: value,
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
	exponent, ok := k.(*Scalar)
	if !ok {
		panic("rhs is not ScalarP256")
	}

	value := fq.New().Exp(s.V, exponent.V)
	return &Scalar{V: value}
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
	return s.V.Bytes()[0]&1 == 1
}

func (s *Scalar) IsEven() bool {
	return s.V.Bytes()[0]&1 == 0
}

func (s *Scalar) Increment() {
	ss, ok := s.Add(s.ScalarField().One()).(*Scalar)
	if !ok {
		panic("invalid type")
	}
	s.V = ss.V
}

func (s *Scalar) Decrement() {
	ss, ok := s.Sub(s.ScalarField().One()).(*Scalar)
	if !ok {
		panic("invalid type")
	}
	s.V = ss.V
}

// === Ordering Methods.

func (s *Scalar) Cmp(rhs curves.Scalar) algebra.Ordering {
	r, ok := rhs.(*Scalar)
	if ok {
		return algebra.Ordering(s.V.Cmp(r.V))
	} else {
		panic("rhs is not ScalarP256")
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

func (*Scalar) ScalarField() curves.ScalarField {
	return NewScalarField()
}

func (*Scalar) Curve() curves.Curve {
	return &p256Instance
}

func (*Scalar) CurveName() string {
	return Name
}

// === Serialisation.

func (s *Scalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (*Scalar) SetNat(v *saferith.Nat) curves.Scalar {
	if v == nil {
		return nil
	}
	value := fq.New().SetNat(v)
	return &Scalar{
		V: value,
	}
}

func (s *Scalar) Nat() *saferith.Nat {
	return s.V.Nat()
}

func (s *Scalar) Bytes() []byte {
	t := s.V.Bytes()
	return bitstring.ReverseBytes(t[:])
}

func (*Scalar) SetBytes(input []byte) (curves.Scalar, error) {
	if len(input) != base.FieldBytes {
		return nil, errs.NewLength("invalid length")
	}
	input = bitstring.ReverseBytes(input)
	value, err := fq.New().SetBytes((*[base.FieldBytes]byte)(input))
	if err != nil {
		return nil, errs.WrapFailed(err, "could not set bytes")
	}
	return &Scalar{
		V: value,
	}, nil
}

func (*Scalar) SetBytesWide(input []byte) (curves.Scalar, error) {
	if len(input) > base.WideFieldBytes {
		return nil, errs.NewLength("invalid length (%d > %d bytes)", len(input), base.WideFieldBytes)
	}
	input = bitstring.PadToRight(bitstring.ReverseBytes(input), base.WideFieldBytes-len(input))
	return &Scalar{
		V: fq.New().SetBytesWide((*[base.WideFieldBytes]byte)(input)),
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
	name, _, err := impl.ParseBinary(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != s.ScalarField().Name() {
		return errs.NewType("name %s is not supported", name)
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewType("invalid base field element")
	}
	s.V = ss.V
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
	sc, err := impl.UnmarshalJson(s.SetBytes, input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract a base field element from json")
	}
	name, _, err := impl.ParseJSON(input)
	if err != nil {
		return errs.WrapSerialisation(err, "could not extract name from input")
	}
	if name != s.ScalarField().Name() {
		return errs.NewType("name %s is not supported", name)
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
