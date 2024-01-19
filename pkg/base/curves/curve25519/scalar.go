package curve25519

import (
	"crypto/subtle"
	"encoding"
	"encoding/binary"
	"encoding/json"

	"github.com/cronokirby/saferith"

	"github.com/copperexchange/krypton-primitives/pkg/base"
	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
	"github.com/copperexchange/krypton-primitives/pkg/base/types"
)

var _ curves.Scalar = (*Scalar)(nil)
var _ encoding.BinaryMarshaler = (*Scalar)(nil)
var _ encoding.BinaryUnmarshaler = (*Scalar)(nil)
var _ json.Unmarshaler = (*Scalar)(nil)

type Scalar struct {
	V [32]byte

	_ types.Incomparable
}

func NewScalar(input uint64) *Scalar {
	s := make([]byte, 32)
	binary.LittleEndian.PutUint64(s, input)
	var scalar [32]byte
	copy(scalar[:], s)
	return &Scalar{V: scalar}
}

// === Basic Methods.

func (s *Scalar) Equal(rhs curves.Scalar) bool {
	r, ok := rhs.(*Scalar)
	return ok && subtle.ConstantTimeCompare(s.V[:], r.V[:]) == 1
}

func (s *Scalar) Clone() curves.Scalar {
	return &Scalar{
		V: s.V,
	}
}

// === Additive Groupoid Methods.

func (*Scalar) Add(rhs curves.Scalar) curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) ApplyAdd(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Add(x.Mul(reducedN))
}

func (*Scalar) Double() curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) Triple() curves.Scalar {
	return s.Double().Add(s)
}

// === Multiplicative Groupoid Methods.

func (*Scalar) Mul(rhs curves.Scalar) curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) ApplyMul(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Mul(x.Exp(reducedN))
}

func (*Scalar) Square() curves.Scalar {
	panic("not implemented")
}

func (*Scalar) Cube() curves.Scalar {
	panic("not implemented")
}

// === Additive Monoid Methods.

func (*Scalar) IsAdditiveIdentity() bool {
	panic("not implemented")
}

// === Multiplicative Monoid Methods.

func (*Scalar) IsMultiplicativeIdentity() bool {
	panic("not implemented")
}

// === Additive Group Methods.

func (*Scalar) AdditiveInverse() curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) IsAdditiveInverse(of curves.Scalar) bool {
	return s.Add(of).IsAdditiveIdentity()
}

func (*Scalar) Sub(rhs curves.Scalar) curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) ApplySub(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Sub(x.Mul(reducedN))
}

// === Multiplicative Group Methods.

func (*Scalar) MultiplicativeInverse() curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) IsMultiplicativeInverse(of curves.Scalar) bool {
	return s.Mul(of).IsMultiplicativeIdentity()
}

func (*Scalar) Div(rhs curves.Scalar) curves.Scalar {
	panic("not implemented")
}

func (s *Scalar) ApplyDiv(x curves.Scalar, n *saferith.Nat) curves.Scalar {
	reducedN := new(Scalar).SetNat(n)
	return s.Div(x.Exp(reducedN))
}

// === Ring Methods.

func (*Scalar) Sqrt() (curves.Scalar, error) {
	panic("not implemented")
}

func (*Scalar) MulAdd(y, z curves.Scalar) curves.Scalar {
	panic("not implemented")
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
	v := NewScalarField().One()
	for i := NewScalarField().Zero(); i.Cmp(k) < 0; i = i.Add(NewScalarField().One()) {
		v = v.Mul(s)
	}
	return v
}

func (s *Scalar) Neg() curves.Scalar {
	return s.AdditiveInverse()
}

func (s *Scalar) IsZero() bool {
	return s.IsAdditiveIdentity()
}

func (s *Scalar) IsOne() bool {
	return s.IsMultiplicativeIdentity()
}

func (*Scalar) IsOdd() bool {
	panic("not implemented")
}

func (*Scalar) IsEven() bool {
	panic("not implemented")
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

func (*Scalar) Cmp(rhs curves.Scalar) algebra.Ordering {
	panic("not implemented")
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

// === Serialisation.

func (s *Scalar) Uint64() uint64 {
	return s.Nat().Big().Uint64()
}

func (*Scalar) SetNat(x *saferith.Nat) curves.Scalar {
	panic("not implemented")
}

func (*Scalar) Nat() *saferith.Nat {
	panic("not implemented")
}

func (s *Scalar) Bytes() []byte {
	return s.V[:]
}

func (*Scalar) SetBytesWide(input []byte) (sc curves.Scalar, err error) {
	panic("not implemented")
}

func (*Scalar) SetBytes(input []byte) (sc curves.Scalar, err error) {
	var ss [base.FieldBytes]byte
	copy(ss[:], input)
	return &Scalar{V: ss}, nil
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
		return errs.NewInvalidType("name %s is not supported", name)
	}
	ss, ok := sc.(*Scalar)
	if !ok {
		return errs.NewInvalidType("invalid base field element")
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
		return errs.NewInvalidType("name %s is not supported", name)
	}
	S, ok := sc.(*Scalar)
	if !ok {
		return errs.NewFailed("invalid type")
	}
	s.V = S.V
	return nil
}
