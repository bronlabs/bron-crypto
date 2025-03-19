package k256

import (
	"encoding"
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"io"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/cronokirby/saferith"
)

var (
	scalarFieldInitOnce sync.Once
	scalarFieldInstance ScalarField

	_ fields.PrimeField[*Scalar]        = (*ScalarField)(nil)
	_ fields.PrimeFieldElement[*Scalar] = (*Scalar)(nil)
	_ encoding.BinaryMarshaler          = (*Scalar)(nil)

	k256Order *saferith.Modulus
)

func scalarFieldInit() {
	orderBytes := make([]byte, len(k256Impl.FqModulus))
	copy(orderBytes, k256Impl.FqModulus[:])
	slices.Reverse(orderBytes)
	k256Order = saferith.ModulusFromBytes(orderBytes)
	scalarFieldInstance = ScalarField{}
}

func NewScalarField() ScalarField {
	scalarFieldInitOnce.Do(scalarFieldInit)
	return scalarFieldInstance
}

type ScalarField struct {
	traits.ScalarField[*k256Impl.Fq, *Scalar, Scalar]
}

func (ScalarField) Name() string {
	return Name
}

func (ScalarField) Operator() algebra.BinaryOperator[*Scalar] {
	return algebra.Add[*Scalar]
}

func (ScalarField) OtherOperator() algebra.BinaryOperator[*Scalar] {
	return algebra.Mul[*Scalar]
}

func (ScalarField) ExtensionDegree() uint {
	return 1
}

func (ScalarField) ElementSize() int {
	return k256Impl.FqBytes
}

func (ScalarField) WideElementSize() int {
	return k256Impl.FqWideBytes
}

func (f ScalarField) Characteristic() algebra.Cardinal {
	return f.Order()
}

func (ScalarField) Order() algebra.Cardinal {
	return k256Order.Nat()
}

func (ScalarField) Random(prng io.Reader) (*Scalar, error) {
	var e Scalar
	ok := e.V.SetRandom(prng)
	if ok == 0 {
		return nil, errs.NewRandomSample("cannot sample scalar")
	}

	return &e, nil
}

func (ScalarField) Hash(input []byte) (*Scalar, error) {
	var e [1]k256Impl.Fq
	h2c.HashToField(e[:], k256Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, input)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

func (f ScalarField) FromNat(v *saferith.Nat) (*Scalar, error) {
	return traits.NewScalarFromNat[*k256Impl.Fq, *Scalar, Scalar](v, k256Order)
}

type Scalar struct {
	traits.Scalar[*k256Impl.Fq, k256Impl.Fq, *Scalar, Scalar]
}

func (s *Scalar) Structure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (s *Scalar) Fq() *k256Impl.Fq {
	return &s.Scalar.V
}

func (s *Scalar) SetFq(v k256Impl.Fq) {
	s.Scalar.V.Set(&v)
}

func (s *Scalar) UnmarshalBinary(data []byte) error {
	if ok := s.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("cannot unmarshal scalar")
	}

	return nil
}
