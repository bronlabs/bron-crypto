package k256

import (
	"io"
	"sync"

	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
	"github.com/bronlabs/krypton-primitives/pkg/base/algebra2/fields"
	"github.com/bronlabs/krypton-primitives/pkg/base/bitstring"
	k256Impl "github.com/bronlabs/krypton-primitives/pkg/base/curves/k256/impl"
	"github.com/bronlabs/krypton-primitives/pkg/base/curves2/impl/traits"
	"github.com/cronokirby/saferith"
)

var (
	scalarFieldInitOnce sync.Once
	scalarFieldInstance ScalarField

	_ fields.PrimeField[*Scalar]        = (*ScalarField)(nil)
	_ fields.PrimeFieldElement[*Scalar] = (*Scalar)(nil)

	k256Order = saferith.ModulusFromBytes(bitstring.ReverseBytes(k256Impl.FqModulus[:]))
)

func scalarFieldInit() {
	scalarFieldInstance = ScalarField{}
}

func NewScalarField() ScalarField {
	scalarFieldInitOnce.Do(scalarFieldInit)
	return scalarFieldInstance
}

type ScalarField struct {
	traits.ScalarField[*k256Impl.Fq, k256Impl.Fq, *Scalar, Scalar]
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
	panic("implement me")
}

func (ScalarField) Hash(input []byte) (*Scalar, error) {
	panic("implement me")
}

func (f ScalarField) FromNat(v *saferith.Nat) (*Scalar, error) {
	return traits.NewScalarFromNat[*k256Impl.Fq, k256Impl.Fq, *Scalar](v, k256Order)
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
	s.Scalar.V = v
}

func (s *Scalar) UnmarshalBinary(data []byte) error {
	panic("implement me")
}
