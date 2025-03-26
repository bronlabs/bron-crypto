package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"io"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"github.com/cronokirby/saferith"
)

const (
	ScalarFieldName       = "BLS12381Fq"
	Hash2CurveScalarSuite = "BLS12381G1_XMD:SHA-256_SSWU_RO_SC_"
)

var (
	_ fields.PrimeField[*Scalar]        = (*ScalarField)(nil)
	_ fields.PrimeFieldElement[*Scalar] = (*Scalar)(nil)

	scalarFieldInitOnce sync.Once
	scalarFieldInstance *ScalarField
	scalarFieldOrder    *saferith.Modulus
)

func scalarFieldInit() {
	orderBytes := make([]byte, len(bls12381Impl.FqModulus))
	copy(orderBytes, bls12381Impl.FqModulus[:])
	slices.Reverse(orderBytes)
	scalarFieldOrder = saferith.ModulusFromBytes(orderBytes)
	scalarFieldInstance = &ScalarField{}
}

type ScalarField struct {
	traits.ScalarField[*bls12381Impl.Fq, *Scalar, Scalar]
}

func NewScalarField() *ScalarField {
	scalarFieldInitOnce.Do(scalarFieldInit)
	return scalarFieldInstance
}

func (*ScalarField) Name() string {
	return ScalarFieldName
}

func (*ScalarField) Operator() algebra.BinaryOperator[*Scalar] {
	return algebra.Add[*Scalar]
}

func (*ScalarField) OtherOperator() algebra.BinaryOperator[*Scalar] {
	return algebra.Mul[*Scalar]
}

func (*ScalarField) ExtensionDegree() uint {
	return 1
}

func (*ScalarField) ElementSize() int {
	return bls12381Impl.FqBytes
}

func (*ScalarField) WideElementSize() int {
	return bls12381Impl.FqWideBytes
}

func (f *ScalarField) Characteristic() algebra.Cardinal {
	return f.Order()
}

func (*ScalarField) Order() algebra.Cardinal {
	return scalarFieldOrder.Nat()
}

func (*ScalarField) Random(prng io.Reader) (*Scalar, error) {
	var e Scalar
	ok := e.V.SetRandom(prng)
	if ok == 0 {
		return nil, errs.NewRandomSample("cannot sample scalar")
	}

	return &e, nil
}

func (*ScalarField) Hash(input []byte) (*Scalar, error) {
	var e [1]bls12381Impl.Fq
	h2c.HashToField(e[:], bls12381Impl.G1CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, input)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

func (f *ScalarField) FromNat(v *saferith.Nat) (*Scalar, error) {
	return traits.NewScalarFromNat[*bls12381Impl.Fq, *Scalar, Scalar](v, scalarFieldOrder)
}

type Scalar struct {
	traits.Scalar[*bls12381Impl.Fq, bls12381Impl.Fq, *Scalar, Scalar]
}

func (s *Scalar) Structure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (s *Scalar) Fq() *bls12381Impl.Fq {
	return &s.Scalar.V
}

func (s *Scalar) SetFq(v bls12381Impl.Fq) {
	s.Scalar.V.Set(&v)
}

func (s *Scalar) UnmarshalBinary(data []byte) error {
	if ok := s.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("cannot unmarshal scalar")
	}

	return nil
}
