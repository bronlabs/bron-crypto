package edwards25519

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
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	"github.com/cronokirby/saferith"
)

const (
	ScalarFieldName = "curve25519Fq"
)

var (
	_ fields.PrimeField[*Scalar]        = (*ScalarField)(nil)
	_ fields.PrimeFieldElement[*Scalar] = (*Scalar)(nil)

	scalarFieldInitOnce sync.Once
	scalarFieldInstance *ScalarField
	scalarFieldOrder    *saferith.Modulus
)

func scalarFieldInit() {
	orderBytes := make([]byte, len(edwards25519Impl.FqModulus))
	copy(orderBytes, edwards25519Impl.FqModulus[:])
	slices.Reverse(orderBytes)
	scalarFieldOrder = saferith.ModulusFromBytes(orderBytes)
	scalarFieldInstance = &ScalarField{}
}

type ScalarField struct {
	traits.ScalarField[*edwards25519Impl.Fq, *Scalar, Scalar]
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
	return edwards25519Impl.FqBytes
}

func (*ScalarField) WideElementSize() int {
	return edwards25519Impl.FqWideBytes
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
	var e [1]edwards25519Impl.Fq
	h2c.HashToField(e[:], edwards25519Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, input)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

func (f *ScalarField) FromNat(v *saferith.Nat) (*Scalar, error) {
	return traits.NewScalarFromNat[*edwards25519Impl.Fq, *Scalar, Scalar](v, scalarFieldOrder)
}

type Scalar struct {
	traits.Scalar[*edwards25519Impl.Fq, edwards25519Impl.Fq, *Scalar, Scalar]
}

func NewScalar(value uint64) *Scalar {
	var sc Scalar
	sc.V.SetUint64(value)
	return &sc
}

func (s *Scalar) Structure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (s *Scalar) Fq() *edwards25519Impl.Fq {
	return &s.Scalar.V
}

func (s *Scalar) SetFq(v edwards25519Impl.Fq) {
	s.Scalar.V.Set(&v)
}

func (s *Scalar) UnmarshalBinary(data []byte) error {
	if ok := s.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("cannot unmarshal scalar")
	}

	return nil
}
