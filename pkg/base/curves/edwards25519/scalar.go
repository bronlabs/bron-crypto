package edwards25519

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
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
	scalarFieldOrder = saferith.ModulusFromBytes(sliceutils.Reversed(edwards25519Impl.FqModulus[:]))
	scalarFieldInstance = &ScalarField{}
}

type ScalarField struct {
	traits.PrimeFieldTrait[*edwards25519Impl.Fq, *Scalar, Scalar]
}

func NewScalarField() *ScalarField {
	scalarFieldInitOnce.Do(scalarFieldInit)
	return scalarFieldInstance
}

func (f *ScalarField) Name() string {
	return ScalarFieldName
}

func (f *ScalarField) Order() algebra.Cardinal {
	return scalarFieldOrder.Nat()
}

func (f *ScalarField) Characteristic() algebra.Cardinal {
	return scalarFieldOrder.Nat()
}

func (f *ScalarField) Operator() algebra.BinaryOperator[*Scalar] {
	return algebra.Add[*Scalar]
}

func (f *ScalarField) OtherOperator() algebra.BinaryOperator[*Scalar] {
	return algebra.Mul[*Scalar]
}

func (f *ScalarField) Hash(bytes []byte) (*Scalar, error) {
	var e [1]edwards25519Impl.Fq
	h2c.HashToField(e[:], edwards25519Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, bytes)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

func (f *ScalarField) ElementSize() int {
	return edwards25519Impl.FqBytes
}

func (f *ScalarField) WideElementSize() int {
	return edwards25519Impl.FqWideBytes
}

type Scalar struct {
	traits.PrimeFieldElementTrait[*edwards25519Impl.Fq, edwards25519Impl.Fq, *Scalar, Scalar]
}

func NewScalar(v uint64) *Scalar {
	var s Scalar
	s.V.SetUint64(v)
	return &s
}

func (fe *Scalar) Structure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

func (fe *Scalar) MarshalBinary() (data []byte, err error) {
	return fe.V.Bytes(), nil
}

func (fe *Scalar) UnmarshalBinary(data []byte) error {
	if ok := fe.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("failed to unmarshal field element")
	}

	return nil
}
