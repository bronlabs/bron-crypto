package p256

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	"github.com/cronokirby/saferith"
)

const (
	ScalarFieldName = "P256Fq"
)

var (
	_ fields.PrimeField[*Scalar]        = (*ScalarField)(nil)
	_ fields.PrimeFieldElement[*Scalar] = (*Scalar)(nil)

	scalarFieldInitOnce sync.Once
	scalarFieldInstance *ScalarField
	scalarFieldOrder    *saferith.Modulus
)

func scalarFieldInit() {
	orderBytes := make([]byte, len(p256Impl.FqModulus))
	copy(orderBytes, p256Impl.FqModulus[:])
	slices.Reverse(orderBytes)
	scalarFieldOrder = saferith.ModulusFromBytes(orderBytes)
	scalarFieldInstance = &ScalarField{}
}

type ScalarField struct {
	traits.PrimeFieldTrait[*p256Impl.Fq, *Scalar, Scalar]
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
	var e [1]p256Impl.Fq
	h2c.HashToField(e[:], p256Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, bytes)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

func (f *ScalarField) ElementSize() int {
	return k256Impl.FqBytes
}

func (f *ScalarField) WideElementSize() int {
	return k256Impl.FqWideBytes
}

type Scalar struct {
	traits.PrimeFieldElementTrait[*p256Impl.Fq, p256Impl.Fq, *Scalar, Scalar]
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
