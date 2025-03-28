package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"sync"
)

const (
	BaseFieldName = "BLS12381Fp2"
)

var (
	_ fields.FiniteField[*BaseFieldElementG2]        = (*BaseFieldG2)(nil)
	_ fields.FiniteFieldElement[*BaseFieldElementG2] = (*BaseFieldElementG2)(nil)

	baseFieldInstanceG2 *BaseFieldG2
	baseFieldInitOnceG2 sync.Once
)

type BaseFieldG2 struct {
	traits.BaseField[*bls12381Impl.Fp2, *BaseFieldElementG2, BaseFieldElementG2]
}

func NewG2BaseField() *BaseFieldG2 {
	baseFieldInitOnceG2.Do(func() {
		baseFieldInstanceG2 = &BaseFieldG2{}
	})

	return baseFieldInstanceG2
}

func (f *BaseFieldG2) FromBytes(data []byte) (*BaseFieldElementG2, error) {
	panic("not implemented")
}

func (f *BaseFieldG2) Hash(bytes []byte) (*BaseFieldElementG2, error) {
	var e [1]bls12381Impl.Fp2
	h2c.HashToField(e[:], bls12381Impl.G2CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuiteG2, bytes)

	var s BaseFieldElementG2
	s.V.Set(&e[0])
	return &s, nil
}

func (f *BaseFieldG2) Name() string {
	return BaseFieldName
}

func (f *BaseFieldG2) Order() algebra.Cardinal {
	panic("not implemented")
}

func (f *BaseFieldG2) Operator() algebra.BinaryOperator[*BaseFieldElementG2] {
	return algebra.Add[*BaseFieldElementG2]
}

func (f *BaseFieldG2) OtherOperator() algebra.BinaryOperator[*BaseFieldElementG2] {
	return algebra.Mul[*BaseFieldElementG2]
}

func (f *BaseFieldG2) Characteristic() algebra.Cardinal {
	return NewG1BaseField().Order()
}

func (f *BaseFieldG2) ExtensionDegree() uint {
	return 2
}

func (f *BaseFieldG2) ElementSize() int {
	return bls12381Impl.FpBytes * 2
}

func (f *BaseFieldG2) WideElementSize() int {
	return bls12381Impl.FpWideBytes * 2
}

type BaseFieldElementG2 struct {
	traits.BaseFieldElement[*bls12381Impl.Fp2, bls12381Impl.Fp2, *BaseFieldElementG2, BaseFieldElementG2]
}

func (fp *BaseFieldElementG2) Structure() algebra.Structure[*BaseFieldElementG2] {
	return NewG2BaseField()
}

func (fp *BaseFieldElementG2) MarshalBinary() (data []byte, err error) {
	panic("not implemented")
}

func (fp *BaseFieldElementG2) UnmarshalBinary(data []byte) error {
	panic("not implemented")
}

func (fp *BaseFieldElementG2) Bytes() []byte {
	panic("not implemented")
}

func (fp *BaseFieldElementG2) Fp() *bls12381Impl.Fp2 {
	return &fp.V
}
