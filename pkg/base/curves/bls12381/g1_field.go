package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
	"slices"
	"sync"
)

const (
	BaseFieldNameG1 = "BLS12381Fp"
)

var (
	// TODO(PrimeField)
	_ fields.FiniteField[*BaseFieldElementG1]        = (*BaseFieldG1)(nil)
	_ fields.FiniteFieldElement[*BaseFieldElementG1] = (*BaseFieldElementG1)(nil)

	baseFieldInstanceG1 *BaseFieldG1
	baseFieldInitOnceG1 sync.Once
	baseFieldOrderG1    *saferith.Modulus
)

type BaseFieldG1 struct {
	traits.BaseField[*bls12381Impl.Fp, *BaseFieldElementG1, BaseFieldElementG1]
}

func NewG1BaseField() *BaseFieldG1 {
	baseFieldInitOnceG1.Do(func() {
		orderBytes := make([]byte, len(bls12381Impl.FpModulus))
		copy(orderBytes, bls12381Impl.FpModulus[:])
		slices.Reverse(orderBytes)
		baseFieldOrderG1 = saferith.ModulusFromBytes(orderBytes)
		baseFieldInstanceG1 = &BaseFieldG1{}
	})

	return baseFieldInstanceG1
}

func (f *BaseFieldG1) FromBytes(data []byte) (*BaseFieldElementG1, error) {
	leData := make([]byte, len(data))
	copy(leData, data)
	slices.Reverse(leData)

	var e BaseFieldElementG1
	if ok := e.V.SetBytes(data); ok == 0 {
		return nil, errs.NewFailed("invalid data")
	}
	return &e, nil
}

func (f *BaseFieldG1) Hash(bytes []byte) (*BaseFieldElementG1, error) {
	var e [1]bls12381Impl.Fp
	h2c.HashToField(e[:], bls12381Impl.G1CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuiteG1, bytes)

	var s BaseFieldElementG1
	s.V.Set(&e[0])
	return &s, nil
}

func (f *BaseFieldG1) Name() string {
	return BaseFieldNameG1
}

func (f *BaseFieldG1) Order() algebra.Cardinal {
	return baseFieldOrderG1.Nat()
}

func (f *BaseFieldG1) Operator() algebra.BinaryOperator[*BaseFieldElementG1] {
	return algebra.Add[*BaseFieldElementG1]
}

func (f *BaseFieldG1) OtherOperator() algebra.BinaryOperator[*BaseFieldElementG1] {
	return algebra.Mul[*BaseFieldElementG1]
}

func (f *BaseFieldG1) Characteristic() algebra.Cardinal {
	return baseFieldOrderG1.Nat()
}

func (f *BaseFieldG1) ExtensionDegree() uint {
	return 1
}

func (f *BaseFieldG1) ElementSize() int {
	return bls12381Impl.FpBytes
}

func (f *BaseFieldG1) WideElementSize() int {
	return bls12381Impl.FpWideBytes
}

type BaseFieldElementG1 struct {
	traits.BaseFieldElement[*bls12381Impl.Fp, bls12381Impl.Fp, *BaseFieldElementG1, BaseFieldElementG1]
}

func (fp *BaseFieldElementG1) Structure() algebra.Structure[*BaseFieldElementG1] {
	return NewG1BaseField()
}

func (fp *BaseFieldElementG1) MarshalBinary() (data []byte, err error) {
	return fp.V.Bytes(), nil
}

func (fp *BaseFieldElementG1) UnmarshalBinary(data []byte) error {
	if ok := fp.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("cannot unmarshal field element")
	}

	return nil
}

func (fp *BaseFieldElementG1) Bytes() []byte {
	return fp.ComponentsBytes()[0]
}

func (fp *BaseFieldElementG1) Fp() *bls12381Impl.Fp {
	return &fp.V
}
