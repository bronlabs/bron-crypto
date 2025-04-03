package bls12381

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/cronokirby/saferith"
	"sync"
)

const (
	BaseFieldNameG1 = "BLS12381Fp"
)

var (
	_ fields.PrimeField[*BaseFieldElementG1]        = (*BaseFieldG1)(nil)
	_ fields.PrimeFieldElement[*BaseFieldElementG1] = (*BaseFieldElementG1)(nil)

	baseFieldInstanceG1 *BaseFieldG1
	baseFieldInitOnceG1 sync.Once
	baseFieldOrderG1    *saferith.Modulus
)

type BaseFieldG1 struct {
	traits.PrimeFieldTrait[*bls12381Impl.Fp, *BaseFieldElementG1, BaseFieldElementG1]
}

func NewG1BaseField() *BaseFieldG1 {
	baseFieldInitOnceG1.Do(func() {
		baseFieldOrderG1 = saferith.ModulusFromBytes(sliceutils.Reversed(bls12381Impl.FpModulus[:]))
		baseFieldInstanceG1 = &BaseFieldG1{}
	})

	return baseFieldInstanceG1
}

func (f *BaseFieldG1) Name() string {
	return BaseFieldNameG1
}

func (f *BaseFieldG1) Order() algebra.Cardinal {
	return baseFieldOrderG1.Nat()
}

func (f *BaseFieldG1) Characteristic() algebra.Cardinal {
	return baseFieldOrderG1.Nat()
}

func (f *BaseFieldG1) Operator() algebra.BinaryOperator[*BaseFieldElementG1] {
	return algebra.Add[*BaseFieldElementG1]
}

func (f *BaseFieldG1) OtherOperator() algebra.BinaryOperator[*BaseFieldElementG1] {
	return algebra.Mul[*BaseFieldElementG1]
}

func (f *BaseFieldG1) Hash(bytes []byte) (*BaseFieldElementG1, error) {
	var e [1]bls12381Impl.Fp
	h2c.HashToField(e[:], bls12381Impl.G1CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuiteG1, bytes)

	var s BaseFieldElementG1
	s.V.Set(&e[0])
	return &s, nil
}

func (f *BaseFieldG1) ElementSize() int {
	return bls12381Impl.FpBytes
}

func (f *BaseFieldG1) WideElementSize() int {
	return bls12381Impl.FpWideBytes
}

type BaseFieldElementG1 struct {
	traits.PrimeFieldElementTrait[*bls12381Impl.Fp, bls12381Impl.Fp, *BaseFieldElementG1, BaseFieldElementG1]
}

func (fe *BaseFieldElementG1) Structure() algebra.Structure[*BaseFieldElementG1] {
	return NewG1BaseField()
}

func (fe *BaseFieldElementG1) MarshalBinary() (data []byte, err error) {
	return fe.V.Bytes(), nil
}

func (fe *BaseFieldElementG1) UnmarshalBinary(data []byte) error {
	if ok := fe.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("failed to unmarshal field element")
	}

	return nil
}
