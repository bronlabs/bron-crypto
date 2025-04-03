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
	BaseFieldNameG2 = "BLS12381Fp2"
)

var (
	// TODO(PrimeField)
	_ fields.FiniteField[*BaseFieldElementG2]        = (*BaseFieldG2)(nil)
	_ fields.FiniteFieldElement[*BaseFieldElementG2] = (*BaseFieldElementG2)(nil)

	baseFieldInstanceG2 *BaseFieldG2
	baseFieldInitOnceG2 sync.Once
)

type BaseFieldG2 struct {
	traits.FiniteFieldTrait[*bls12381Impl.Fp2, *BaseFieldElementG2, BaseFieldElementG2]
}

func NewG2BaseField() *BaseFieldG2 {
	baseFieldInitOnceG2.Do(func() {
		baseFieldInstanceG2 = &BaseFieldG2{}
	})

	return baseFieldInstanceG2
}

func (f *BaseFieldG2) Hash(bytes []byte) (*BaseFieldElementG2, error) {
	var e [1]bls12381Impl.Fp2
	h2c.HashToField(e[:], bls12381Impl.G2CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuiteG2, bytes)

	var s BaseFieldElementG2
	s.V.Set(&e[0])
	return &s, nil
}

func (f *BaseFieldG2) Name() string {
	return BaseFieldNameG2
}

func (f *BaseFieldG2) Order() algebra.Cardinal {
	g1Order := NewG1BaseField().Order()
	return new(saferith.Nat).Add(g1Order, g1Order, -1)
}

func (f *BaseFieldG2) Characteristic() algebra.Cardinal {
	return NewG1BaseField().Characteristic()
}

func (f *BaseFieldG2) ExtensionDegree() uint {
	return 2
}

func (f *BaseFieldG2) Operator() algebra.BinaryOperator[*BaseFieldElementG2] {
	return algebra.Add[*BaseFieldElementG2]
}

func (f *BaseFieldG2) ElementSize() int {
	return 2 * bls12381Impl.FpBytes
}

func (f *BaseFieldG2) WideElementSize() int {
	return 2 * bls12381Impl.FpWideBytes
}

func (f *BaseFieldG2) OtherOperator() algebra.BinaryOperator[*BaseFieldElementG2] {
	return algebra.Mul[*BaseFieldElementG2]
}

type BaseFieldElementG2 struct {
	traits.FiniteFieldElementTrait[*bls12381Impl.Fp2, bls12381Impl.Fp2, *BaseFieldElementG2, BaseFieldElementG2]
}

func (fe *BaseFieldElementG2) Structure() algebra.Structure[*BaseFieldElementG2] {
	return NewG2BaseField()
}

func (fe *BaseFieldElementG2) MarshalBinary() ([]byte, error) {
	return slices.Concat(fe.V.U1.Bytes(), fe.V.U0.Bytes()), nil
}

func (fe *BaseFieldElementG2) UnmarshalBinary(data []byte) error {
	if ok := fe.V.U1.SetBytes(data[:bls12381Impl.FpBytes]); ok == 0 {
		return errs.NewSerialisation("invalid data")
	}
	if ok := fe.V.U0.SetBytes(data[bls12381Impl.FpBytes:]); ok == 0 {
		return errs.NewSerialisation("invalid data")
	}
	return nil
}
