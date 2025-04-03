package p256

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/cronokirby/saferith"
	"sync"
)

const (
	BaseFieldName = "P256Fp"
)

var (
	_ fields.PrimeField[*BaseFieldElement]        = (*BaseField)(nil)
	_ fields.PrimeFieldElement[*BaseFieldElement] = (*BaseFieldElement)(nil)

	baseFieldInstance *BaseField
	baseFieldInitOnce sync.Once
	baseFieldOrder    *saferith.Modulus
)

type BaseField struct {
	traits.PrimeFieldTrait[*p256Impl.Fp, *BaseFieldElement, BaseFieldElement]
}

func NewBaseField() *BaseField {
	baseFieldInitOnce.Do(func() {
		baseFieldOrder = saferith.ModulusFromBytes(sliceutils.Reversed(p256Impl.FpModulus[:]))
		baseFieldInstance = &BaseField{}
	})

	return baseFieldInstance
}

func (f *BaseField) Name() string {
	return BaseFieldName
}

func (f *BaseField) Order() algebra.Cardinal {
	return baseFieldOrder.Nat()
}

func (f *BaseField) Characteristic() algebra.Cardinal {
	return baseFieldOrder.Nat()
}

func (f *BaseField) Operator() algebra.BinaryOperator[*BaseFieldElement] {
	return algebra.Add[*BaseFieldElement]
}

func (f *BaseField) OtherOperator() algebra.BinaryOperator[*BaseFieldElement] {
	return algebra.Mul[*BaseFieldElement]
}

func (f *BaseField) Hash(bytes []byte) (*BaseFieldElement, error) {
	var e [1]p256Impl.Fp
	h2c.HashToField(e[:], p256Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuite, bytes)

	var s BaseFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

func (f *BaseField) ElementSize() int {
	return p256Impl.FpBytes
}

func (f *BaseField) WideElementSize() int {
	return p256Impl.FpWideBytes
}

type BaseFieldElement struct {
	traits.PrimeFieldElementTrait[*p256Impl.Fp, p256Impl.Fp, *BaseFieldElement, BaseFieldElement]
}

func (fe *BaseFieldElement) Structure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

func (fe *BaseFieldElement) MarshalBinary() (data []byte, err error) {
	return fe.V.Bytes(), nil
}

func (fe *BaseFieldElement) UnmarshalBinary(data []byte) error {
	if ok := fe.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("failed to unmarshal field element")
	}

	return nil
}
