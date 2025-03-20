package k256

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/cronokirby/saferith"
	"slices"
	"sync"
)

const (
	BaseFieldName = "secp256k1Fp"
)

var (
	_ fields.FiniteField[*BaseFieldElement]        = (*BaseField)(nil)
	_ fields.FiniteFieldElement[*BaseFieldElement] = (*BaseFieldElement)(nil)

	baseFieldInstance *BaseField
	baseFieldInitOnce sync.Once
	baseFieldOrder    *saferith.Modulus
)

type BaseField struct {
	traits.BaseField[*k256Impl.Fp, *BaseFieldElement, BaseFieldElement]
}

func NewBaseField() *BaseField {
	baseFieldInitOnce.Do(func() {
		orderBytes := make([]byte, len(k256Impl.FpModulus))
		copy(orderBytes, k256Impl.FpModulus[:])
		slices.Reverse(orderBytes)
		baseFieldOrder = saferith.ModulusFromBytes(orderBytes)
		baseFieldInstance = &BaseField{}
	})

	return baseFieldInstance
}

func (f *BaseField) FromBytes(data []byte) (*BaseFieldElement, error) {
	leData := make([]byte, len(data))
	copy(leData, data)
	slices.Reverse(leData)

	var e BaseFieldElement
	if ok := e.V.SetBytes(data); ok == 0 {
		return nil, errs.NewFailed("invalid data")
	}
	return &e, nil
}

func (f *BaseField) Hash(bytes []byte) (*BaseFieldElement, error) {
	var e [1]k256Impl.Fp
	h2c.HashToField(e[:], k256Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuite, bytes)

	var s BaseFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

func (f *BaseField) Name() string {
	return BaseFieldName
}

func (f *BaseField) Order() algebra.Cardinal {
	return baseFieldOrder.Nat()
}

func (f *BaseField) Operator() algebra.BinaryOperator[*BaseFieldElement] {
	return algebra.Add[*BaseFieldElement]
}

func (f *BaseField) OtherOperator() algebra.BinaryOperator[*BaseFieldElement] {
	return algebra.Mul[*BaseFieldElement]
}

func (f *BaseField) Characteristic() algebra.Cardinal {
	return baseFieldOrder.Nat()
}

func (f *BaseField) ExtensionDegree() uint {
	return 1
}

func (f *BaseField) ElementSize() int {
	return k256Impl.FpBytes
}

func (f *BaseField) WideElementSize() int {
	return k256Impl.FpWideBytes
}

type BaseFieldElement struct {
	traits.BaseFieldElement[*k256Impl.Fp, k256Impl.Fp, *BaseFieldElement, BaseFieldElement]
}

func (fp *BaseFieldElement) Structure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

func (fp *BaseFieldElement) MarshalBinary() (data []byte, err error) {
	return fp.V.Bytes(), nil
}

func (fp *BaseFieldElement) UnmarshalBinary(data []byte) error {
	if ok := fp.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("cannot unmarshal field element")
	}

	return nil
}

func (fp *BaseFieldElement) Bytes() []byte {
	return fp.ComponentsBytes()[0]
}

func (fp *BaseFieldElement) Fp() *k256Impl.Fp {
	return &fp.V
}
