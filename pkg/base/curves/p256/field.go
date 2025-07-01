package p256

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/num/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/cronokirby/saferith"
)

const (
	BaseFieldName = "P256Fp"
)

var (
	_ algebra.PrimeField[*BaseFieldElement]        = (*BaseField)(nil)
	_ algebra.PrimeFieldElement[*BaseFieldElement] = (*BaseFieldElement)(nil)

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

func (f *BaseField) Order() cardinal.Cardinal {
	return cardinal.NewFromNat(baseFieldOrder.Nat())
}

func (f *BaseField) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromNat(baseFieldOrder.Nat())
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
