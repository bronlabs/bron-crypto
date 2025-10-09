package edwards25519

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/cronokirby/saferith"
)

const (
	BaseFieldName = "curve25519Fp"
)

var (
	// TODO(PrimeField)
	_ algebra.PrimeField[*BaseFieldElement]        = (*BaseField)(nil)
	_ algebra.PrimeFieldElement[*BaseFieldElement] = (*BaseFieldElement)(nil)

	baseFieldInstance *BaseField
	baseFieldInitOnce sync.Once
	baseFieldOrder    *saferith.Modulus
)

type BaseField struct {
	traits.PrimeFieldTrait[*edwards25519Impl.Fp, *BaseFieldElement, BaseFieldElement]
}

func NewBaseField() *BaseField {
	baseFieldInitOnce.Do(func() {
		baseFieldOrder = saferith.ModulusFromBytes(sliceutils.Reversed(edwards25519Impl.FpModulus[:]))
		baseFieldInstance = &BaseField{}
	})

	return baseFieldInstance
}

func (f *BaseField) Name() string {
	return BaseFieldName
}

func (f *BaseField) Order() cardinal.Cardinal {
	return cardinal.NewFromSaferith(baseFieldOrder.Nat())
}

func (f *BaseField) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromSaferith(baseFieldOrder.Nat())
}

func (f *BaseField) Hash(bytes []byte) (*BaseFieldElement, error) {
	var e [1]edwards25519Impl.Fp
	h2c.HashToField(e[:], edwards25519Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuite, bytes)

	var s BaseFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

func (f *BaseField) ElementSize() int {
	return int(edwards25519Impl.FpBytes)
}

func (f *BaseField) WideElementSize() int {
	return int(edwards25519Impl.FpWideBytes)
}

type BaseFieldElement struct {
	traits.PrimeFieldElementTrait[*edwards25519Impl.Fp, edwards25519Impl.Fp, *BaseFieldElement, BaseFieldElement]
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
