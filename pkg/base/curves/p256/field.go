package p256

import (
	"encoding"
	"slices"
	"sync"

	"github.com/cronokirby/saferith"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

const (
	BaseFieldName = "P256Fp"
)

var (
	_ algebra.PrimeField[*BaseFieldElement]        = (*BaseField)(nil)
	_ algebra.PrimeFieldElement[*BaseFieldElement] = (*BaseFieldElement)(nil)
	_ encoding.BinaryMarshaler                     = (*BaseFieldElement)(nil)
	_ encoding.BinaryUnmarshaler                   = (*BaseFieldElement)(nil)

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
	return cardinal.NewFromSaferith(baseFieldOrder.Nat())
}

func (f *BaseField) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromSaferith(baseFieldOrder.Nat())
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

func (f *BaseField) BitLen() int {
	return p256Impl.FpBits
}

func (f *BaseField) FromNat(n *numct.Nat) (*BaseFieldElement, error) {
	var v numct.Nat
	m, ok := numct.NewModulusOddPrime((*numct.Nat)(baseFieldOrder.Nat()))
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create modulus")
	}
	m.Mod(&v, n)
	vBytes := v.Bytes()
	slices.Reverse(vBytes)
	var s BaseFieldElement
	if ok := s.V.SetBytesWide(vBytes); ok == ct.False {
		return nil, errs.NewFailed("failed to set scalar from nat")
	}
	return &s, nil
}

func (f *BaseField) FromNumeric(n algebra.Numeric) (*BaseFieldElement, error) {
	var v numct.Nat
	m, ok := numct.NewModulusOddPrime((*numct.Nat)(baseFieldOrder.Nat()))
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create modulus")
	}
	var nNat numct.Nat
	nNat.SetBytes(n.BytesBE())
	m.Mod(&v, &nNat)
	vBytes := v.Bytes()
	slices.Reverse(vBytes)
	var fe BaseFieldElement
	if ok := fe.V.SetBytesWide(vBytes); ok == ct.False {
		return nil, errs.NewFailed("failed to set scalar from numeric")
	}
	return &fe, nil
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
