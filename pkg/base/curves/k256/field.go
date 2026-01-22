package k256

import (
	"encoding"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/errs-go/pkg/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

const (
	// BaseFieldName is the base field name.
	BaseFieldName = "secp256k1Fp"
)

var (
	_ algebra.PrimeField[*BaseFieldElement]        = (*BaseField)(nil)
	_ algebra.PrimeFieldElement[*BaseFieldElement] = (*BaseFieldElement)(nil)
	_ encoding.BinaryMarshaler                     = (*BaseFieldElement)(nil)
	_ encoding.BinaryUnmarshaler                   = (*BaseFieldElement)(nil)

	baseFieldInstance *BaseField
	baseFieldInitOnce sync.Once
	baseFieldOrder    *numct.Modulus
)

// BaseField represents the curve base field.
type BaseField struct {
	traits.PrimeFieldTrait[*k256Impl.Fp, *BaseFieldElement, BaseFieldElement]
}

// NewBaseField returns the base field instance.
func NewBaseField() *BaseField {
	baseFieldInitOnce.Do(func() {
		baseFieldOrder, _ = numct.NewModulusFromBytesBE(sliceutils.Reversed(k256Impl.FpModulus[:]))
		//nolint:exhaustruct // no need for a trait
		baseFieldInstance = &BaseField{}
	})

	return baseFieldInstance
}

// Name returns the name of the structure.
func (*BaseField) Name() string {
	return BaseFieldName
}

// Order returns the group or field order.
func (*BaseField) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(baseFieldOrder.Nat())
}

// Characteristic returns the field characteristic.
func (*BaseField) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromNumeric(baseFieldOrder.Nat())
}

// Hash maps input bytes to an element or point.
func (*BaseField) Hash(bytes []byte) (*BaseFieldElement, error) {
	var e [1]k256Impl.Fp
	h2c.HashToField(e[:], k256Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuite, bytes)

	var s BaseFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

// ElementSize returns the element size in bytes.
func (*BaseField) ElementSize() int {
	return k256Impl.FpBytes
}

// WideElementSize returns the wide element size in bytes.
func (*BaseField) WideElementSize() int {
	return k256Impl.FpWideBytes
}

// BitLen returns the field modulus bit length.
func (*BaseField) BitLen() int {
	return k256Impl.FpBits
}

// FromBytesBEReduce reduces a big-endian integer into the field.
func (f *BaseField) FromBytesBEReduce(input []byte) (*BaseFieldElement, error) {
	var v numct.Nat
	var nNat numct.Nat
	nNat.SetBytes(input)
	baseFieldOrder.Mod(&v, &nNat)
	vBytes := v.Bytes()
	out, err := f.FromBytesBE(vBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert reduced bytes into field element")
	}
	return out, nil
}

// BaseFieldElement represents an element of the base field.
type BaseFieldElement struct {
	traits.PrimeFieldElementTrait[*k256Impl.Fp, k256Impl.Fp, *BaseFieldElement, BaseFieldElement]
}

// Structure returns the algebraic structure for the receiver.
func (*BaseFieldElement) Structure() algebra.Structure[*BaseFieldElement] {
	return NewBaseField()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (fe *BaseFieldElement) MarshalBinary() (data []byte, err error) {
	return fe.V.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (fe *BaseFieldElement) UnmarshalBinary(data []byte) error {
	if ok := fe.V.SetBytes(data); ok == 0 {
		return curves.ErrSerialisation.WithMessage("failed to unmarshal field element")
	}

	return nil
}
