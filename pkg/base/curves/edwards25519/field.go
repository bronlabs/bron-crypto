package edwards25519

import (
	"encoding"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

const (
	// BaseFieldName is the base field name.
	BaseFieldName = "curve25519Fp"
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
	traits.PrimeFieldTrait[*edwards25519Impl.Fp, *BaseFieldElement, BaseFieldElement]
}

// NewBaseField returns the base field instance.
func NewBaseField() *BaseField {
	baseFieldInitOnce.Do(func() {
		baseFieldOrder, _ = numct.NewModulusFromBytesBE(sliceutils.Reversed(edwards25519Impl.FpModulus[:]))
		//nolint:exhaustruct // no need for a trait
		baseFieldInstance = &BaseField{}
	})

	return baseFieldInstance
}

// Name returns the name of the structure.
func (f *BaseField) Name() string {
	return BaseFieldName
}

// Order returns the group or field order.
func (f *BaseField) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(baseFieldOrder.Nat())
}

// Characteristic returns the field characteristic.
func (f *BaseField) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromNumeric(baseFieldOrder.Nat())
}

// Hash maps input bytes to an element or point.
func (f *BaseField) Hash(bytes []byte) (*BaseFieldElement, error) {
	var e [1]edwards25519Impl.Fp
	h2c.HashToField(e[:], edwards25519Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveSuite, bytes)

	var s BaseFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

// ElementSize returns the element size in bytes.
func (f *BaseField) ElementSize() int {
	return int(edwards25519Impl.FpBytes)
}

// WideElementSize returns the wide element size in bytes.
func (f *BaseField) WideElementSize() int {
	return int(edwards25519Impl.FpWideBytes)
}

// BitLen returns the field modulus bit length.
func (f *BaseField) BitLen() int {
	return int(edwards25519Impl.FpBits)
}

// FromBytesBEReduce reduces a big-endian integer into the field.
func (f *BaseField) FromBytesBEReduce(input []byte) (*BaseFieldElement, error) {
	var v numct.Nat
	var nNat numct.Nat
	nNat.SetBytes(input)
	baseFieldOrder.Mod(&v, &nNat)
	vBytes := v.Bytes()
	return f.FromBytesBE(vBytes)
}

// BaseFieldElement represents an element of the base field.
type BaseFieldElement struct {
	traits.PrimeFieldElementTrait[*edwards25519Impl.Fp, edwards25519Impl.Fp, *BaseFieldElement, BaseFieldElement]
}

// Structure returns the algebraic structure for the receiver.
func (fe *BaseFieldElement) Structure() algebra.Structure[*BaseFieldElement] {
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
