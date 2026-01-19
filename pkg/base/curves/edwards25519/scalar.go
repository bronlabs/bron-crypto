package edwards25519

import (
	"encoding"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	edwards25519Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/edwards25519/impl"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

const (
	// ScalarFieldName is the scalar field name.
	ScalarFieldName = "curve25519Fq"
)

var (
	_ algebra.PrimeField[*Scalar]        = (*ScalarField)(nil)
	_ algebra.PrimeFieldElement[*Scalar] = (*Scalar)(nil)
	_ encoding.BinaryMarshaler           = (*Scalar)(nil)
	_ encoding.BinaryUnmarshaler         = (*Scalar)(nil)

	scalarFieldInitOnce sync.Once
	scalarFieldInstance *ScalarField
	scalarFieldOrder    *numct.Modulus
)

func scalarFieldInit() {
	scalarFieldOrder, _ = numct.NewModulusFromBytesBE(sliceutils.Reversed(edwards25519Impl.FqModulus[:]))
	//nolint:exhaustruct // no need for a trait
	scalarFieldInstance = &ScalarField{}
}

// ScalarField represents the scalar field.
type ScalarField struct {
	traits.PrimeFieldTrait[*edwards25519Impl.Fq, *Scalar, Scalar]
}

// NewScalarField returns the scalar field instance.
func NewScalarField() *ScalarField {
	scalarFieldInitOnce.Do(scalarFieldInit)
	return scalarFieldInstance
}

// Name returns the name of the structure.
func (*ScalarField) Name() string {
	return ScalarFieldName
}

// Order returns the group or field order.
func (*ScalarField) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(scalarFieldOrder.Nat())
}

// Characteristic returns the field characteristic.
func (*ScalarField) Characteristic() cardinal.Cardinal {
	return cardinal.NewFromNumeric(scalarFieldOrder.Nat())
}

// Hash maps input bytes to an element or point.
func (*ScalarField) Hash(bytes []byte) (*Scalar, error) {
	var e [1]edwards25519Impl.Fq
	h2c.HashToField(e[:], edwards25519Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, bytes)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

// FromBytesBEReduce reduces a big-endian integer into the field.
func (f *ScalarField) FromBytesBEReduce(input []byte) (*Scalar, error) {
	var v numct.Nat
	var nNat numct.Nat
	nNat.SetBytes(input)
	scalarFieldOrder.Mod(&v, &nNat)
	vBytes := v.Bytes()
	return f.FromBytesBE(vBytes)
}

// ElementSize returns the element size in bytes.
func (*ScalarField) ElementSize() int {
	return edwards25519Impl.FqBytes
}

// WideElementSize returns the wide element size in bytes.
func (*ScalarField) WideElementSize() int {
	return edwards25519Impl.FqWideBytes
}

// BitLen returns the field modulus bit length.
func (*ScalarField) BitLen() int {
	return edwards25519Impl.FqBits
}

// FromClampedBytes decodes a clamped scalar from bytes.
func (*ScalarField) FromClampedBytes(data []byte) (*Scalar, error) {
	if len(data) != edwards25519Impl.FqBytes {
		return nil, curves.ErrInvalidLength.WithMessage("invalid input")
	}

	var clone [32]byte
	copy(clone[:], data)
	clone[0] &= 248
	clone[31] &= 127
	clone[31] |= 64

	var s Scalar
	if ok := s.V.SetBytesWide(clone[:]); ok == ct.False {
		return nil, curves.ErrFailed.WithMessage("failed to set scalar from bytes")
	}
	return &s, nil
}

// Scalar represents a scalar field element.
type Scalar struct {
	traits.PrimeFieldElementTrait[*edwards25519Impl.Fq, edwards25519Impl.Fq, *Scalar, Scalar]
}

// NewScalar returns a new scalar.
func NewScalar(v uint64) *Scalar {
	var s Scalar
	s.V.SetUint64(v)
	return &s
}

// Structure returns the algebraic structure for the receiver.
func (*Scalar) Structure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (fe *Scalar) MarshalBinary() (data []byte, err error) {
	return fe.V.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (fe *Scalar) UnmarshalBinary(data []byte) error {
	if ok := fe.V.SetBytes(data); ok == 0 {
		return curves.ErrSerialisation.WithMessage("failed to unmarshal field element")
	}

	return nil
}
