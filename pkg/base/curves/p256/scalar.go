package p256

import (
	"encoding"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	p256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/p256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs2"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
)

const (
	// ScalarFieldName is the scalar field name.
	ScalarFieldName = "P256Fq"
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
	orderBytes := make([]byte, len(p256Impl.FqModulus))
	copy(orderBytes, p256Impl.FqModulus[:])
	slices.Reverse(orderBytes)
	var ok ct.Bool
	v := numct.NewNatFromBytes(orderBytes)
	scalarFieldOrder, ok = numct.NewModulus(v)
	if ok == ct.False {
		panic("failed to create scalar field modulus")
	}
	//nolint:exhaustruct // no need for a trait
	scalarFieldInstance = &ScalarField{}
}

// ScalarField represents the scalar field.
type ScalarField struct {
	traits.PrimeFieldTrait[*p256Impl.Fq, *Scalar, Scalar]
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
	var e [1]p256Impl.Fq
	h2c.HashToField(e[:], p256Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, bytes)

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
	out, err := f.FromBytesBE(vBytes)
	if err != nil {
		return nil, errs2.Wrap(err).WithMessage("failed to convert reduced bytes into field element")
	}
	return out, nil
}

// ElementSize returns the element size in bytes.
func (*ScalarField) ElementSize() int {
	return p256Impl.FqBytes
}

// WideElementSize returns the wide element size in bytes.
func (*ScalarField) WideElementSize() int {
	return p256Impl.FqWideBytes
}

// BitLen returns the field modulus bit length.
func (*ScalarField) BitLen() int {
	return p256Impl.FqBits
}

// Scalar represents a scalar field element.
type Scalar struct {
	traits.PrimeFieldElementTrait[*p256Impl.Fq, p256Impl.Fq, *Scalar, Scalar]
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
