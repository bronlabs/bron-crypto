package k256

import (
	"encoding"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	k256Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/k256/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/errs-go/errs"
)

const (
	// ScalarFieldName is the scalar field name.
	ScalarFieldName = "secp256k1Fq"
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
	orderBytes := make([]byte, len(k256Impl.FqModulus))
	copy(orderBytes, k256Impl.FqModulus[:])
	slices.Reverse(orderBytes)
	scalarFieldOrder, _ = numct.NewModulusFromBytesBE(orderBytes)
	//nolint:exhaustruct // no need for trait
	scalarFieldInstance = &ScalarField{}
}

// ScalarField represents the scalar field.
type ScalarField struct {
	traits.PrimeFieldTrait[*k256Impl.Fq, *Scalar, Scalar]
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

// FromBytesBEReduce reduces a big-endian integer into the field.
func (f *ScalarField) FromBytesBEReduce(input []byte) (*Scalar, error) {
	var v numct.Nat
	var nNat numct.Nat
	nNat.SetBytes(input)
	scalarFieldOrder.Mod(&v, &nNat)
	vBytes := v.Bytes()
	out, err := f.FromBytesBE(vBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert reduced bytes into field element")
	}
	return out, nil
}

// Hash maps input bytes to an element or point.
func (*ScalarField) Hash(bytes []byte) (*Scalar, error) {
	var e [1]k256Impl.Fq
	h2c.HashToField(e[:], k256Impl.CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, bytes)

	var s Scalar
	s.V.Set(&e[0])
	return &s, nil
}

// ElementSize returns the element size in bytes.
func (*ScalarField) ElementSize() int {
	return k256Impl.FqBytes
}

// WideElementSize returns the wide element size in bytes.
func (*ScalarField) WideElementSize() int {
	return k256Impl.FqWideBytes
}

// BitLen returns the field modulus bit length.
func (*ScalarField) BitLen() int {
	return k256Impl.FqBits
}

// Scalar represents a scalar field element.
type Scalar struct {
	traits.PrimeFieldElementTrait[*k256Impl.Fq, k256Impl.Fq, *Scalar, Scalar]
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
