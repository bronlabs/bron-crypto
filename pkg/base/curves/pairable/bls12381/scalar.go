package bls12381

import (
	"encoding"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	bls12381Impl "github.com/bronlabs/bron-crypto/pkg/base/curves/pairable/bls12381/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"github.com/bronlabs/errs-go/errs"
)

const (
	// ScalarFieldName is the scalar field name.
	ScalarFieldName = "BLS12381Fq"
	// Hash2CurveScalarSuite is the hash-to-curve scalar suite string.
	Hash2CurveScalarSuite = "BLS12381G1_XMD:SHA-256_SSWU_RO_SC_"
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
	scalarFieldOrder, _ = numct.NewModulusFromBytesBE(sliceutils.Reversed(bls12381Impl.FqModulus[:]))
	//nolint:exhaustruct // no need for trait
	scalarFieldInstance = &ScalarField{}
}

// ScalarField represents the scalar field.
type ScalarField struct {
	traits.PrimeFieldTrait[*bls12381Impl.Fq, *Scalar, Scalar]
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

// ElementSize returns the element size in bytes.
func (*ScalarField) ElementSize() int {
	return bls12381Impl.FqBytes
}

// WideElementSize returns the wide element size in bytes.
func (*ScalarField) WideElementSize() int {
	return bls12381Impl.FqWideBytes
}

// Characteristic returns the field characteristic.
func (f *ScalarField) Characteristic() cardinal.Cardinal {
	return f.Order()
}

// Order returns the group or field order.
func (*ScalarField) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(scalarFieldOrder)
}

// Hash maps input bytes to an element or point.
func (*ScalarField) Hash(input []byte) (*Scalar, error) {
	var e [1]bls12381Impl.Fq
	h2c.HashToField(e[:], bls12381Impl.G1CurveHasherParams{}, base.Hash2CurveAppTag+Hash2CurveScalarSuite, input)

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
		return nil, errs.Wrap(err).WithMessage("failed to convert reduced bytes into field element")
	}
	return out, nil
}

// BitLen returns the field modulus bit length.
func (*ScalarField) BitLen() int {
	return bls12381Impl.FqBits
}

// Scalar represents a scalar field element.
type Scalar struct {
	traits.PrimeFieldElementTrait[*bls12381Impl.Fq, bls12381Impl.Fq, *Scalar, Scalar]
}

// Structure returns the algebraic structure for the receiver.
func (*Scalar) Structure() algebra.Structure[*Scalar] {
	return NewScalarField()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (s *Scalar) MarshalBinary() ([]byte, error) {
	return s.V.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (s *Scalar) UnmarshalBinary(data []byte) error {
	if ok := s.V.SetBytes(data); ok == 0 {
		return curves.ErrSerialisation.WithMessage("cannot unmarshal scalar")
	}

	return nil
}
