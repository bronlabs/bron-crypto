package pasta

import (
	"encoding"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type (
	VestaBaseField    = FqField
	PallasScalarField = FqField
)

const (
	// FqFieldName is the field name.
	FqFieldName = "PastaFq"
)

var (
	_ algebra.PrimeField[*FqFieldElement]        = (*FqField)(nil)
	_ algebra.PrimeFieldElement[*FqFieldElement] = (*FqFieldElement)(nil)
	_ encoding.BinaryMarshaler                   = (*FqFieldElement)(nil)
	_ encoding.BinaryUnmarshaler                 = (*FqFieldElement)(nil)

	fqFieldInitOnce sync.Once
	fqFieldInstance *FqField
	fqFieldOrder    *numct.Modulus
)

func fqFieldInit() {
	fqFieldOrder, _ = numct.NewModulusFromBytesBE(sliceutils.Reversed(pastaImpl.FqModulus[:]))
	//nolint:exhaustruct // no need for trait
	fqFieldInstance = &FqField{}
}

// FqField represents a field instance.
type FqField struct {
	traits.PrimeFieldTrait[*pastaImpl.Fq, *FqFieldElement, FqFieldElement]
}

func newFqField() *FqField {
	fqFieldInitOnce.Do(fqFieldInit)
	return fqFieldInstance
}

// NewVestaBaseField returns the Vesta base field.
func NewVestaBaseField() *FqField {
	return newFqField()
}

// NewPallasScalarField returns the Pallas scalar field.
func NewPallasScalarField() *FqField {
	return newFqField()
}

// Name returns the name of the structure.
func (*FqField) Name() string {
	return FqFieldName
}

// ElementSize returns the element size in bytes.
func (*FqField) ElementSize() int {
	return pastaImpl.FqBytes
}

// WideElementSize returns the wide element size in bytes.
func (*FqField) WideElementSize() int {
	return pastaImpl.FqWideBytes
}

// Characteristic returns the field characteristic.
func (f *FqField) Characteristic() cardinal.Cardinal {
	return f.Order()
}

// Order returns the group or field order.
func (*FqField) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(fqFieldOrder)
}

// Hash maps input bytes to an element or point.
func (*FqField) Hash(input []byte) (*FqFieldElement, error) {
	var e [1]pastaImpl.Fq
	h2c.HashToField(e[:], pastaImpl.VestaCurveHasherParams{}, base.Hash2CurveAppTag+VestaHash2CurveSuite, input)

	var s FqFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

// BitLen returns the field modulus bit length.
func (*FqField) BitLen() int {
	return pastaImpl.FqBits
}

// FromBytesBEReduce reduces a big-endian integer into the field.
func (f *FqField) FromBytesBEReduce(input []byte) (*FqFieldElement, error) {
	var v numct.Nat
	var nNat numct.Nat
	nNat.SetBytes(input)
	fqFieldOrder.Mod(&v, &nNat)
	vBytes := v.Bytes()
	return f.FromBytesBE(vBytes)
}

// FqFieldElement represents a field element.
type FqFieldElement struct {
	traits.PrimeFieldElementTrait[*pastaImpl.Fq, pastaImpl.Fq, *FqFieldElement, FqFieldElement]
}

// Structure returns the algebraic structure for the receiver.
func (s *FqFieldElement) Structure() algebra.Structure[*FqFieldElement] {
	return newFqField()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (s *FqFieldElement) MarshalBinary() ([]byte, error) {
	return s.V.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (s *FqFieldElement) UnmarshalBinary(data []byte) error {
	if ok := s.V.SetBytes(data); ok == 0 {
		return curves.ErrSerialisation.WithMessage("cannot unmarshal scalar")
	}

	return nil
}
