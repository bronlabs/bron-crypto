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
	"github.com/bronlabs/errs-go/pkg/errs"
)

type (
	VestaScalarField = FpField
	PallasBaseField  = FpField
)

const (
	// FpFieldName is the field name.
	FpFieldName = "PastaFp"
)

var (
	_ algebra.PrimeField[*FpFieldElement]        = (*FpField)(nil)
	_ algebra.PrimeFieldElement[*FpFieldElement] = (*FpFieldElement)(nil)
	_ encoding.BinaryMarshaler                   = (*FpFieldElement)(nil)
	_ encoding.BinaryUnmarshaler                 = (*FpFieldElement)(nil)

	fpFieldInitOnce sync.Once
	fpFieldInstance *FpField
	fpFieldOrder    *numct.Modulus
)

func fpFieldInit() {
	fpFieldOrder, _ = numct.NewModulusFromBytesBE(sliceutils.Reversed(pastaImpl.FpModulus[:]))
	//nolint:exhaustruct // no need for trait
	fpFieldInstance = &FpField{}
}

// FpField represents a field instance.
type FpField struct {
	traits.PrimeFieldTrait[*pastaImpl.Fp, *FpFieldElement, FpFieldElement]
}

func newFpField() *FpField {
	fpFieldInitOnce.Do(fpFieldInit)
	return fpFieldInstance
}

// NewPallasBaseField returns the Pallas base field.
func NewPallasBaseField() *FpField {
	return newFpField()
}

// NewVestaScalarField returns the Vesta scalar field.
func NewVestaScalarField() *FpField {
	return newFpField()
}

// Name returns the name of the structure.
func (*FpField) Name() string {
	return FpFieldName
}

// ElementSize returns the element size in bytes.
func (*FpField) ElementSize() int {
	return pastaImpl.FpBytes
}

// WideElementSize returns the wide element size in bytes.
func (*FpField) WideElementSize() int {
	return pastaImpl.FpWideBytes
}

// Characteristic returns the field characteristic.
func (f *FpField) Characteristic() cardinal.Cardinal {
	return f.Order()
}

// Order returns the group or field order.
func (*FpField) Order() cardinal.Cardinal {
	return cardinal.NewFromNumeric(fpFieldOrder)
}

// Hash maps input bytes to an element or point.
func (*FpField) Hash(input []byte) (*FpFieldElement, error) {
	var e [1]pastaImpl.Fp
	h2c.HashToField(e[:], pastaImpl.PallasCurveHasherParams{}, base.Hash2CurveAppTag+PallasHash2CurveSuite, input)

	var s FpFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

// BitLen returns the field modulus bit length.
func (*FpField) BitLen() int {
	return pastaImpl.FpBits
}

// FromBytesBEReduce reduces a big-endian integer into the field.
func (f *FpField) FromBytesBEReduce(input []byte) (*FpFieldElement, error) {
	var v numct.Nat
	var nNat numct.Nat
	nNat.SetBytes(input)
	fpFieldOrder.Mod(&v, &nNat)
	vBytes := v.Bytes()
	out, err := f.FromBytesBE(vBytes)
	if err != nil {
		return nil, errs.Wrap(err).WithMessage("failed to convert reduced bytes into field element")
	}
	return out, nil
}

// FpFieldElement represents a field element.
type FpFieldElement struct {
	traits.PrimeFieldElementTrait[*pastaImpl.Fp, pastaImpl.Fp, *FpFieldElement, FpFieldElement]
}

// Structure returns the algebraic structure for the receiver.
func (*FpFieldElement) Structure() algebra.Structure[*FpFieldElement] {
	return newFpField()
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (fe *FpFieldElement) MarshalBinary() ([]byte, error) {
	return fe.V.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (fe *FpFieldElement) UnmarshalBinary(data []byte) error {
	if ok := fe.V.SetBytes(data); ok == 0 {
		return curves.ErrSerialisation.WithMessage("cannot unmarshal scalar")
	}

	return nil
}
