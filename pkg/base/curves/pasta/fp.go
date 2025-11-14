package pasta

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
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type (
	VestaScalarField = FpField
	PallasBaseField  = FpField
)

const (
	FpFieldName = "PastaFp"
)

var (
	_ algebra.PrimeField[*FpFieldElement]        = (*FpField)(nil)
	_ algebra.PrimeFieldElement[*FpFieldElement] = (*FpFieldElement)(nil)
	_ encoding.BinaryMarshaler                   = (*FpFieldElement)(nil)
	_ encoding.BinaryUnmarshaler                 = (*FpFieldElement)(nil)

	fpFieldInitOnce sync.Once
	fpFieldInstance *FpField
	fpFieldOrder    *saferith.Modulus
)

func fpFieldInit() {
	fpFieldOrder = saferith.ModulusFromBytes(sliceutils.Reversed(pastaImpl.FpModulus[:]))
	fpFieldInstance = &FpField{}
}

type FpField struct {
	traits.PrimeFieldTrait[*pastaImpl.Fp, *FpFieldElement, FpFieldElement]
}

func newFpField() *FpField {
	fpFieldInitOnce.Do(fpFieldInit)
	return fpFieldInstance
}

func NewPallasBaseField() *FpField {
	return newFpField()
}

func NewVestaScalarField() *FpField {
	return newFpField()
}

func (*FpField) Name() string {
	return FpFieldName
}

func (*FpField) ElementSize() int {
	return pastaImpl.FpBytes
}

func (*FpField) WideElementSize() int {
	return pastaImpl.FpWideBytes
}

func (f *FpField) Characteristic() cardinal.Cardinal {
	return f.Order()
}

func (*FpField) Order() cardinal.Cardinal {
	return cardinal.NewFromSaferith(fpFieldOrder.Nat())
}

func (*FpField) Hash(input []byte) (*FpFieldElement, error) {
	var e [1]pastaImpl.Fp
	h2c.HashToField(e[:], pastaImpl.PallasCurveHasherParams{}, base.Hash2CurveAppTag+PallasHash2CurveSuite, input)

	var s FpFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

func (*FpField) BitLen() int {
	return pastaImpl.FpBits
}

func (f *FpField) FromNat(n *numct.Nat) (*FpFieldElement, error) {
	var v numct.Nat
	m, ok := numct.NewModulusOddPrime((*numct.Nat)(fpFieldOrder.Nat()))
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create modulus")
	}
	m.Mod(&v, n)
	vBytes := v.Bytes()
	slices.Reverse(vBytes)
	var s FpFieldElement
	if ok := s.V.SetBytesWide(vBytes); ok == ct.False {
		return nil, errs.NewFailed("failed to set scalar from nat")
	}
	return &s, nil
}

func (f *FpField) FromNumeric(n algebra.Numeric) (*FpFieldElement, error) {
	var v numct.Nat
	m, ok := numct.NewModulusOddPrime((*numct.Nat)(fpFieldOrder.Nat()))
	if ok == ct.False {
		return nil, errs.NewFailed("failed to create modulus")
	}
	var nNat numct.Nat
	nNat.SetBytes(n.BytesBE())
	m.Mod(&v, &nNat)
	vBytes := v.Bytes()
	slices.Reverse(vBytes)
	var fe FpFieldElement
	if ok := fe.V.SetBytesWide(vBytes); ok == ct.False {
		return nil, errs.NewFailed("failed to set scalar from numeric")
	}
	return &fe, nil
}

type FpFieldElement struct {
	traits.PrimeFieldElementTrait[*pastaImpl.Fp, pastaImpl.Fp, *FpFieldElement, FpFieldElement]
}

func (s *FpFieldElement) Structure() algebra.Structure[*FpFieldElement] {
	return newFpField()
}

func (s *FpFieldElement) MarshalBinary() ([]byte, error) {
	return s.V.Bytes(), nil
}

func (s *FpFieldElement) UnmarshalBinary(data []byte) error {
	if ok := s.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("cannot unmarshal scalar")
	}

	return nil
}
