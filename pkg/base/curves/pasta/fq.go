package pasta

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	h2c "github.com/bronlabs/bron-crypto/pkg/base/curves/impl/rfc9380"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/cardinal"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/cronokirby/saferith"
)

type (
	VestaBaseField    = FqField
	PallasScalarField = FqField
)

const (
	FqFieldName = "PastaFq"
)

var (
	_ algebra.PrimeField[*FqFieldElement]        = (*FqField)(nil)
	_ algebra.PrimeFieldElement[*FqFieldElement] = (*FqFieldElement)(nil)

	fqFieldInitOnce sync.Once
	fqFieldInstance *FqField
	fqFieldOrder    *saferith.Modulus
)

func fqFieldInit() {
	fqFieldOrder = saferith.ModulusFromBytes(sliceutils.Reversed(pastaImpl.FqModulus[:]))
	fqFieldInstance = &FqField{}
}

type FqField struct {
	traits.PrimeFieldTrait[*pastaImpl.Fq, *FqFieldElement, FqFieldElement]
}

func newFqField() *FqField {
	fqFieldInitOnce.Do(fqFieldInit)
	return fqFieldInstance
}

func NewVestaBaseField() *FqField {
	return newFqField()
}

func NewPallasScalarField() *FqField {
	return newFqField()
}

func (*FqField) Name() string {
	return FqFieldName
}

func (*FqField) ElementSize() int {
	return pastaImpl.FqBytes
}

func (*FqField) WideElementSize() int {
	return pastaImpl.FqWideBytes
}

func (f *FqField) Characteristic() cardinal.Cardinal {
	return f.Order()
}

func (*FqField) Order() cardinal.Cardinal {
	return cardinal.NewFromNat(fqFieldOrder.Nat())
}

func (*FqField) Hash(input []byte) (*FqFieldElement, error) {
	var e [1]pastaImpl.Fq
	h2c.HashToField(e[:], pastaImpl.VestaCurveHasherParams{}, base.Hash2CurveAppTag+VestaHash2CurveSuite, input)

	var s FqFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

type FqFieldElement struct {
	traits.PrimeFieldElementTrait[*pastaImpl.Fq, pastaImpl.Fq, *FqFieldElement, FqFieldElement]
}

func (s *FqFieldElement) Structure() algebra.Structure[*FqFieldElement] {
	return newFqField()
}

func (s *FqFieldElement) MarshalBinary() ([]byte, error) {
	return s.V.Bytes(), nil
}

func (s *FqFieldElement) UnmarshalBinary(data []byte) error {
	if ok := s.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("cannot unmarshal scalar")
	}

	return nil
}
