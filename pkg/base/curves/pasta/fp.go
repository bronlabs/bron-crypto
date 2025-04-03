package pasta

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/cronokirby/saferith"
)

const (
	FpFieldName = "PastaFp"
)

var (
	_ fields.PrimeField[*FpFieldElement]        = (*FpField)(nil)
	_ fields.PrimeFieldElement[*FpFieldElement] = (*FpFieldElement)(nil)

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

func (*FpField) Operator() algebra.BinaryOperator[*FpFieldElement] {
	return algebra.Add[*FpFieldElement]
}

func (*FpField) OtherOperator() algebra.BinaryOperator[*FpFieldElement] {
	return algebra.Mul[*FpFieldElement]
}

func (*FpField) ElementSize() int {
	return pastaImpl.FpBytes
}

func (*FpField) WideElementSize() int {
	return pastaImpl.FpWideBytes
}

func (f *FpField) Characteristic() algebra.Cardinal {
	return f.Order()
}

func (*FpField) Order() algebra.Cardinal {
	return fpFieldOrder.Nat()
}

func (*FpField) Hash(input []byte) (*FpFieldElement, error) {
	var e [1]pastaImpl.Fp
	h2c.HashToField(e[:], pastaImpl.PallasCurveHasherParams{}, base.Hash2CurveAppTag+PallasHash2CurveSuite, input)

	var s FpFieldElement
	s.V.Set(&e[0])
	return &s, nil
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
