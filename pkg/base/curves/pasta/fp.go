package pasta

import (
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl"
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
	VestaScalarField = FpField
	PallasBaseField  = FpField
)

const (
	FpFieldName = "PastaFp"
)

var (
	_ algebra.PrimeField[*FpFieldElement]        = (*FpField)(nil)
	_ algebra.PrimeFieldElement[*FpFieldElement] = (*FpFieldElement)(nil)

	fpFieldInitOnce      sync.Once
	fpFieldInstance      *FpField
	fpFieldModelOnce     sync.Once
	fpFieldModelInstance *universal.Model[*FpFieldElement]
	fpFieldOrder         *saferith.Modulus
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

func FpFieldModel() *universal.Model[*FpFieldElement] {
	fpFieldModelOnce.Do(func() {
		var err error
		fpFieldModelInstance, err = impl.BaseFieldModel(
			newFpField(),
		)
		if err != nil {
			panic(err)
		}
	})

	return fpFieldModelInstance
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

func (f *FpField) Model() *universal.Model[*FpFieldElement] {
	return FpFieldModel()
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
	return cardinal.NewFromNat(fpFieldOrder.Nat())
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
