package pasta

// import (
// 	"github.com/bronlabs/bron-crypto/pkg/base"
// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
// 	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
// 	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/traits"
// 	"github.com/bronlabs/bron-crypto/pkg/base/errs"
// 	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
// 	"sync"

// 	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
// 	"github.com/cronokirby/saferith"
// )

// const (
// 	FqFieldName = "PastaFq"
// )

// var (
// 	_ fields.PrimeField[*FqFieldElement]        = (*FqField)(nil)
// 	_ fields.PrimeFieldElement[*FqFieldElement] = (*FqFieldElement)(nil)

// 	fqFieldInitOnce sync.Once
// 	fqFieldInstance *FqField
// 	fqFieldOrder    *saferith.Modulus
// )

// func fqFieldInit() {
// 	fqFieldOrder = saferith.ModulusFromBytes(sliceutils.Reversed(pastaImpl.FqModulus[:]))
// 	fqFieldInstance = &FqField{}
// }

// type FqField struct {
// 	traits.PrimeFieldTrait[*pastaImpl.Fq, *FqFieldElement, FqFieldElement]
// }

// func newFqField() *FqField {
// 	fqFieldInitOnce.Do(fqFieldInit)
// 	return fqFieldInstance
// }

// func NewVestaBaseField() *FqField {
// 	return newFqField()
// }

// func NewPallasScalarField() *FqField {
// 	return newFqField()
// }

// func (*FqField) Name() string {
// 	return FqFieldName
// }

// func (*FqField) Operator() algebra.BinaryOperator[*FqFieldElement] {
// 	return algebra.Add[*FqFieldElement]
// }

// func (*FqField) OtherOperator() algebra.BinaryOperator[*FqFieldElement] {
// 	return algebra.Mul[*FqFieldElement]
// }

// func (*FqField) ElementSize() int {
// 	return pastaImpl.FqBytes
// }

// func (*FqField) WideElementSize() int {
// 	return pastaImpl.FqWideBytes
// }

// func (f *FqField) Characteristic() algebra.Cardinal {
// 	return f.Order()
// }

// func (*FqField) Order() algebra.Cardinal {
// 	return fqFieldOrder.Nat()
// }

// func (*FqField) Hash(input []byte) (*FqFieldElement, error) {
// 	var e [1]pastaImpl.Fq
// 	h2c.HashToField(e[:], pastaImpl.VestaCurveHasherParams{}, base.Hash2CurveAppTag+VestaHash2CurveSuite, input)

// 	var s FqFieldElement
// 	s.V.Set(&e[0])
// 	return &s, nil
// }

// type FqFieldElement struct {
// 	traits.PrimeFieldElementTrait[*pastaImpl.Fq, pastaImpl.Fq, *FqFieldElement, FqFieldElement]
// }

// func (s *FqFieldElement) Structure() algebra.Structure[*FqFieldElement] {
// 	return newFqField()
// }

// func (s *FqFieldElement) MarshalBinary() ([]byte, error) {
// 	return s.V.Bytes(), nil
// }

// func (s *FqFieldElement) UnmarshalBinary(data []byte) error {
// 	if ok := s.V.SetBytes(data); ok == 0 {
// 		return errs.NewSerialisation("cannot unmarshal scalar")
// 	}

// 	return nil
// }
