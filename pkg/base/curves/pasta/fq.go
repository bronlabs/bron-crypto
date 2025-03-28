package pasta

import (
	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/fields"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/impl/h2c"
	pastaImpl "github.com/bronlabs/bron-crypto/pkg/base/curves/pasta/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/traits"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"io"
	"slices"
	"sync"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/cronokirby/saferith"
)

const (
	FqFieldName = "PastaFq"
)

var (
	_ fields.PrimeField[*FqFieldElement]        = (*FqField)(nil)
	_ fields.PrimeFieldElement[*FqFieldElement] = (*FqFieldElement)(nil)

	fqFieldInitOnce sync.Once
	fqFieldInstance *FqField
	fqFieldOrder    *saferith.Modulus
)

func fqFieldInit() {
	orderBytes := make([]byte, len(pastaImpl.FqModulus))
	copy(orderBytes, pastaImpl.FqModulus[:])
	slices.Reverse(orderBytes)
	fqFieldOrder = saferith.ModulusFromBytes(orderBytes)
	fqFieldInstance = &FqField{}
}

type FqField struct {
	traits.ScalarField[*pastaImpl.Fq, *FqFieldElement, FqFieldElement]
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

func (*FqField) Operator() algebra.BinaryOperator[*FqFieldElement] {
	return algebra.Add[*FqFieldElement]
}

func (*FqField) OtherOperator() algebra.BinaryOperator[*FqFieldElement] {
	return algebra.Mul[*FqFieldElement]
}

func (*FqField) ExtensionDegree() uint {
	return 1
}

func (*FqField) ElementSize() int {
	return pastaImpl.FqBytes
}

func (*FqField) WideElementSize() int {
	return pastaImpl.FqWideBytes
}

func (f *FqField) Characteristic() algebra.Cardinal {
	return f.Order()
}

func (*FqField) Order() algebra.Cardinal {
	return fqFieldOrder.Nat()
}

func (*FqField) Random(prng io.Reader) (*FqFieldElement, error) {
	var e FqFieldElement
	ok := e.V.SetRandom(prng)
	if ok == 0 {
		return nil, errs.NewRandomSample("cannot sample scalar")
	}

	return &e, nil
}

func (*FqField) Hash(input []byte) (*FqFieldElement, error) {
	var e [1]pastaImpl.Fq
	h2c.HashToField(e[:], pastaImpl.VestaCurveHasherParams{}, base.Hash2CurveAppTag+VestaHash2CurveSuite, input)

	var s FqFieldElement
	s.V.Set(&e[0])
	return &s, nil
}

func (f *FqField) FromNat(v *saferith.Nat) (*FqFieldElement, error) {
	return traits.NewScalarFromNat[*pastaImpl.Fq, *FqFieldElement, FqFieldElement](v, fqFieldOrder)
}

type FqFieldElement struct {
	traits.Scalar[*pastaImpl.Fq, pastaImpl.Fq, *FqFieldElement, FqFieldElement]
}

func (s *FqFieldElement) Structure() algebra.Structure[*FqFieldElement] {
	return newFqField()
}

func (s *FqFieldElement) Fq() *pastaImpl.Fq {
	return &s.Scalar.V
}

func (s *FqFieldElement) UnmarshalBinary(data []byte) error {
	if ok := s.V.SetBytes(data); ok == 0 {
		return errs.NewSerialisation("cannot unmarshal scalar")
	}

	return nil
}
