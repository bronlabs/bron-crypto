package fields

import (
	algebra "github.com/bronlabs/krypton-primitives/pkg/base/algebra2"
	"github.com/bronlabs/krypton-primitives/pkg/base/errs"
)

type (
	Field[FE algebra.FieldElement[FE]]        algebra.Field[FE]
	FieldElement[FE algebra.FieldElement[FE]] algebra.FieldElement[FE]

	FiniteField[FE algebra.FiniteFieldElement[FE]]        algebra.FiniteField[FE]
	FiniteFieldElement[FE algebra.FiniteFieldElement[FE]] algebra.FiniteFieldElement[FE]

	PrimeField[FE algebra.PrimeFieldElement[FE]]        algebra.PrimeField[FE]
	PrimeFieldElement[FE algebra.PrimeFieldElement[FE]] algebra.PrimeFieldElement[FE]
)

func GetField[FE FieldElement[FE]](fe FE) (Field[FE], error) {
	f, ok := fe.Structure().(Field[FE])
	if !ok {
		return nil, (errs.NewType("FieldElement does not have a Field structure"))
	}
	return f, nil
}

func GetFiniteField[FE FiniteFieldElement[FE]](fe FE) (FiniteField[FE], error) {
	f, ok := fe.Structure().(FiniteField[FE])
	if !ok {
		return nil, (errs.NewType("FieldElement does not have a FiniteField structure"))
	}
	return f, nil
}

func GetPrimeField[FE PrimeFieldElement[FE]](fe FE) (PrimeField[FE], error) {
	f, ok := fe.Structure().(PrimeField[FE])
	if !ok {
		return nil, (errs.NewType("FieldElement does not have a PrimeField structure"))
	}
	return f, nil
}
