package polynomials

import (
	"fmt"
	"unicode"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal/models"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
)

func polynomialSort(indeterminate rune, coeffSort universal.Sort) universal.Sort {
	return universal.Sort(fmt.Sprintf("%s[%c]", coeffSort, unicode.ToUpper(indeterminate)))
}

func moduleValuedPolynomialSort(indeterminate rune, coeffSort, scalarSort universal.Sort) universal.Sort {
	polyRing := polynomialSort(indeterminate, scalarSort)
	return universal.Sort(fmt.Sprintf("(%s_%s %s)", coeffSort, scalarSort, polyRing))
}

func PolynomialRingModel[SR interface {
	algebra.Ring[S]
	algebra.FiniteStructure[S]
}, S algebra.RingElement[S]](
	indeterminate rune, polyRing PolynomialRing[S], coeffRing SR,
) *universal.TwoSortedModel[Polynomial[S], S] {
	coefficientRingSort := universal.Sort(coeffRing.Name())
	sort := polynomialSort(indeterminate, coefficientRingSort)
	addA, mulA, zeroA, oneA, negA, err := models.DeriveStandardRingOperators(sort, polyRing)
	if err != nil {
		panic(err)
	}
	quoA, remA, normA, err := models.EuclideanDivisionOperators(sort, polyRing)
	if err != nil {
		panic(err)
	}
	addR, mulR, zeroR, oneR, negR, err := models.DeriveStandardRingOperators(coefficientRingSort, coeffRing)
	if err != nil {
		panic(err)
	}
	scMul, err := aimpl.NewScalarMultiplicationOperator[Polynomial[S], S](sort, coefficientRingSort)
	if err != nil {
		panic(err)
	}
	ringAspect, err := models.RAlgebra(
		sort, polyRing,
		addA, mulA, zeroA, oneA, negA,
		coefficientRingSort, coeffRing,
		addR, mulR, zeroR, oneR, negR,
		scMul,
	)
	if err != nil {
		panic(err)
	}
	domainAspect, err := models.EuclideanDomain(
		sort, polyRing,
		addA, mulA, zeroA, oneA, negA,
		quoA, remA, normA,
	)
	if err != nil {
		panic(err)
	}
	out, err := ringAspect.UnionAlongFirst(domainAspect)
	if err != nil {
		panic(err)
	}
	if err := out.Second().Algebra().AttachSampler(coeffRing.Random); err != nil {
		panic(err)
	}
	return out
}

func PolynomialModuleModel[CM interface {
	algebra.Module[CME, S]
	algebra.FiniteStructure[CME]
}, SR interface {
	algebra.Ring[S]
	algebra.FiniteStructure[S]
}, CME algebra.ModuleElement[CME, S], S algebra.RingElement[S]](
	indeterminate rune, polyModule PolynomialModule[CME, S], coeffModule CM, scalarRing SR,
) *universal.ThreeSortedModel[ModuleValuedPolynomial[CME, S], S, CME] {
	coeffSort := universal.Sort(coeffModule.Name())
	scalarSort := universal.Sort(scalarRing.Name())
	sort := moduleValuedPolynomialSort(indeterminate, coeffSort, scalarSort)
	op, err := universal.NewBinaryOperator(sort, universal.CircleSymbol, utils.Maybe2(algebra.Operator[ModuleValuedPolynomial[CME, S]]))
	if err != nil {
		panic(err)
	}
	opIdentity, err := universal.NewConstant(
		sort,
		universal.IdentitySymbol(op.Symbol()),
		polyModule.OpIdentity(),
	)
	if err != nil {
		panic(err)
	}
	opInv, err := universal.NewUnaryOperator(
		sort,
		universal.InverseSymbol(op.Symbol()),
		utils.Maybe(func(a ModuleValuedPolynomial[CME, S]) ModuleValuedPolynomial[CME, S] { return a.OpInv() }),
	)
	if err != nil {
		panic(err)
	}
	addS, mulS, zeroS, oneS, negS, err := models.DeriveStandardRingOperators(scalarSort, scalarRing)
	if err != nil {
		panic(err)
	}
	scMul, err := aimpl.NewLeftActionOperator[ModuleValuedPolynomial[CME, S], S](sort, scalarSort)
	if err != nil {
		panic(err)
	}
	module, err := models.Module(
		sort, polyModule,
		op, opIdentity, opInv,
		scalarSort, scalarRing,
		addS, mulS, zeroS, oneS, negS,
		scMul,
	)
	if err != nil {
		panic(err)
	}
	moduleAbelian := models.AsAbelian2(module, op)
	out, err := models.AdjoinBareSort(moduleAbelian, coeffSort, coeffModule)
	if err != nil {
		panic(err)
	}
	return out
}
