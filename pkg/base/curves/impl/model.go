package impl

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal/models"
	"github.com/bronlabs/bron-crypto/pkg/base/curves"
)

const (
	EllipticCurveSort universal.Sort = "E"
	PrimeSubGroupSort universal.Sort = "E[q]"
	BaseFieldSort     universal.Sort = "Fp"
	ScalarsSort       universal.Sort = "Fq"
	PairingTargetSort universal.Sort = "Gt"

	GeneratorSymbol     universal.Symbol = "G"
	PointAdditionSymbol                  = universal.DirectSumSymbol
)

type ScalarRingConstraint[S algebra.UintLike[S]] interface {
	algebra.ZnLike[S]
	algebra.FiniteStructure[S]
}

type ScalarFieldConstraint[S algebra.PrimeFieldElement[S]] interface {
	algebra.PrimeField[S]
	algebra.FiniteStructure[S]
}

type BaseFieldConstraint[F algebra.FieldElement[F]] interface {
	algebra.Field[F]
	algebra.FiniteStructure[F]
}

type EllipticCurveConstraint[P curves.ECPoint[P, F, S], F algebra.FieldElement[F], S algebra.UintLike[S]] interface {
	curves.EllipticCurve[P, F, S]
	algebra.FiniteStructure[P]
}

type CurveConstraint[P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S]] interface {
	curves.Curve[P, F, S]
	algebra.FiniteStructure[P]
}

type PairingTargetConstraint[E algebra.MultiplicativeGroupElement[E]] interface {
	algebra.MultiplicativeGroup[E]
	algebra.FiniteStructure[E]
}

func PointNegation[P curves.ECPoint[P, F, S], F algebra.FieldElement[F], S algebra.UintLike[S]](sort universal.Sort) *universal.UnaryOperator[P] {
	op, err := universal.NewUnaryOperator(
		sort, universal.UnaryFunctionSymbol(universal.MinusSymbol), maybe(algebra.Negate[P]),
	)
	if err != nil {
		panic(err)
	}
	return op
}

func ScalarRingModel[
	SR ScalarRingConstraint[S], S algebra.UintLike[S],
](scalarRing SR) (*universal.Model[S], error) {
	addition, multiplication, zero, one, negation, err := models.DeriveStandardRingOperators(ScalarsSort, scalarRing)
	if err != nil {
		return nil, err
	}
	ring, err := models.Ring(
		ScalarsSort, scalarRing,
		addition,
		multiplication,
		zero, one,
		negation,
	)
	if err != nil {
		return nil, err
	}
	out := models.AsAbelian(ring, addition, multiplication)
	if err := out.Algebra().AttachSampler(scalarRing.Random); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Signature().Sort(), universal.PrimaryOperation, addition); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Signature().Sort(), universal.SecondaryOperation, multiplication); err != nil {
		return nil, err
	}
	return out, nil
}

func ScalarFieldModel[
	SF ScalarFieldConstraint[S], S algebra.PrimeFieldElement[S],
](scalarField SF) (*universal.Model[S], error) {
	addition, multiplication, zero, one, negation, inversion, quot, rem, norm, err := models.DeriveStandardFieldOperators(ScalarsSort, scalarField)
	if err != nil {
		return nil, err
	}
	field, err := models.Field(
		ScalarsSort, scalarField,
		addition,
		multiplication,
		zero, one,
		negation, inversion,
		quot, rem, norm,
	)
	if err != nil {
		return nil, err
	}
	if err := field.Algebra().AttachSampler(scalarField.Random); err != nil {
		return nil, err
	}
	if err := field.SetTag(field.Algebra().Signature().Sort(), universal.PrimaryOperation, addition); err != nil {
		return nil, err
	}
	if err := field.SetTag(field.Algebra().Signature().Sort(), universal.SecondaryOperation, multiplication); err != nil {
		return nil, err
	}
	return field, nil
}

func BaseFieldModel[
	BF BaseFieldConstraint[F], F algebra.FieldElement[F],
](baseField BF) (*universal.Model[F], error) {
	addition, multiplication, zero, one, negation, inversion, quot, rem, norm, err := models.DeriveStandardFieldOperators(BaseFieldSort, baseField)
	if err != nil {
		return nil, err
	}
	field, err := models.Field(
		BaseFieldSort, baseField,
		addition,
		multiplication,
		zero, one,
		negation, inversion,
		quot, rem, norm,
	)
	if err != nil {
		return nil, err
	}
	if err := field.Algebra().AttachSampler(baseField.Random); err != nil {
		return nil, err
	}
	if err := field.SetTag(field.Algebra().Signature().Sort(), universal.PrimaryOperation, addition); err != nil {
		return nil, err
	}
	if err := field.SetTag(field.Algebra().Signature().Sort(), universal.SecondaryOperation, multiplication); err != nil {
		return nil, err
	}
	return field, nil
}

func EllipticCurveModel[
	C EllipticCurveConstraint[P, F, S], BF BaseFieldConstraint[F], SR ScalarRingConstraint[S],
	P curves.ECPoint[P, F, S], F algebra.FieldElement[F], S algebra.UintLike[S],

](curve C, baseField BF, scalarRing SR) (*universal.ThreeSortedModel[P, S, F], error) {
	pointAddition, err := universal.NewBinaryOperator(EllipticCurveSort, PointAdditionSymbol, maybe2(algebra.Addition[P]))
	if err != nil {
		return nil, err
	}
	identity, err := universal.NewConstant(EllipticCurveSort, universal.IdentitySymbol(""), curve.OpIdentity())
	if err != nil {
		return nil, err
	}
	scalarAddition, scalarMultiplication, scalarZero, scalarOne, scalarNegation, err := models.DeriveStandardRingOperators(ScalarsSort, scalarRing)
	if err != nil {
		return nil, err
	}
	baseFieldAddition, baseFieldMultiplication, _, _, _, _, _, _, _, err := models.DeriveStandardFieldOperators(BaseFieldSort, baseField)
	if err != nil {
		return nil, err
	}
	scMul, err := aimpl.NewScalarMultiplicationOperator[P, S](EllipticCurveSort, ScalarsSort)
	if err != nil {
		return nil, err
	}
	module, err := models.Module(
		EllipticCurveSort, curve,
		pointAddition,
		identity, PointNegation[P](EllipticCurveSort),

		ScalarsSort, scalarRing,
		scalarAddition, scalarMultiplication, scalarZero, scalarOne, scalarNegation,

		scMul,
	)
	if err != nil {
		return nil, err
	}
	out, err := models.AdjoinBareSort(module, BaseFieldSort, baseField)
	if err != nil {
		return nil, err
	}
	if err := out.Algebra().First().AttachSampler(curve.Random); err != nil {
		return nil, err
	}
	if err := out.Algebra().Second().AttachSampler(scalarRing.Random); err != nil {
		return nil, err
	}
	if err := out.Algebra().Third().AttachSampler(baseField.Random); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().First().Signature().Sort(), universal.PrimaryOperation, pointAddition); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Second().Signature().Sort(), universal.PrimaryOperation, scalarAddition); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Second().Signature().Sort(), universal.SecondaryOperation, scalarMultiplication); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Third().Signature().Sort(), universal.PrimaryOperation, baseFieldAddition); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Third().Signature().Sort(), universal.SecondaryOperation, baseFieldMultiplication); err != nil {
		return nil, err
	}

	return out, nil
}

func CurveModel[
	C CurveConstraint[P, F, S], BF BaseFieldConstraint[F], SF ScalarFieldConstraint[S],
	P curves.Point[P, F, S], F algebra.FieldElement[F], S algebra.PrimeFieldElement[S],
](curve C, baseField BF, scalarField SF) (*universal.ThreeSortedModel[P, S, F], error) {
	pointAddition, err := universal.NewBinaryOperator(PrimeSubGroupSort, PointAdditionSymbol, maybe2(algebra.Addition[P]))
	if err != nil {
		return nil, err
	}
	identity, err := universal.NewConstant(PrimeSubGroupSort, universal.IdentitySymbol(""), curve.OpIdentity())
	if err != nil {
		return nil, err
	}
	generator, err := universal.NewConstant(PrimeSubGroupSort, "G", curve.PrimeSubGroupGenerator())
	if err != nil {
		return nil, err
	}
	scalarAddition, scalarMultiplication, scalarZero, scalarOne, scalarNegation, scalarInversion, scalarQuot, scalarRem, scalarNorm, err := models.DeriveStandardFieldOperators(ScalarsSort, scalarField)
	if err != nil {
		return nil, err
	}
	baseFieldAddition, baseFieldMultiplication, _, _, _, _, _, _, _, err := models.DeriveStandardFieldOperators(BaseFieldSort, baseField)
	if err != nil {
		return nil, err
	}
	scMul, err := aimpl.NewScalarMultiplicationOperator[P, S](EllipticCurveSort, ScalarsSort)
	if err != nil {
		return nil, err
	}
	vs, err := models.VectorSpace(
		EllipticCurveSort, curve,
		pointAddition,
		identity, PointNegation[P](EllipticCurveSort),

		ScalarsSort, scalarField,
		scalarAddition, scalarMultiplication, scalarZero, scalarOne, scalarNegation, scalarInversion,
		scalarQuot, scalarRem, scalarNorm,

		scMul,
	)
	if err != nil {
		return nil, err
	}
	cyclicVs, err := models.MakeCyclic2(vs, generator)
	if err != nil {
		return nil, err
	}
	out, err := models.AdjoinBareSort(cyclicVs, BaseFieldSort, baseField)
	if err != nil {
		return nil, err
	}
	if err := out.Algebra().First().AttachSampler(curve.Random); err != nil {
		return nil, err
	}
	if err := out.Algebra().Second().AttachSampler(scalarField.Random); err != nil {
		return nil, err
	}
	if err := out.Algebra().Third().AttachSampler(baseField.Random); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().First().Signature().Sort(), universal.PrimaryOperation, pointAddition); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Second().Signature().Sort(), universal.PrimaryOperation, scalarAddition); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Second().Signature().Sort(), universal.SecondaryOperation, scalarMultiplication); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Third().Signature().Sort(), universal.PrimaryOperation, baseFieldAddition); err != nil {
		return nil, err
	}
	if err := out.SetTag(out.Algebra().Third().Signature().Sort(), universal.SecondaryOperation, baseFieldMultiplication); err != nil {
		return nil, err
	}
	return out, nil
}

func PairingTargetModel[
	G PairingTargetConstraint[E], E algebra.MultiplicativeGroupElement[E],
](group G) (*universal.Model[E], error) {
	multiplication, err := universal.NewBinaryOperator(
		PairingTargetSort, universal.TimesSymbol, maybe2(algebra.Multiplication[E]),
	)
	if err != nil {
		return nil, err
	}
	identity, err := universal.NewConstant(
		PairingTargetSort, universal.IdentitySymbol(universal.TimesSymbol), group.OpIdentity(),
	)
	if err != nil {
		return nil, err
	}
	inversion, err := universal.NewUnaryOperator(
		PairingTargetSort, universal.InverseSymbol(universal.TimesSymbol), algebra.MaybeInvert[E],
	)
	if err != nil {
		return nil, err
	}
	model, err := models.Group(PairingTargetSort, group, multiplication, identity, inversion)
	if err != nil {
		return nil, err
	}
	if err := model.Algebra().AttachSampler(group.Random); err != nil {
		return nil, err
	}
	if err := model.SetTag(model.Algebra().Signature().Sort(), universal.PrimaryOperation, multiplication); err != nil {
		return nil, err
	}
	return model, nil
}

func maybe[T any](f func(T) T) func(T) (T, error) {
	return func(t T) (T, error) {
		return f(t), nil
	}
}

func maybe2[O, T1, T2 any](f func(T1, T2) O) func(T1, T2) (O, error) {
	return func(t1 T1, t2 T2) (O, error) {
		return f(t1, t2), nil
	}
}
