package models

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	aimpl "github.com/bronlabs/bron-crypto/pkg/base/algebra/impl"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func Amalgamate2[E1 universal.Element[E1], E2 universal.Element[E2]](
	models ...*universal.TwoSortedModel[E1, E2],
) (*universal.TwoSortedModel[E1, E2], error) {
	if len(models) == 0 {
		return nil, errs.NewIsNil("no models provided for amalgamation")
	}
	if len(models) == 1 {
		return models[0], nil
	}
	accum := models[0]
	return iterutils.ReduceOrError(
		slices.Values(models[1:]),
		accum,
		func(m *universal.TwoSortedModel[E1, E2], other *universal.TwoSortedModel[E1, E2]) (*universal.TwoSortedModel[E1, E2], error) {
			if m == nil || other == nil {
				return nil, errs.NewIsNil("at least one of the models are nil")
			}
			if m.First().Sort() != other.First().Sort() || m.Second().Sort() != other.Second().Sort() {
				return nil, errs.NewFailed("models have different sorts")
			}
			theory, err := universal.CoProduct(m.Theory(), other.Theory())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create co-product of theories")
			}
			algebra, err := m.Algebra().Extend(other.Algebra().Interpretation())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create extended algebra")
			}
			accum, err = universal.NewTwoSortedModel(algebra, theory)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create new model from extended algebra and theory")
			}
			return accum, nil
		},
	)
}

func Amalgamate3[E1 universal.Element[E1], E2 universal.Element[E2], E3 universal.Element[E3]](
	models ...*universal.ThreeSortedModel[E1, E2, E3],
) (*universal.ThreeSortedModel[E1, E2, E3], error) {
	if len(models) == 0 {
		return nil, errs.NewIsNil("no models provided for amalgamation")
	}
	if len(models) == 1 {
		return models[0], nil
	}
	accum := models[0]
	return iterutils.ReduceOrError(
		slices.Values(models[1:]),
		accum,
		func(m *universal.ThreeSortedModel[E1, E2, E3], other *universal.ThreeSortedModel[E1, E2, E3]) (*universal.ThreeSortedModel[E1, E2, E3], error) {
			if m == nil || other == nil {
				return nil, errs.NewIsNil("at least one of the models are nil")
			}
			if m.First().Sort() != other.First().Sort() || m.Second().Sort() != other.Second().Sort() ||
				m.Third().Sort() != other.Third().Sort() {
				return nil, errs.NewFailed("models have different sorts")
			}
			theory, err := universal.CoProduct(m.Theory(), other.Theory())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create co-product of theories")
			}
			algebra, err := m.Algebra().Extend(other.Algebra().Interpretation())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create extended algebra")
			}
			accum, err = universal.NewThreeSortedModel(algebra, theory)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create new model from extended algebra and theory")
			}
			return accum, nil
		},
	)
}

func NewSortedStructure[S crtp.Structure[E], E crtp.Element[E]](sort universal.Sort, structure S) *SortedStructure[S, E] {
	return &SortedStructure[S, E]{
		Sort:      sort,
		Structure: structure,
	}
}

type SortedStructure[S crtp.Structure[E], E crtp.Element[E]] struct {
	Sort      universal.Sort
	Structure S
}

func (s *SortedStructure[S, E]) Symbol() universal.Sort {
	return s.Sort
}

func (s *SortedStructure[S, E]) Value() S {
	return s.Structure
}
func AsAbelian[E crtp.Element[E]](model *universal.Model[E], ops ...*universal.BinaryOperator[E]) *universal.Model[E] {
	if model == nil {
		panic(errs.NewIsNil("model cannot be nil"))
	}
	if len(ops) == 0 {
		panic(errs.NewMissing("at least one operator must be provided"))
	}
	if !sliceutils.All(ops, func(op *universal.BinaryOperator[E]) bool {
		return op != nil && model.Algebra().Signature().HasBinary(op.Symbol())
	}) {
		panic(errs.NewMissing("model does not have all provided operators"))
	}
	opsCasted := make([]universal.Operation[universal.BinaryFunctionSymbol], len(ops))
	for i, op := range ops {
		opsCasted[i] = op
	}
	out, err := model.Refine(
		universal.Extend(model.Theory()).IsCommutative(opsCasted...).Finalize(),
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to refine model with commutativity"))
	}
	return out
}

func AsAbelian2[E1 crtp.Element[E1], E2 crtp.Element[E2], OP crtp.Element[OP]](
	model *universal.TwoSortedModel[E1, E2], ops ...*universal.BinaryOperator[OP],
) *universal.TwoSortedModel[E1, E2] {
	if model == nil {
		panic(errs.NewIsNil("model cannot be nil"))
	}
	if len(ops) == 0 {
		panic(errs.NewIsNil("operator cannot be nil"))
	}
	opsCasted := make([]universal.Operation[universal.BinaryFunctionSymbol], len(ops))
	for i, op := range ops {
		if op == nil {
			panic(errs.NewMissing("operator cannot be nil: %d", i))
		}
		factor, exists := model.Algebra().Signature().Factor(op.Profile().Output())
		if !exists {
			panic(errs.NewMissing("model does not have operator %s", op.Symbol()))
		}
		if !factor.HasBinary(op.Symbol()) {
			panic(errs.NewMissing("model does not have operator %s", op.Symbol()))
		}
		opsCasted[i] = op
	}
	out, err := model.Refine(
		universal.Extend(model.Theory()).IsCommutative(opsCasted...).Finalize(),
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to refine model with commutativity"))
	}
	return out
}

func AdjoinBareSort[E1 crtp.Element[E1], E2 crtp.Element[E2], E3 crtp.Element[E3], S3 crtp.Structure[E3]](
	model *universal.TwoSortedModel[E1, E2], extraSort universal.Sort, extraCarrier S3,
) (*universal.ThreeSortedModel[E1, E2, E3], error) {
	if model == nil {
		return nil, errs.NewIsNil("model cannot be nil")
	}
	algebra3, err := universal.AdjoinBareSortToTwoSortedAlgebra[E1, E2, E3](model.Algebra(), NewSortedStructure(extraSort, extraCarrier))
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to adjoin bare sort to two-sorted algebra")
	}
	return universal.NewThreeSortedModel(algebra3, model.Theory())
}

func MakeCyclic[E crtp.Element[E]](model *universal.Model[E], generator *universal.Constant[E]) (*universal.Model[E], error) {
	if model == nil {
		return nil, errs.NewIsNil("model cannot be nil")
	}
	if generator == nil {
		return nil, errs.NewIsNil("generator cannot be nil")
	}
	out, err := model.Refine(
		universal.Extend(model.Theory()).AdjoinConstant(generator).Finalize(),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to refine model with cyclic property")
	}
	return out, nil
}

func MakeCyclic2[E1 crtp.Element[E1], E2 crtp.Element[E2], G crtp.Element[G]](
	model *universal.TwoSortedModel[E1, E2], generator *universal.Constant[G],
) (*universal.TwoSortedModel[E1, E2], error) {
	if model == nil {
		return nil, errs.NewIsNil("model cannot be nil")
	}
	if generator == nil {
		return nil, errs.NewIsNil("generator cannot be nil")
	}
	out, err := model.Refine(
		universal.Extend(model.Theory()).AdjoinConstant(generator).Finalize(),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to refine two-sorted model with cyclic property")
	}
	return out, nil
}

func DeriveStandardRingOperators[R crtp.Ring[S], S crtp.RingElement[S]](
	sort universal.Sort, ring R,
) (
	add, mul *universal.BinaryOperator[S],
	zero, one *universal.Constant[S],
	neg *universal.UnaryOperator[S],
	err error,
) {
	add, err = universal.NewBinaryOperator(sort, universal.PlusSymbol, utils.Maybe2(algebra.Addition[S]))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	mul, err = universal.NewBinaryOperator(sort, universal.TimesSymbol, utils.Maybe2(algebra.Multiplication[S]))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	neg, err = universal.NewUnaryOperator(sort, universal.UnaryFunctionSymbol(universal.MinusSymbol), utils.Maybe(algebra.Negate[S]))
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	zero, err = universal.NewConstant(sort, universal.NullaryFunctionSymbol("0"), ring.Zero())
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	one, err = universal.NewConstant(sort, universal.NullaryFunctionSymbol("1"), ring.One())
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}
	return add, mul, zero, one, neg, nil
}

func EuclideanDivisionOperators[
	D crtp.EuclideanSemiDomain[S], S crtp.EuclideanSemiDomainElement[S],
](sort universal.Sort, domain D) (
	quo, rem *universal.BinaryOperator[S],
	norm *universal.UnaryOperator[S],
	err error,
) {
	quo, err = universal.NewBinaryOperator(
		sort, universal.BinaryFunctionSymbol("/"), func(a S, b S) (S, error) {
			quot, _, err := a.EuclideanDiv(b)
			return quot, err
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}
	rem, err = universal.NewBinaryOperator(
		sort, universal.BinaryFunctionSymbol("%"), func(a S, b S) (S, error) {
			_, rem, err := a.EuclideanDiv(b)
			return rem, err
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}
	norm, err = aimpl.NewEuclideanNormOperator[S](sort)
	if err != nil {
		return nil, nil, nil, err
	}
	return quo, rem, norm, nil
}

func DeriveStandardFieldOperators[F crtp.Field[FE], FE crtp.FieldElement[FE]](
	sort universal.Sort, field F,
) (
	add, mul *universal.BinaryOperator[FE],
	zero, one *universal.Constant[FE],
	neg, inv *universal.UnaryOperator[FE],
	quo, rem *universal.BinaryOperator[FE],
	norm *universal.UnaryOperator[FE],
	err error,
) {
	add, mul, zero, one, neg, err = DeriveStandardRingOperators(sort, field)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	inv, err = universal.NewUnaryOperator(sort, universal.InverseSymbol(universal.TimesSymbol), (algebra.MaybeInvert[FE]))
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	quo, rem, norm, err = EuclideanDivisionOperators(sort, field)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	return add, mul, zero, one, neg, inv, quo, rem, norm, nil
}
