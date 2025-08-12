package models

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/crtp"
	"github.com/bronlabs/bron-crypto/pkg/base/algebra/universal"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

func Set[S crtp.Structure[E], E crtp.Element[E]](sort universal.Sort, set S) (*universal.Model[E], error) {
	table, err := universal.NewInterpretation[E](sort, nil, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create interpretation table")
	}
	algebra, err := universal.NewAlgebra(NewSortedStructure(sort, set), table)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra")
	}
	theory := universal.SetTheory(sort)
	model, err := universal.NewModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func Magma[S crtp.Magma[E], E crtp.MagmaElement[E]](
	sort universal.Sort, magma S, operator *universal.BinaryOperator[E],
) (*universal.Model[E], error) {
	if operator == nil {
		return nil, errs.NewIsNil("operator cannot be nil")
	}
	theory := universal.MagmaTheory(sort, operator)

	table, err := universal.NewInterpretation(sort, nil, nil, []*universal.BinaryOperator[E]{operator})
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create interpretation table")
	}
	algebra, err := universal.NewAlgebra(NewSortedStructure(sort, magma), table)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra")
	}
	model, err := universal.NewModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func SemiGroup[S crtp.SemiGroup[E], E crtp.SemiGroupElement[E]](
	sort universal.Sort, semiGroup S, operator *universal.BinaryOperator[E],
) (*universal.Model[E], error) {
	magmaModel, err := Magma(sort, semiGroup, operator)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create magma model")
	}
	semiGroupModel, err := magmaModel.Refine(
		universal.SemiGroupTheory(sort, operator),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend magma model to semi-group model")
	}
	return semiGroupModel, nil
}

func Monoid[S crtp.Monoid[E], E crtp.MonoidElement[E]](
	sort universal.Sort, monoid S, operator *universal.BinaryOperator[E],
	id *universal.Constant[E],
) (*universal.Model[E], error) {
	semiGroupModel, err := SemiGroup(sort, monoid, operator)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create semi-group model")
	}
	delta, err := universal.NewInterpretation(sort, []*universal.Constant[E]{id}, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create interpretation table containing id id")
	}
	monoidAlgebra, err := semiGroupModel.Algebra().Extend(delta)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend semi-group algebra with id")
	}
	return semiGroupModel.RefineAndReInterpret(
		universal.MonoidTheory(sort, operator, id),
		monoidAlgebra,
	)
}

func Group[S crtp.Group[E], E crtp.GroupElement[E]](
	sort universal.Sort, group S, operator *universal.BinaryOperator[E],
	id *universal.Constant[E], inv *universal.UnaryOperator[E],
) (*universal.Model[E], error) {
	monoidModel, err := Monoid(sort, group, operator, id)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create monoid model")
	}
	delta, err := universal.NewInterpretation(sort, nil, []*universal.UnaryOperator[E]{inv}, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create interpretation table containing inverse operator")
	}
	groupAlgebra, err := monoidModel.Algebra().Extend(delta)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend monoid algebra with inverse operator")
	}
	return monoidModel.RefineAndReInterpret(
		universal.GroupTheory(sort, operator, id, inv),
		groupAlgebra,
	)
}

func CyclicGroup[S crtp.CyclicGroup[E], E crtp.CyclicGroupElement[E]](
	sort universal.Sort, group S, operator *universal.BinaryOperator[E],
	id *universal.Constant[E], inv *universal.UnaryOperator[E],
	generator *universal.Constant[E],
) (*universal.Model[E], error) {
	groupModel, err := Group(sort, group, operator, id, inv)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create group model")
	}
	out, err := groupModel.Refine(
		universal.DlogHardGroupTheory(sort, operator, id, inv, generator),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to refine group model with DlogHardGroupTheory")
	}
	return out, nil
}

func DoubleMagma[S crtp.DoubleMagma[E], E crtp.DoubleMagmaElement[E]](
	sort universal.Sort, doubleMagma S, add, mul *universal.BinaryOperator[E],
) (*universal.Model[E], error) {
	if add == nil || mul == nil {
		return nil, errs.NewIsNil("add and mul operators cannot be nil")
	}
	theory := universal.DoubleMagmaTheory(sort, add, mul)
	table, err := universal.NewInterpretation(sort, nil, nil, []*universal.BinaryOperator[E]{add, mul})
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create interpretation table")
	}
	algebra, err := universal.NewAlgebra(NewSortedStructure(sort, doubleMagma), table)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra")
	}
	out, err := universal.NewModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return out, nil
}

func HemiRing[S crtp.HemiRing[E], E crtp.HemiRingElement[E]](
	sort universal.Sort, hemiRing S, add, mul *universal.BinaryOperator[E],
) (*universal.Model[E], error) {
	doubleMagmaModel, err := DoubleMagma(sort, hemiRing, add, mul)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create double magma model")
	}
	out, err := doubleMagmaModel.Refine(
		universal.HemiRingTheory(sort, add, mul),
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to refine double magma model with hemi-ring theory")
	}
	return out, nil
}

func SemiRing[S crtp.SemiRing[E], E crtp.SemiRingElement[E]](
	sort universal.Sort, semiRing S, add, mul *universal.BinaryOperator[E],
	id *universal.Constant[E],
) (*universal.Model[E], error) {
	hemiRingModel, err := HemiRing(sort, semiRing, add, mul)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create hemi-ring model")
	}
	delta, err := universal.NewInterpretation(sort, []*universal.Constant[E]{id}, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "couldn't create interpretation table containing id")
	}
	semiRingAlgebra, err := hemiRingModel.Algebra().Extend(delta)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend hemi-ring algebra with id")
	}
	return hemiRingModel.RefineAndReInterpret(
		universal.SemiRingTheory(sort, add, mul, id),
		semiRingAlgebra,
	)
}

func Rig[S crtp.Rig[E], E crtp.RigElement[E]](
	sort universal.Sort, rig S, add, mul *universal.BinaryOperator[E],
	zero, one *universal.Constant[E],
) (*universal.Model[E], error) {
	if add == nil || mul == nil || zero == nil || one == nil {
		return nil, errs.NewIsNil("add, mul, zero, and one cannot be nil")
	}
	theory := universal.RigTheory(sort, add, mul, zero, one)
	table, err := universal.NewInterpretation(
		sort, []*universal.Constant[E]{zero, one}, nil,
		[]*universal.BinaryOperator[E]{add, mul},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create interpretation table")
	}
	algebra, err := universal.NewAlgebra(NewSortedStructure(sort, rig), table)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra")
	}
	model, err := universal.NewModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func EuclideanSemiDomain[S crtp.EuclideanSemiDomain[E], E crtp.EuclideanSemiDomainElement[E]](
	sort universal.Sort, euclideanSemiDomain S, add, mul *universal.BinaryOperator[E],
	zero, one *universal.Constant[E], quo, rem *universal.BinaryOperator[E],
	norm *universal.UnaryOperator[E],
) (*universal.Model[E], error) {
	if add == nil || mul == nil || zero == nil || one == nil || quo == nil || rem == nil || norm == nil {
		return nil, errs.NewIsNil("add, mul, zero, one, quo, rem, and norm cannot be nil")
	}
	theory := universal.EuclideanSemiDomainTheory(sort, add, mul, zero, one, quo, rem, norm)
	table, err := universal.NewInterpretation(
		sort,
		[]*universal.Constant[E]{zero, one},
		[]*universal.UnaryOperator[E]{norm},
		[]*universal.BinaryOperator[E]{add, mul, quo, rem},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create interpretation table")
	}
	algebra, err := universal.NewAlgebra(NewSortedStructure(sort, euclideanSemiDomain), table)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra")
	}
	model, err := universal.NewModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func Rng[S crtp.Rng[E], E crtp.RngElement[E]](
	sort universal.Sort, rng S, add, mul *universal.BinaryOperator[E],
	zero *universal.Constant[E], neg *universal.UnaryOperator[E],
) (*universal.Model[E], error) {
	if add == nil || mul == nil || zero == nil || neg == nil {
		return nil, errs.NewIsNil("add, mul, zero, and neg cannot be nil")
	}
	theory := universal.RngTheory(sort, add, mul, zero, neg)
	table, err := universal.NewInterpretation(
		sort, []*universal.Constant[E]{zero}, []*universal.UnaryOperator[E]{neg},
		[]*universal.BinaryOperator[E]{add, mul},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create interpretation table")
	}
	algebra, err := universal.NewAlgebra(NewSortedStructure(sort, rng), table)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra")
	}
	model, err := universal.NewModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func Ring[S crtp.Ring[E], E crtp.RingElement[E]](
	sort universal.Sort, ring S, add, mul *universal.BinaryOperator[E],
	zero, one *universal.Constant[E], neg *universal.UnaryOperator[E],
) (*universal.Model[E], error) {
	if add == nil || mul == nil || zero == nil || one == nil || neg == nil {
		return nil, errs.NewIsNil("add, mul, zero, one, and neg cannot be nil")
	}
	theory := universal.RingTheory(sort, add, mul, zero, one, neg)
	table, err := universal.NewInterpretation(
		sort,
		[]*universal.Constant[E]{zero, one},
		[]*universal.UnaryOperator[E]{neg},
		[]*universal.BinaryOperator[E]{add, mul},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create interpretation table")
	}
	algebra, err := universal.NewAlgebra(NewSortedStructure(sort, ring), table)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra")
	}
	model, err := universal.NewModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func EuclideanDomain[S crtp.EuclideanDomain[E], E crtp.EuclideanDomainElement[E]](
	sort universal.Sort, euclideanDomain S, add, mul *universal.BinaryOperator[E],
	zero, one *universal.Constant[E], neg *universal.UnaryOperator[E], quo, rem *universal.BinaryOperator[E],
	norm *universal.UnaryOperator[E],
) (*universal.Model[E], error) {
	if add == nil || mul == nil || zero == nil || one == nil || neg == nil || quo == nil || rem == nil || norm == nil {
		return nil, errs.NewIsNil("add, mul, zero, one, neg, quo, rem, and norm cannot be nil")
	}
	theory := universal.EuclideanDomainTheory(sort, add, mul, zero, one, neg, quo, rem, norm)
	table, err := universal.NewInterpretation(
		sort,
		[]*universal.Constant[E]{zero, one},
		[]*universal.UnaryOperator[E]{norm},
		[]*universal.BinaryOperator[E]{add, mul, quo, rem},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create interpretation table")
	}
	algebra, err := universal.NewAlgebra(NewSortedStructure(sort, euclideanDomain), table)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra")
	}
	model, err := universal.NewModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func Field[S crtp.Field[E], E crtp.FieldElement[E]](
	sort universal.Sort, field S, add, mul *universal.BinaryOperator[E],
	zero, one *universal.Constant[E], neg, inv *universal.UnaryOperator[E],
	quo, rem *universal.BinaryOperator[E], norm *universal.UnaryOperator[E],
) (*universal.Model[E], error) {
	if add == nil || mul == nil || zero == nil || one == nil || neg == nil || inv == nil || quo == nil || rem == nil || norm == nil {
		return nil, errs.NewIsNil("add, mul, zero, one, neg, inv, quo, rem, and norm cannot be nil")
	}
	theory := universal.FieldTheory(sort, add, mul, zero, one, neg, inv, quo, rem, norm)
	table, err := universal.NewInterpretation(
		sort,
		[]*universal.Constant[E]{zero, one},
		[]*universal.UnaryOperator[E]{neg, inv, norm},
		[]*universal.BinaryOperator[E]{add, mul, quo, rem},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create interpretation table")
	}
	algebra, err := universal.NewAlgebra(NewSortedStructure(sort, field), table)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra")
	}
	model, err := universal.NewModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func SemiModule[M crtp.SemiModule[E, S], SR crtp.SemiRing[S], E crtp.SemiModuleElement[E, S], S crtp.SemiRingElement[S]](
	semiModuleSort universal.Sort, semiModule M,
	op *universal.BinaryOperator[E], id *universal.Constant[E],

	scalarSort universal.Sort, scalarSemiRing SR,
	add, mul *universal.BinaryOperator[S], one *universal.Constant[S],

	scMul *universal.LeftAction[S, E],
) (*universal.TwoSortedModel[E, S], error) {
	if op == nil || id == nil || add == nil || mul == nil || one == nil || scMul == nil {
		return nil, errs.NewIsNil("op, id, add, mul, one, and scMul cannot be nil")
	}
	monoidModel, err := Monoid(semiModuleSort, semiModule, op, id)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create monoid model for semi-module")
	}
	semiRingModel, err := SemiRing(scalarSort, scalarSemiRing, add, mul, one)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create semi-ring model for semi-module")
	}
	theory := universal.SemiModuleTheory(
		semiModuleSort, op, id,
		scalarSort, add, mul, one,
		scMul,
	)
	table, err := universal.NewTwoSortedInterpretation(
		monoidModel.Algebra().Interpretation(),
		semiRingModel.Algebra().Interpretation(),
		nil, nil, nil, nil, nil, nil,
		[]*universal.LeftAction[S, E]{scMul}, nil,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create two-sorted interpretation table")
	}
	algebra, err := universal.NewTwoSortedAlgebra(
		monoidModel.Algebra(),
		semiRingModel.Algebra(),
		table,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create two-sorted algebra")
	}
	model, err := universal.NewTwoSortedModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func Module[M crtp.Module[E, S], R crtp.Ring[S], E crtp.ModuleElement[E, S], S crtp.RingElement[S]](
	moduleSort universal.Sort, module M,
	op *universal.BinaryOperator[E], id *universal.Constant[E], inv *universal.UnaryOperator[E],

	ringSort universal.Sort, ring R,
	add, mul *universal.BinaryOperator[S], zero, one *universal.Constant[S],
	neg *universal.UnaryOperator[S],

	scMul *universal.LeftAction[S, E],
) (*universal.TwoSortedModel[E, S], error) {
	if op == nil || id == nil || inv == nil || add == nil || mul == nil || zero == nil || one == nil || neg == nil || scMul == nil {
		return nil, errs.NewIsNil("op, id, inv, add, mul, zero, one, neg, and scMul cannot be nil")
	}
	groupModel, err := Group(moduleSort, module, op, id, inv)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create group model for module")
	}
	ringModel, err := Ring(ringSort, ring, add, mul, zero, one, neg)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ring model for module")
	}
	theory := universal.ModuleTheory(
		moduleSort, op, id, inv,
		ringSort, add, mul, zero, one, neg,
		scMul,
	)
	table, err := universal.NewTwoSortedInterpretation(
		groupModel.Algebra().Interpretation(),
		ringModel.Algebra().Interpretation(),
		nil, nil, nil, nil, nil, nil,
		[]*universal.LeftAction[S, E]{scMul}, nil,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create two-sorted interpretation table")
	}
	algebra, err := universal.NewTwoSortedAlgebra(
		groupModel.Algebra(),
		ringModel.Algebra(),
		table,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create two-sorted algebra")
	}
	model, err := universal.NewTwoSortedModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func VectorSpace[V crtp.VectorSpace[E, S], F crtp.Field[S], E crtp.Vector[E, S], S crtp.FieldElement[S]](
	vectorSpaceSort universal.Sort, vectorSpace V,
	op *universal.BinaryOperator[E], id *universal.Constant[E], inv *universal.UnaryOperator[E],

	fieldSort universal.Sort, field F,
	add, mul *universal.BinaryOperator[S], zero, one *universal.Constant[S],
	neg, invF *universal.UnaryOperator[S],
	quo, rem *universal.BinaryOperator[S], euclideanNorm *universal.UnaryOperator[S],

	scMul *universal.LeftAction[S, E],
) (*universal.TwoSortedModel[E, S], error) {
	if op == nil || id == nil || inv == nil || add == nil || mul == nil || zero == nil || one == nil || neg == nil || invF == nil || quo == nil || rem == nil || euclideanNorm == nil || scMul == nil {
		return nil, errs.NewIsNil("op, id, inv, add, mul, zero, one, neg, invF, quo, rem, euclideanNorm, and scMul cannot be nil")
	}
	groupModel, err := Group(vectorSpaceSort, vectorSpace, op, id, inv)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create group model for vector space")
	}
	fieldModel, err := Field(fieldSort, field, add, mul, zero, one, neg, invF, quo, rem, euclideanNorm)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create field model for vector space")
	}
	theory := universal.VectorSpaceTheory(
		vectorSpaceSort, op, id, inv,
		fieldSort, add, mul, zero, one, neg, inv, quo, rem, euclideanNorm,
		scMul,
	)
	table, err := universal.NewTwoSortedInterpretation(
		groupModel.Algebra().Interpretation(),
		fieldModel.Algebra().Interpretation(),
		nil, nil, nil, nil, nil, nil,
		[]*universal.LeftAction[S, E]{scMul}, nil,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create two-sorted interpretation table")
	}
	algebra, err := universal.NewTwoSortedAlgebra(
		groupModel.Algebra(),
		fieldModel.Algebra(),
		table,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create two-sorted algebra")
	}
	model, err := universal.NewTwoSortedModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}

func RAlgebra[A crtp.Algebra[E, S], R crtp.Ring[S], E crtp.AlgebraElement[E, S], S crtp.RingElement[S]](
	rAlgebraSort universal.Sort, rAlgebra A,
	addA, mulA *universal.BinaryOperator[E], zeroA, oneA *universal.Constant[E], negA *universal.UnaryOperator[E],

	ringSort universal.Sort, ring R,
	addR, mulR *universal.BinaryOperator[S], zeroR, oneR *universal.Constant[S], negR *universal.UnaryOperator[S],

	scMul *universal.LeftAction[S, E],
) (*universal.TwoSortedModel[E, S], error) {
	if addA == nil || mulA == nil || zeroA == nil || oneA == nil || negA == nil ||
		addR == nil || mulR == nil || zeroR == nil || oneR == nil || negR == nil {
		return nil, errs.NewIsNil("addA, mulA, zeroA, oneA, negA, addR, mulR, zeroR, oneR, negR, and scMul cannot be nil")
	}
	mainModel, err := Ring(rAlgebraSort, rAlgebra, addA, mulA, zeroA, oneA, negA)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create ring model for R-algebra")
	}
	underlyingModel, err := Ring(ringSort, ring, addR, mulR, zeroR, oneR, negR)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create base ring model for R-algebra")
	}
	theory := universal.RAlgebraTheory(
		rAlgebraSort, addA, mulA, zeroA, oneA, negA,
		ringSort, addR, mulR, zeroR, oneR, negR,
		scMul,
	)
	table, err := universal.NewTwoSortedInterpretation(
		mainModel.Algebra().Interpretation(),
		underlyingModel.Algebra().Interpretation(),
		nil, nil, nil, nil, nil, nil,
		[]*universal.LeftAction[S, E]{scMul}, nil,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create two-sorted interpretation table")
	}
	algebra, err := universal.NewTwoSortedAlgebra(
		mainModel.Algebra(),
		underlyingModel.Algebra(),
		table,
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create two-sorted algebra")
	}
	model, err := universal.NewTwoSortedModel(algebra, theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create model")
	}
	return model, nil
}
