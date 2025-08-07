package universal

import (
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
)

type Model[E Element[E]] struct {
	algebra *Algebra[E]
	theory  *Theory
	TagStoreTrait
}

func validateModelArgs(algebra interface {
	SupportsSignature(*Theory) bool
}, theory *Theory) error {
	if algebra == nil {
		return errs.NewIsNil("algebra cannot be nil")
	}
	if theory == nil {
		return errs.NewIsNil("theory cannot be nil")
	}
	if !algebra.SupportsSignature(theory) {
		return errs.NewFailed("algebra does not satisfy the theory")
	}
	return nil
}

func NewModel[E Element[E]](algebra *Algebra[E], theory *Theory) (*Model[E], error) {
	if err := validateModelArgs(algebra, theory); err != nil {
		return nil, err
	}
	trait := TagStoreTrait{
		v: NewTagStore(algebra.interp.sort),
	}
	return &Model[E]{algebra: algebra, theory: theory, TagStoreTrait: trait}, nil
}

func (m *Model[E]) Sort() Sort {
	return m.algebra.interp.sort
}

func (m *Model[E]) Algebra() *Algebra[E] {
	return m.algebra
}

func (m *Model[E]) Theory() *Theory {
	return m.theory
}

func (m *Model[E]) Clone() *Model[E] {
	return &Model[E]{algebra: m.algebra.Clone(), theory: m.theory.Clone()}
}

func (m *Model[E]) Refine(theory *Theory) (*Model[E], error) {
	if theory == nil {
		return nil, errs.NewIsNil("theory cannot be nil")
	}
	if !m.theory.IsSubTheory(theory) {
		return nil, errs.NewFailed("theory is not a sub-theory of the model's theory")
	}
	if err := validateModelArgs(m.algebra, theory); err != nil {
		return nil, err
	}
	return &Model[E]{algebra: m.algebra.Clone(), theory: theory.Clone()}, nil
}

func (m *Model[E]) ReInterpret(algebra *Algebra[E]) (*Model[E], error) {
	if algebra == nil {
		return nil, errs.NewIsNil("algebra cannot be nil")
	}
	if !algebra.SupportsSignature(m.theory) {
		return nil, errs.NewFailed("algebra does not satisfy the model's theory")
	}
	if !m.algebra.IsSubAlgebra(algebra) {
		return nil, errs.NewFailed("algebra is not a sub‑algebra of the model's algebra")
	}
	return &Model[E]{
		algebra: algebra,
		theory:  m.theory.Clone(),
	}, nil
}

func (m *Model[E]) RefineAndReInterpret(theory *Theory, algebra *Algebra[E]) (*Model[E], error) {
	refined, err := m.Refine(theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend model with the theory")
	}
	if algebra == nil {
		return refined, nil
	}
	out, err := refined.ReInterpret(algebra)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to reinterpret model with the factor algebra")
	}
	return out, nil
}

func (m *Model[E]) Union(others ...*Model[E]) (*Model[E], error) {
	accum := m.Clone()
	return iterutils.ReduceOrError(
		slices.Values(others),
		accum,
		func(m *Model[E], other *Model[E]) (*Model[E], error) {
			if m == nil || other == nil {
				return nil, errs.NewIsNil("at least one of the models are nil")
			}
			if m.Sort() != other.Sort() {
				return nil, errs.NewFailed("models have different sorts")
			}
			theory, err := CoProduct(m.Theory(), other.Theory())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create co-product of theories")
			}
			algebra, err := m.Algebra().Extend(other.Algebra().Interpretation())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create extended algebra")
			}
			accum, err = NewModel(algebra, theory)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create new model from extended algebra and theory")
			}
			accum.TagStoreTrait.v, err = mergeTagStores(m.tags(), other.tags())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to merge tags from models")
			}
			return accum, nil
		},
	)
}

type TwoSortedModel[E1 Element[E1], E2 Element[E2]] struct {
	algebra *TwoSortedAlgebra[E1, E2]
	theory  *Theory
	TagStoreTrait
}

func NewTwoSortedModel[E1 Element[E1], E2 Element[E2]](
	algebra *TwoSortedAlgebra[E1, E2], theory *Theory,
) (*TwoSortedModel[E1, E2], error) {
	if err := validateModelArgs(algebra, theory); err != nil {
		return nil, err
	}
	trait := TagStoreTrait{
		v: NewTagStore(theory.Sorts().List()...),
	}
	return &TwoSortedModel[E1, E2]{algebra: algebra, theory: theory, TagStoreTrait: trait}, nil
}

func (m *TwoSortedModel[E1, E2]) Algebra() *TwoSortedAlgebra[E1, E2] {
	return m.algebra
}

func (m *TwoSortedModel[E1, E2]) Theory() *Theory {
	return m.theory
}

func (m *TwoSortedModel[E1, E2]) Sorts() ds.Set[Sort] {
	return m.theory.Sorts()
}

func (m *TwoSortedModel[E1, E2]) Clone() *TwoSortedModel[E1, E2] {
	return &TwoSortedModel[E1, E2]{
		algebra: m.algebra.Clone(),
		theory:  m.theory.Clone(),
	}
}

func (m *TwoSortedModel[E1, E2]) RefineAlongFirst(theory *Theory) (*TwoSortedModel[E1, E2], error) {
	if theory == nil {
		return nil, errs.NewIsNil("theory cannot be nil")
	}
	if !m.First().Theory().IsSubTheory(theory) {
		return nil, errs.NewFailed("theory is not a sub-theory of the model's theory")
	}
	if err := validateModelArgs(m.algebra, theory); err != nil {
		return nil, err
	}
	coprod, err := CoProduct(m.First().Theory(), theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create co-product of theories")
	}
	return &TwoSortedModel[E1, E2]{
		algebra: m.algebra.Clone(),
		theory:  coprod,
	}, nil
}

func (m *TwoSortedModel[E1, E2]) RefineAlongSecond(theory *Theory) (*TwoSortedModel[E1, E2], error) {
	if theory == nil {
		return nil, errs.NewIsNil("theory cannot be nil")
	}
	if !m.Second().Theory().IsSubTheory(theory) {
		return nil, errs.NewFailed("theory is not a sub-theory of the model's theory")
	}
	if err := validateModelArgs(m.algebra, theory); err != nil {
		return nil, err
	}
	coprod, err := CoProduct(m.Second().Theory(), theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create co-product of theories")
	}
	return &TwoSortedModel[E1, E2]{
		algebra: m.algebra.Clone(),
		theory:  coprod,
	}, nil
}

func (m *TwoSortedModel[E1, E2]) Refine(theory *Theory) (*TwoSortedModel[E1, E2], error) {
	if theory == nil {
		return nil, errs.NewIsNil("theory cannot be nil")
	}
	if !m.theory.IsSubTheory(theory) {
		return nil, errs.NewFailed("theory is not a sub-theory of the model's theory")
	}
	if err := validateModelArgs(m.algebra, theory); err != nil {
		return nil, err
	}
	return &TwoSortedModel[E1, E2]{
		algebra: m.algebra.Clone(),
		theory:  theory.Clone(),
	}, nil
}

func (m *TwoSortedModel[E1, E2]) ReInterpretFirst(algebra *Algebra[E1]) (*TwoSortedModel[E1, E2], error) {
	if algebra == nil {
		return nil, errs.NewIsNil("algebra cannot be nil")
	}
	if !algebra.SupportsSignature(m.theory) {
		return nil, errs.NewFailed("algebra does not satisfy the model's theory")
	}
	if !m.algebra.First().IsSubAlgebra(algebra) {
		return nil, errs.NewFailed("algebra is not a sub‑algebra of the model's first factor")
	}
	extended, err := m.algebra.ExtendAlongFirst(algebra.interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend algebra along the first sort")
	}
	return &TwoSortedModel[E1, E2]{
		algebra: extended,
		theory:  m.theory.Clone(),
	}, nil
}

func (m *TwoSortedModel[E1, E2]) ReInterpretSecond(algebra *Algebra[E2]) (*TwoSortedModel[E1, E2], error) {
	if algebra == nil {
		return nil, errs.NewIsNil("algebra cannot be nil")
	}
	if !algebra.SupportsSignature(m.theory) {
		return nil, errs.NewFailed("algebra does not satisfy the model's theory")
	}
	if !m.algebra.Second().IsSubAlgebra(algebra) {
		return nil, errs.NewFailed("algebra is not a sub‑algebra of the model's second factor")
	}
	extended, err := m.algebra.ExtendAlongSecond(algebra.interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend algebra along the second sort")
	}
	return &TwoSortedModel[E1, E2]{
		algebra: extended,
		theory:  m.theory.Clone(),
	}, nil
}

func (m *TwoSortedModel[E1, E2]) ReInterpret(algebra *TwoSortedAlgebra[E1, E2]) (*TwoSortedModel[E1, E2], error) {
	if algebra == nil {
		return nil, errs.NewIsNil("algebra cannot be nil")
	}
	if !algebra.SupportsSignature(m.theory) {
		return nil, errs.NewFailed("algebra does not satisfy the model's theory")
	}
	if !m.algebra.IsSubAlgebra(algebra) {
		return nil, errs.NewFailed("algebra is not a sub‑algebra of the model's algebra")
	}
	return &TwoSortedModel[E1, E2]{
		algebra: algebra,
		theory:  m.theory.Clone(),
	}, nil
}

func (m *TwoSortedModel[E1, E2]) RefineAndReInterpretAlongFirst(
	algebra *Algebra[E1], theory *Theory,
) (*TwoSortedModel[E1, E2], error) {
	refined, err := m.RefineAlongFirst(theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend model with the theory")
	}
	if algebra == nil {
		return refined, nil
	}
	if !m.First().Algebra().IsSubAlgebra(algebra) {
		return nil, errs.NewFailed("algebra is not a sub-algebra of the model's first factor")
	}
	out, err := refined.ReInterpretFirst(algebra)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to reinterpret model with the factor algebra")
	}
	return out, nil
}

func (m *TwoSortedModel[E1, E2]) RefineAndReInterpretAlongSecond(
	algebra *Algebra[E2], theory *Theory,
) (*TwoSortedModel[E1, E2], error) {
	refined, err := m.RefineAlongSecond(theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend model with the theory")
	}
	if algebra == nil {
		return refined, nil
	}
	if !m.Second().Algebra().IsSubAlgebra(algebra) {
		return nil, errs.NewFailed("algebra is not a sub-algebra of the model's second factor")
	}
	out, err := refined.ReInterpretSecond(algebra)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to reinterpret model with the factor algebra")
	}
	return out, nil
}

func (m *TwoSortedModel[E1, E2]) RefineAndReInterpret(
	algebra *TwoSortedAlgebra[E1, E2], theory *Theory,
) (*TwoSortedModel[E1, E2], error) {
	refined, err := m.Refine(theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to refine model")
	}
	if algebra == nil {
		return refined, nil
	}
	if !m.algebra.IsSubAlgebra(algebra) {
		return nil, errs.NewFailed("algebra is not a sub-algebra of the model's algebra")
	}
	extendedAlgebra, err := m.algebra.Extend(algebra.interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend algebra")
	}
	out, err := refined.ReInterpret(extendedAlgebra)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to reinterpret model with the extended algebra")
	}
	return out, nil
}

func (m *TwoSortedModel[E1, E2]) UnionAlongFirst(
	others ...*Model[E1],
) (*TwoSortedModel[E1, E2], error) {
	accum := m.First()
	unionedFirst, err := iterutils.ReduceOrError(
		slices.Values(others),
		accum,
		func(m *Model[E1], other *Model[E1]) (*Model[E1], error) {
			if m == nil || other == nil {
				return nil, errs.NewIsNil("at least one of the models are nil")
			}
			if m.Sort() != other.Sort() {
				return nil, errs.NewFailed("models have different sorts")
			}
			theory, err := CoProduct(m.Theory(), other.Theory())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create co-product of theories")
			}
			algebra, err := m.Algebra().Extend(other.Algebra().Interpretation())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create extended algebra")
			}
			accum, err = NewModel(algebra, theory)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create new model from extended algebra and theory")
			}
			return accum, nil
		},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to union along the first sort")
	}
	out, err := m.RefineAndReInterpretAlongFirst(unionedFirst.algebra, unionedFirst.theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to refine and reinterpret along the first sort")
	}
	out.TagStoreTrait.v, err = iterutils.ReduceOrError(
		slices.Values(others),
		m.TagStoreTrait.v,
		func(ts *TagStore, other *Model[E1]) (*TagStore, error) {
			if ts == nil || other == nil {
				return nil, errs.NewIsNil("at least one of the models are nil")
			}
			return mergeTagStores(ts, other.tags())
		},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to merge tags from models")
	}
	return out, nil
}

func (m *TwoSortedModel[E1, E2]) UnionAlongSecond(
	others ...*Model[E2],
) (*TwoSortedModel[E1, E2], error) {
	accum := m.Second()
	unionedSecond, err := iterutils.ReduceOrError(
		slices.Values(others),
		accum,
		func(m *Model[E2], other *Model[E2]) (*Model[E2], error) {
			if m == nil || other == nil {
				return nil, errs.NewIsNil("at least one of the models are nil")
			}
			if m.Sort() != other.Sort() {
				return nil, errs.NewFailed("models have different sorts")
			}
			theory, err := CoProduct(m.Theory(), other.Theory())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create co-product of theories")
			}
			algebra, err := m.Algebra().Extend(other.Algebra().Interpretation())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create extended algebra")
			}
			accum, err = NewModel(algebra, theory)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create new model from extended algebra and theory")
			}
			return accum, nil
		},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to union along the second sort")
	}
	out, err := m.RefineAndReInterpretAlongSecond(unionedSecond.algebra, unionedSecond.theory)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to refine and reinterpret along the second sort")
	}
	out.TagStoreTrait.v, err = iterutils.ReduceOrError(
		slices.Values(others),
		m.TagStoreTrait.v,
		func(ts *TagStore, other *Model[E2]) (*TagStore, error) {
			if ts == nil || other == nil {
				return nil, errs.NewIsNil("at least one of the models are nil")
			}
			return mergeTagStores(ts, other.tags())
		},
	)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to merge tags from models")
	}

	return out, nil
}

func (m *TwoSortedModel[E1, E2]) Union(
	others ...*TwoSortedModel[E1, E2],
) (*TwoSortedModel[E1, E2], error) {
	accum := m.Clone()
	return iterutils.ReduceOrError(
		slices.Values(others),
		accum,
		func(m *TwoSortedModel[E1, E2], other *TwoSortedModel[E1, E2]) (*TwoSortedModel[E1, E2], error) {
			if m == nil || other == nil {
				return nil, errs.NewIsNil("at least one of the models are nil")
			}
			if !m.Sorts().Equal(other.Sorts()) {
				return nil, errs.NewFailed("models have different sorts")
			}
			theory, err := CoProduct(m.Theory(), other.Theory())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create co-product of theories")
			}
			algebra, err := m.Algebra().Extend(other.Algebra().Interpretation())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create extended algebra")
			}
			accum, err = NewTwoSortedModel(algebra, theory)
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to create new model from extended algebra and theory")
			}
			accum.TagStoreTrait.v, err = mergeTagStores(m.tags(), other.tags())
			if err != nil {
				return nil, errs.WrapFailed(err, "failed to merge tags from models")
			}
			return accum, nil
		},
	)
}

func (m *TwoSortedModel[E1, E2]) First() *Model[E1] {
	return &Model[E1]{algebra: m.algebra.First(), theory: m.theory}
}

func (m *TwoSortedModel[E1, E2]) Second() *Model[E2] {
	return &Model[E2]{algebra: m.algebra.Second(), theory: m.theory}
}

type ThreeSortedModel[E1 Element[E1], E2 Element[E2], E3 Element[E3]] struct {
	algebra *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]
	theory  *Theory
	TagStoreTrait
}

func NewThreeSortedModel[E1 Element[E1], E2 Element[E2], E3 Element[E3]](algebra *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3], theory *Theory) (*ThreeSortedModel[E1, E2, E3], error) {
	if err := validateModelArgs(algebra, theory); err != nil {
		return nil, errs.WrapFailed(err, "failed to validate three-sorted model arguments")
	}
	trait := TagStoreTrait{
		v: NewTagStore(algebra.First().interp.sort, algebra.Second().interp.sort, algebra.Third().interp.sort),
	}
	return &ThreeSortedModel[E1, E2, E3]{
		algebra:       algebra,
		theory:        theory,
		TagStoreTrait: trait,
	}, nil
}

func (m *ThreeSortedModel[E1, E2, E3]) First() *Model[E1] {
	return &Model[E1]{algebra: m.algebra.First(), theory: m.theory}
}

func (m *ThreeSortedModel[E1, E2, E3]) Second() *Model[E2] {
	return &Model[E2]{algebra: m.algebra.Second(), theory: m.theory}
}

func (m *ThreeSortedModel[E1, E2, E3]) Third() *Model[E3] {
	return &Model[E3]{algebra: m.algebra.Third(), theory: m.theory}
}

func (m *ThreeSortedModel[E1, E2, E3]) Algebra() *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3] {
	return m.algebra
}

func (m *ThreeSortedModel[E1, E2, E3]) Theory() *Theory {
	return m.theory
}

// *** Misc

type TagStoreTrait struct {
	v *TagStore
}

func (t *TagStoreTrait) tags() *TagStore {
	return t.v
}

func (t *TagStoreTrait) SetTag(sort Sort, tag OperationTag, op Operation[BinaryFunctionSymbol]) error {
	if err := t.v.Put(sort, tag, op); err != nil {
		return errs.WrapFailed(err, "failed to tag operation")
	}
	return nil
}

func (t *TagStoreTrait) GetTag(sort Sort, tag OperationTag) (Operation[BinaryFunctionSymbol], bool) {
	return t.v.Get(sort, tag)
}
