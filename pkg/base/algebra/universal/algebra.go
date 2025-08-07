package universal

import (
	"io"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type Element[E any] any

type Carrier[E Element[E]] interface {
	Symbol() Sort
}

// *** Single Sorted Algebra ***

func NewAlgebra[E Element[E]](s Carrier[E], interp *Interpretation[E]) (*Algebra[E], error) {
	if s == nil {
		return nil, errs.NewIsNil("sort cannot be nil")
	}
	if interp == nil {
		return nil, errs.NewIsNil("interpretation cannot be nil")
	}
	if interp.Sort() != s.Symbol() {
		return nil, errs.NewIsNil("interpretation sort does not match carrier sort")
	}
	return &Algebra[E]{
		carrier: s,
		interp:  interp,
	}, nil
}

type Algebra[E Element[E]] struct {
	carrier Carrier[E]
	interp  *Interpretation[E]

	// misc
	sampler func(io.Reader) (E, error)
}

func (a *Algebra[E]) Carrier() Carrier[E] {
	return a.carrier
}

func (a *Algebra[E]) Interpretation() *Interpretation[E] {
	return a.interp
}

func (a *Algebra[E]) Signature() *Signature {
	return a.interp.Signature()
}

func (a *Algebra[E]) SupportsSignature(th *Theory) bool {
	if th == nil {
		return false
	}
	factorSignature, exists := th.signature.factors.Get(a.Carrier().Symbol())
	if !exists {
		return false
	}
	return a.Signature().IsSubSignature(factorSignature)
}

func (a *Algebra[E]) IsSubAlgebra(of *Algebra[E]) bool {
	return of != nil &&
		a.Signature().IsSubSignature(of.Signature()) &&
		a.interp.IsSubInterpretation(of.Interpretation())
}

func (a *Algebra[E]) Clone() *Algebra[E] {
	return &Algebra[E]{
		carrier: a.carrier,
		interp:  a.interp.Clone(),
	}
}

func (a *Algebra[E]) Extend(interp *Interpretation[E]) (*Algebra[E], error) {
	if interp == nil {
		return nil, errs.NewIsNil("interpretation table cannot be nil")
	}
	if interp.Sort() != a.Carrier().Symbol() {
		return nil, errs.NewFailed("interpretation sort does not match algebra's carrier sort")
	}
	mergedInterp, err := a.interp.Merge(interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to merge interpretation tables")
	}
	return &Algebra[E]{
		carrier: a.Carrier(),
		interp:  mergedInterp,
	}, nil
}

func (a *Algebra[E]) AttachSampler(sampler func(io.Reader) (E, error)) error {
	if sampler == nil {
		return errs.NewIsNil("sampler cannot be nil")
	}
	if a.sampler != nil {
		return errs.NewFailed("sampler is already attached")
	}
	a.sampler = sampler
	return nil
}

func (a *Algebra[E]) Random(prng io.Reader) (E, error) {
	if a.sampler == nil {
		return *new(E), errs.NewFailed("sampler is not attached")
	}
	return a.sampler(prng)
}

// *** Two Sorted Algebra ***

func NewTwoSortedAlgebra[E1 Element[E1], E2 Element[E2]](first *Algebra[E1], second *Algebra[E2], interp *TwoSortedInterpretation[E1, E2]) (*TwoSortedAlgebra[E1, E2], error) {
	if first == nil {
		return nil, errs.NewIsNil("first algebra cannot be nil")
	}
	if second == nil {
		return nil, errs.NewIsNil("second algebra cannot be nil")
	}
	if interp == nil {
		return nil, errs.NewIsNil("interpretation cannot be nil")
	}
	if first.Carrier().Symbol() != interp.First().sort || second.Carrier().Symbol() != interp.Second().sort {
		return nil, errs.NewIsNil("interpretation sorts do not match algebras' sorts")
	}
	var err error
	if interp.first != nil {
		first, err = first.Extend(interp.first)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to extend first algebra")
		}
	}
	if interp.second != nil {
		second, err = second.Extend(interp.second)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to extend second algebra")
		}
	}
	return &TwoSortedAlgebra[E1, E2]{
		first:  first,
		second: second,
		interp: interp,
	}, nil
}

type TwoSortedAlgebra[E1 Element[E1], E2 Element[E2]] struct {
	first  *Algebra[E1]
	second *Algebra[E2]
	interp *TwoSortedInterpretation[E1, E2]
}

func (a *TwoSortedAlgebra[E1, E2]) First() *Algebra[E1] {
	return a.first
}

func (a *TwoSortedAlgebra[E1, E2]) Second() *Algebra[E2] {
	return a.second
}

func (a *TwoSortedAlgebra[E1, E2]) Interpretation() *TwoSortedInterpretation[E1, E2] {
	return a.interp
}

func (a *TwoSortedAlgebra[E1, E2]) Sorts() []Sort {
	return []Sort{a.first.Carrier().Symbol(), a.second.Carrier().Symbol()}
}

func (a *TwoSortedAlgebra[E1, E2]) SupportsSignature(th *Theory) bool {
	return th != nil && a.interp.Signature().IsSubSignature(th.signature)
}

func (a *TwoSortedAlgebra[E1, E2]) Signature() *MultiSortedSignature {
	return a.interp.Signature()
}

func (a *TwoSortedAlgebra[E1, E2]) ExtendAlongFirst(
	interp *Interpretation[E1],
) (*TwoSortedAlgebra[E1, E2], error) {
	if interp == nil {
		return nil, errs.NewIsNil("interpretation cannot be nil")
	}
	if interp.Sort() != a.first.Carrier().Symbol() {
		return nil, errs.NewFailed("interpretation sort does not match first algebra's carrier sort")
	}
	extendedFirst, err := a.first.Extend(interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend factor algebra")
	}
	return &TwoSortedAlgebra[E1, E2]{
		first:  extendedFirst,
		second: a.second,
		interp: a.interp,
	}, nil
}

func (a *TwoSortedAlgebra[E1, E2]) ExtendAlongSecond(
	interp *Interpretation[E2],
) (*TwoSortedAlgebra[E1, E2], error) {
	if interp == nil {
		return nil, errs.NewIsNil("interpretation cannot be nil")
	}
	if interp.Sort() != a.Second().Carrier().Symbol() {
		return nil, errs.NewFailed("interpretation sort does not match factor algebra's carrier sort")
	}
	extendedSecond, err := a.second.Extend(interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend factor algebra")
	}
	return &TwoSortedAlgebra[E1, E2]{
		first:  a.first,
		second: extendedSecond,
		interp: a.interp,
	}, nil
}

func (a *TwoSortedAlgebra[E1, E2]) Extend(
	interp *TwoSortedInterpretation[E1, E2],
) (*TwoSortedAlgebra[E1, E2], error) {
	if interp == nil {
		return nil, errs.NewIsNil("interpretation cannot be nil")
	}
	if interp.First().Sort() != a.First().Carrier().Symbol() || interp.Second().Sort() != a.Second().Carrier().Symbol() {
		return nil, errs.NewFailed("interpretation sorts do not match algebras' sorts")
	}
	mergedTable, err := a.interp.Merge(interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to merge interpretation tables")
	}
	out := &TwoSortedAlgebra[E1, E2]{
		first:  a.first,
		second: a.second,
		interp: mergedTable,
	}
	if interp.First() != nil {
		out.first, err = out.first.Extend(interp.First())
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to extend first algebra")
		}
	}
	if interp.Second() != nil {
		out.second, err = out.second.Extend(interp.Second())
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to extend second algebra")
		}
	}
	return out, nil
}

func (a *TwoSortedAlgebra[E1, E2]) Clone() *TwoSortedAlgebra[E1, E2] {
	return &TwoSortedAlgebra[E1, E2]{
		first:  a.first.Clone(),
		second: a.second.Clone(),
		interp: a.interp.Clone(),
	}
}

// *** Three sorted Algebra ***

func AdjoinBareSortToTwoSortedAlgebra[E1 Element[E1], E2 Element[E2], E3 Element[E3]](
	a *TwoSortedAlgebra[E1, E2], extraSort Carrier[E3],
) (*TwoSortedAlgebraWithExtraBareSort[E1, E2, E3], error) {
	if a == nil {
		return nil, errs.NewIsNil("two sorted algebra cannot be nil")
	}
	if extraSort == nil {
		return nil, errs.NewIsNil("extra sort cannot be nil")
	}
	trivialInterp, err := NewInterpretation[E3](extraSort.Symbol(), nil, nil, nil)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create trivial interpretation table")
	}
	bareAlgebra, err := NewAlgebra(extraSort, trivialInterp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to create algebra for extra sort")
	}
	return &TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]{
		TwoSortedAlgebra: *a,
		third:            bareAlgebra,
	}, nil
}

func (a *TwoSortedAlgebra[E1, E2]) IsSubAlgebra(of *TwoSortedAlgebra[E1, E2]) bool {
	return of != nil && a.First().IsSubAlgebra(of.First()) && a.Second().IsSubAlgebra(of.Second()) &&
		a.Interpretation().IsSubInterpretation(of.Interpretation())
}

type TwoSortedAlgebraWithExtraBareSort[E1 Element[E1], E2 Element[E2], E3 Element[E3]] struct {
	TwoSortedAlgebra[E1, E2]
	third *Algebra[E3]
}

func (a *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]) Third() *Algebra[E3] {
	return a.third
}

func (a *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]) Sorts() []Sort {
	return append(a.TwoSortedAlgebra.Sorts(), a.Third().Carrier().Symbol())
}

func (a *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]) SupportsSignature(th *Theory) bool {
	return a.TwoSortedAlgebra.SupportsSignature(th) && th.signature.factors.ContainsKey(a.Third().Carrier().Symbol())
}

func (a *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]) Signature() *MultiSortedSignature {
	bareFactorSignature, err := NewSignature(a.third.Signature().sort, nil, nil, nil)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create signature for bare sort"))
	}
	bareSignature, err := NewMultiSortedSignature(
		map[Sort]*Signature{
			a.third.Signature().sort: bareFactorSignature,
		}, nil, nil,
	)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create signature for bare sort"))
	}
	signature, err := a.TwoSortedAlgebra.Signature().Sum(bareSignature)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create signature for two sorted algebra with extra bare sort"))
	}
	return signature
}

func (a *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]) ExtendAlongFirst(
	interp *Interpretation[E1],
) (*TwoSortedAlgebraWithExtraBareSort[E1, E2, E3], error) {
	algebra, err := a.TwoSortedAlgebra.ExtendAlongFirst(interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend along first sort")
	}
	return &TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]{
		TwoSortedAlgebra: *algebra,
		third:            a.third,
	}, nil
}

func (a *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]) ExtendAlongSecond(
	interp *Interpretation[E2],
) (*TwoSortedAlgebraWithExtraBareSort[E1, E2, E3], error) {
	algebra, err := a.TwoSortedAlgebra.ExtendAlongSecond(interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend along second sort")
	}
	return &TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]{
		TwoSortedAlgebra: *algebra,
		third:            a.third,
	}, nil
}

func (a *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]) Extend(
	interp *TwoSortedInterpretation[E1, E2],
) (*TwoSortedAlgebraWithExtraBareSort[E1, E2, E3], error) {
	algebra, err := a.TwoSortedAlgebra.Extend(interp)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to extend along both sorts")
	}
	return &TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]{
		TwoSortedAlgebra: *algebra,
		third:            a.third,
	}, nil
}

func (a *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]) Clone() *TwoSortedAlgebraWithExtraBareSort[E1, E2, E3] {
	clonedInner := a.TwoSortedAlgebra.Clone()
	return &TwoSortedAlgebraWithExtraBareSort[E1, E2, E3]{
		TwoSortedAlgebra: *clonedInner,
		third:            a.third.Clone(),
	}
}
