package model

import (
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func ExpandLanguage[E Element[E]](given *Language[E]) *LanguageExpansion[E] {
	if given == nil {
		given = NewEmptyLanguage[E]()
	}
	return &LanguageExpansion[E]{
		language: given.Clone(),
	}
}

type LanguageExpansion[E Element[E]] struct {
	language *Language[E]
}

func (s *LanguageExpansion[E]) WithConstant(c *Constant[E]) *LanguageExpansion[E] {
	l, err := NewLanguage([]*Constant[E]{c}, nil, nil)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create language with constant %s", c.Symbol()))
	}
	s.language, err = s.language.Union(l)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to extend language with constant %s", c.Symbol()))
	}
	return s
}

func (s *LanguageExpansion[E]) WithUnaryOperator(op *UnaryOperator[E]) *LanguageExpansion[E] {
	l, err := NewLanguage(nil, []*UnaryOperator[E]{op}, nil)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create language with unary operator %s", op.Symbol()))
	}
	s.language, err = s.language.Union(l)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to extend language with unary operator %s", op.Symbol()))
	}
	return s
}

func (s *LanguageExpansion[E]) WithBinaryOperator(op *BinaryOperator[E]) *LanguageExpansion[E] {
	l, err := NewLanguage(nil, nil, []*BinaryOperator[E]{op})
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create language with binary operator %s", op.Symbol()))
	}
	s.language, err = s.language.Union(l)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to extend language with binary operator %s", op.Symbol()))
	}
	return s
}

func (s *LanguageExpansion[E]) Finalize() *Language[E] {
	return s.language.Clone()
}

func Extend[E Element[E]](model *Model[E]) *ModelExtension[E] {
	if model == nil {
		model = NewEmpty[E]()
	}
	return &ModelExtension[E]{
		m: model,
	}
}

func Amalgamate[E Element[E]](models ...*Model[E]) *ModelExtension[E] {
	if len(models) == 0 {
		return Extend[E](nil)
	}
	if len(models) == 1 {
		return Extend(models[0])
	}
	if sliceutils.CountUniqueFunc(models, func(m *Model[E]) Symbol {
		return m.algebra.universe.Symbol()
	}) != 1 {
		panic(errs.NewFailed("cannot merge models with different universe symbols"))
	}
	merged := models[0].Clone()
	for _, m := range models[1:] {
		if m == nil {
			continue
		}
		l, err := merged.Language().Union(m.Language())
		if err != nil {
			panic(errs.WrapFailed(err, "failed to merge languages"))
		}
		merged.setLanguage(l)
	}
	return &ModelExtension[E]{
		m: merged,
	}
}

type ModelExtension[E Element[E]] struct {
	m *Model[E]
}

func (t *ModelExtension[E]) AdjoinConstant(c *Constant[E]) *ModelExtension[E] {
	L := ExpandLanguage(t.m.Language()).WithConstant(c).Finalize()
	t.m.setLanguage(L)
	return t
}

func (t *ModelExtension[E]) EnrichWithUnaryOperator(op *UnaryOperator[E]) *ModelExtension[E] {
	L := ExpandLanguage(t.m.Language()).WithUnaryOperator(op).Finalize()
	t.m.setLanguage(L)
	return t
}

func (t *ModelExtension[E]) EnrichWithBinaryOperator(op *BinaryOperator[E]) *ModelExtension[E] {
	L := ExpandLanguage(t.m.Language()).WithBinaryOperator(op).Finalize()
	t.m.setLanguage(L)
	return t
}

func (t *ModelExtension[E]) IsClosed1(under *UnaryOperator[E], conditions ...func(E) bool) *ModelExtension[E] {
	if !sliceutils.ContainsEqualFunc(t.m.Language().unary, under, func(x, y *UnaryOperator[E]) bool {
		return x.Equal(y)
	}) {
		panic(errs.NewFailed("unary operator %s is not defined in the language", under.Symbol()))
	}
	property := &ClosureProperty1[E]{
		set: t.m.algebra.universe,
		op:  under,
	}
	t.m.theory.rank1[property.Law()] = &Axiom1[E]{
		law:        property.Law(),
		language:   t.m.Language(),
		check:      property.Check,
		conditions: conditions,
	}
	return t
}

func (t *ModelExtension[E]) IsClosed2(under *BinaryOperator[E], conditions ...func(E, E) bool) *ModelExtension[E] {
	if !sliceutils.ContainsEqualFunc(t.m.Language().binary, under, func(x, y *BinaryOperator[E]) bool {
		return x.Equal(y)
	}) {
		panic(errs.NewFailed("binary operator %s is not defined in the language", under.Symbol()))
	}
	property := &ClosureProperty2[E]{
		set: t.m.algebra.universe,
		op:  under,
	}
	t.m.theory.rank2[property.Law()] = &Axiom2[E]{
		law:        property.Law(),
		language:   t.m.Language(),
		check:      property.Check,
		conditions: conditions,
	}
	return t
}

func (t *ModelExtension[E]) IsAssociative(under *BinaryOperator[E], conditions ...func(E, E, E) bool) *ModelExtension[E] {
	if !sliceutils.ContainsEqualFunc(t.m.Language().binary, under, func(x, y *BinaryOperator[E]) bool {
		return x.Equal(y)
	}) {
		panic(errs.NewFailed("binary operator %s is not defined in the language", under.Symbol()))
	}
	property := &AssociativeProperty[E]{
		set: t.m.algebra.universe,
		op:  under,
	}
	t.m.theory.rank3[property.Law()] = &Axiom3[E]{
		law:        property.Law(),
		language:   t.m.Language(),
		check:      property.Check,
		conditions: conditions,
	}
	return t
}

func (t *ModelExtension[E]) WithIdentityElement(id *Constant[E], under *BinaryOperator[E], conditions ...func(E) bool) *ModelExtension[E] {
	if !sliceutils.ContainsEqualFunc(t.m.Language().binary, under, func(x, y *BinaryOperator[E]) bool {
		return x.Equal(y)
	}) {
		panic(errs.NewFailed("binary operator %s is not defined in the language", under.Symbol()))
	}
	t.AdjoinConstant(id)
	property := &IdentityElementProperty[E]{
		set: t.m.algebra.universe,
		op:  under,
		id:  id,
	}
	t.m.theory.rank1[property.Law()] = &Axiom1[E]{
		law:        property.Law(),
		language:   t.m.Language(),
		check:      property.Check,
		conditions: slices.Clone(conditions),
	}
	return t
}

func (t *ModelExtension[E]) WithInverseOperator(inv *UnaryOperator[E], under *BinaryOperator[E], conditions ...func(E) bool) *ModelExtension[E] {
	if !sliceutils.ContainsEqualFunc(t.m.Language().binary, under, func(x, y *BinaryOperator[E]) bool {
		return x.Equal(y)
	}) {
		panic(errs.NewFailed("binary operator %s is not defined in the language", under.Symbol()))
	}
	correspondingIdentityIndex := slices.IndexFunc(t.m.Language().nullary, func(c *Constant[E]) bool {
		return c.Symbol() == IdentitySymbol(under)
	})
	if correspondingIdentityIndex == -1 {
		panic(errs.NewFailed("identity element for operator %s is not defined in the language", under.Symbol()))
	}
	correspondingIdentity := t.m.Language().nullary[correspondingIdentityIndex]
	t.EnrichWithUnaryOperator(inv)
	property := &InverseElementProperty[E]{
		set: t.m.algebra.universe,
		op:  under,
		inv: inv,
		id:  correspondingIdentity,
	}
	t.m.theory.rank1[property.Law()] = &Axiom1[E]{
		law:        property.Law(),
		language:   t.m.Language(),
		check:      property.Check,
		conditions: slices.Clone(conditions),
	}
	return t
}

func (t *ModelExtension[E]) IsCommutative(under *BinaryOperator[E], conditions ...func(E, E) bool) *ModelExtension[E] {
	if !sliceutils.ContainsEqualFunc(t.m.Language().binary, under, func(x, y *BinaryOperator[E]) bool {
		return x.Equal(y)
	}) {
		panic(errs.NewFailed("binary operator %s is not defined in the language", under.Symbol()))
	}
	property := &CommutativeProperty[E]{
		set: t.m.algebra.universe,
		op:  under,
	}
	t.m.theory.rank2[property.Law()] = &Axiom2[E]{
		law:        property.Law(),
		language:   t.m.Language(),
		check:      property.Check,
		conditions: slices.Clone(conditions),
	}
	return t
}

func (t *ModelExtension[E]) WithDistributiveProperty(op, over *BinaryOperator[E], conditions ...func(E, E, E) bool) *ModelExtension[E] {
	for _, f := range []*BinaryOperator[E]{op, over} {
		if !sliceutils.ContainsEqualFunc(t.m.Language().binary, f, func(x, y *BinaryOperator[E]) bool {
			return x.Equal(y)
		}) {
			panic(errs.NewFailed("binary operator %s is not defined in the language", f.Symbol()))
		}
	}
	property := &DistributiveProperty[E]{
		set:  t.m.algebra.universe,
		op:   op,
		over: over,
	}
	t.m.theory.rank3[property.Law()] = &Axiom3[E]{
		law:        property.Law(),
		language:   t.m.Language(),
		check:      property.Check,
		conditions: slices.Clone(conditions),
	}
	return t
}

func (t *ModelExtension[E]) Finalize() *Model[E] {
	return t.m.Clone()
}
