package model

import (
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type Function[E Element[E]] interface {
	Rank() int
	WithSymbol
	fmt.Stringer
	base.Hashable[Function[E]]
}

func stringifyFunction[E Element[E]](f Function[E]) string {
	return fmt.Sprintf("%s (%d)", f.Symbol(), f.Rank())
}

func Apply[E Element[E]](op Function[E], args ...E) (E, error) {
	if op == nil {
		return *new(E), errs.NewIsNil("function")
	}
	if len(args) != op.Rank() {
		return *new(E), errs.NewFailed("expected %d arguments, got %d", op.Rank(), len(args))
	}
	switch f := op.(type) {
	case *Constant[E]:
		return f.value, nil
	case UnaryOperator[E]:
		return f.call(args[0]), nil
	case BinaryOperator[E]:
		return f.call(args[0], args[1]), nil
	default:
		return *new(E), errs.NewFailed("unknown function type: %T", f)
	}
}

func NewConstant[E Element[E]](value E, symbol Symbol) (*Constant[E], error) {
	if utils.IsNil(value) {
		return nil, errs.NewIsNil("value")
	}
	return &Constant[E]{
		symbol: symbol,
		value:  value,
	}, nil
}

type Constant[E Element[E]] struct {
	symbol Symbol
	value  E
}

func (c *Constant[E]) String() string {
	return stringifyFunction(c)
}

func (c *Constant[E]) Rank() int {
	return 0
}

func (c *Constant[E]) Symbol() Symbol {
	return c.symbol
}

func (c *Constant[E]) Equal(other Function[E]) bool {
	if c == nil || other == nil {
		return c == other
	}
	otherC, ok := other.(*Constant[E])
	if !ok {
		return false
	}
	return c.symbol == otherC.symbol && c.value.Equal(otherC.value)
}

func (c *Constant[E]) HashCode() base.HashCode {
	return base.DeriveHashCode([]byte(c.symbol))
}

func (c *Constant[E]) Clone() *Constant[E] {
	return &Constant[E]{
		symbol: c.symbol,
		value:  c.value,
	}
}

func NewUnaryOperator[E Element[E]](symbol Symbol, f func(E) E) (*UnaryOperator[E], error) {
	if utils.IsNil(f) {
		return nil, errs.NewIsNil("f")
	}
	return &UnaryOperator[E]{symbol: symbol, call: f}, nil
}

type UnaryOperator[E Element[E]] struct {
	symbol Symbol
	call   func(E) E
}

func (u UnaryOperator[E]) String() string {
	return stringifyFunction(u)
}

func (u UnaryOperator[E]) Symbol() Symbol {
	return u.symbol
}

func (u UnaryOperator[E]) Rank() int {
	return 1
}

func (u UnaryOperator[E]) Equal(other Function[E]) bool {
	return other != nil && u.symbol == other.Symbol() && u.Rank() == other.Rank()
}

func (u UnaryOperator[E]) HashCode() base.HashCode {
	return base.DeriveHashCode([]byte(u.symbol))
}

func (u UnaryOperator[E]) Clone() UnaryOperator[E] {
	return UnaryOperator[E]{
		symbol: u.symbol,
		call:   u.call,
	}
}

func NewBinaryOperator[E Element[E]](symbol Symbol, f func(E, E) E) (*BinaryOperator[E], error) {
	if utils.IsNil(f) {
		return nil, errs.NewIsNil("f")
	}
	return &BinaryOperator[E]{symbol: symbol, call: f}, nil
}

type BinaryOperator[E Element[E]] struct {
	symbol Symbol
	call   func(E, E) E
}

func (b BinaryOperator[E]) String() string {
	return stringifyFunction(b)
}
func (b BinaryOperator[E]) Symbol() Symbol {
	return b.symbol
}
func (b BinaryOperator[E]) Rank() int {
	return 2
}

func (b BinaryOperator[E]) Equal(other Function[E]) bool {
	return other != nil && b.symbol == other.Symbol() && b.Rank() == other.Rank()
}

func (b BinaryOperator[E]) HashCode() base.HashCode {
	return base.DeriveHashCode([]byte(b.symbol))
}

func (b *BinaryOperator[E]) Clone() *BinaryOperator[E] {
	return &BinaryOperator[E]{
		symbol: b.symbol,
		call:   b.call,
	}
}

func NewLanguage[E Element[E]](nullary []*Constant[E], unary []*UnaryOperator[E], binary []*BinaryOperator[E]) (*Language[E], error) {
	if len(nullary) != sliceutils.CountUniqueEqualFunc(nullary, func(x, y *Constant[E]) bool {
		return x.Equal(y)
	}) {
		return nil, errs.NewFailed("duplicate nullary constants found")
	}
	if len(unary) != sliceutils.CountUniqueEqualFunc(unary, func(x, y *UnaryOperator[E]) bool {
		return x.Equal(y)
	}) {
		return nil, errs.NewFailed("duplicate unary operators found")
	}
	if len(binary) != sliceutils.CountUniqueEqualFunc(binary, func(x, y *BinaryOperator[E]) bool {
		return x.Equal(y)
	}) {
		return nil, errs.NewFailed("duplicate binary operators found")
	}
	return &Language[E]{
		nullary: nullary,
		unary:   unary,
		binary:  binary,
	}, nil
}

func NewEmptyLanguage[E Element[E]]() *Language[E] {
	out, err := NewLanguage[E](nil, nil, nil)
	if err != nil {
		panic(errs.WrapFailed(err, "failed to create empty language"))
	}
	return out
}

type Language[E Element[E]] struct {
	nullary []*Constant[E]
	unary   []*UnaryOperator[E]
	binary  []*BinaryOperator[E]
}

func (s *Language[E]) Equal(other *Language[E]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return !utils.IsNil(other) &&
		slices.EqualFunc(s.nullary, other.nullary, func(x, y *Constant[E]) bool {
			return x.Equal(y)
		}) &&
		slices.EqualFunc(s.unary, other.unary, func(x, y *UnaryOperator[E]) bool {
			return x.Equal(y)
		}) &&
		slices.EqualFunc(s.binary, other.binary, func(x, y *BinaryOperator[E]) bool {
			return x.Equal(y)
		})
}

func (s *Language[E]) Clone() *Language[E] {
	return &Language[E]{
		nullary: slices.Clone(s.nullary),
		unary:   slices.Clone(s.unary),
		binary:  slices.Clone(s.binary),
	}
}

func (L *Language[E]) IsDefinedUnder(ops ...Function[E]) bool {
	for _, op := range ops {
		switch f := op.(type) {
		case *Constant[E]:
			if !sliceutils.ContainsEqualFunc(L.nullary, f, func(x, y *Constant[E]) bool {
				return x.Equal(y)
			}) {
				return false
			}
		case *UnaryOperator[E]:
			if !sliceutils.ContainsEqualFunc(L.unary, f, func(x, y *UnaryOperator[E]) bool {
				return x.Equal(y)
			}) {
				return false
			}
		case *BinaryOperator[E]:
			if !sliceutils.ContainsEqualFunc(L.binary, f, func(x, y *BinaryOperator[E]) bool {
				return x.Equal(y)
			}) {
				return false
			}
		default:
			panic("unknown function type: " + reflect.TypeOf(op).String())
		}
	}
	return true
}

func (s *Language[E]) IsSublanguage(other *Language[E]) bool {
	return !utils.IsNil(other) &&
		sliceutils.IsSubListFunc(s.nullary, other.nullary, func(x, y *Constant[E]) bool {
			return x.Equal(y)
		}) &&
		sliceutils.IsSubListFunc(s.unary, other.unary, func(x, y *UnaryOperator[E]) bool {
			return x.Equal(y)
		}) &&
		sliceutils.IsSubListFunc(s.binary, other.binary, func(x, y *BinaryOperator[E]) bool {
			return x.Equal(y)
		})
}

func (s *Language[E]) Union(other *Language[E]) (*Language[E], error) {
	out := &Language[E]{
		nullary: make([]*Constant[E], 0, len(s.nullary)+len(other.nullary)),
		unary:   make([]*UnaryOperator[E], 0, len(s.unary)+len(other.unary)),
		binary:  make([]*BinaryOperator[E], 0, len(s.binary)+len(other.binary)),
	}
	nullarySeen := map[Symbol]*Constant[E]{}
	unarySeen := map[Symbol]*UnaryOperator[E]{}
	binarySeen := map[Symbol]*BinaryOperator[E]{}
	copy(out.nullary[:len(s.nullary)], s.nullary)
	copy(out.unary[:len(s.unary)], s.unary)
	copy(out.binary[:len(s.binary)], s.binary)
	for _, v := range other.nullary {
		if pv, seen := nullarySeen[v.symbol]; seen {
			if !pv.Equal(v) {
				return nil, errs.NewFailed("constant %s already exists with a different value", v.symbol)
			}
			continue
		}
		nullarySeen[v.symbol] = v
		out.nullary = append(out.nullary, v)
	}
	for _, v := range other.unary {
		if pv, seen := unarySeen[v.symbol]; seen {
			if !pv.Equal(v) {
				return nil, errs.NewFailed("unary operator %s already exists with a different value", v.symbol)
			}
			continue
		}
		unarySeen[v.symbol] = v
		out.unary = append(out.unary, v)
	}
	for _, v := range other.binary {
		if pv, seen := binarySeen[v.symbol]; seen {
			if !pv.Equal(v) {
				return nil, errs.NewFailed("binary operator %s already exists with a different value", v.symbol)
			}
			continue
		}
		binarySeen[v.symbol] = v
		out.binary = append(out.binary, v)
	}
	return out, nil
}

type LStructure[E Element[E]] interface {
	Language() *Language[E]
	base.Equatable[LStructure[E]]
}

func NewAlgebra[E Element[E]](universe CarrierSet[E], language *Language[E]) (*Algebra[E], error) {
	if utils.IsNil(universe) {
		return nil, errs.NewIsNil("universe")
	}
	if language == nil {
		language = NewEmptyLanguage[E]()
	}
	return &Algebra[E]{
		universe: universe,
		language: language,
	}, nil
}

func newPureSet[E Element[E]](set CarrierSet[E]) (*Algebra[E], error) {
	return NewAlgebra(set, nil)
}

type Algebra[E Element[E]] struct {
	universe CarrierSet[E]
	language *Language[E]
}

func (a *Algebra[E]) Universe() CarrierSet[E] {
	return a.universe
}

func (a *Algebra[E]) Language() *Language[E] {
	return a.language
}

func (a *Algebra[E]) Equal(other LStructure[E]) bool {
	otherC, ok := other.(*Algebra[E])
	if !ok {
		return false
	}
	if a == nil || otherC == nil {
		return a == otherC
	}
	return !utils.IsNil(other) && equalCarrierSet(a.universe, otherC.universe) && a.language.Equal(otherC.language)
}

func (a *Algebra[E]) Clone() *Algebra[E] {
	return &Algebra[E]{
		universe: a.universe,
		language: a.language.Clone(),
	}
}

func (a *Algebra[E]) DefinitionalExpansion(language *Language[E]) (*Algebra[E], error) {
	unioned, err := a.language.Union(language)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to union languages")
	}
	out := a.Clone()
	out.language = unioned
	return out, nil
}

type Axiom[E Element[E]] interface {
	Language() *Language[E]
	Rank() int
	Law() Law
	base.Equatable[Axiom[E]]
}

type Axiom1[E Element[E]] struct {
	law        Law
	language   *Language[E]
	check      func(E) bool
	conditions []func(E) bool
}

func (u *Axiom1[E]) Law() Law {
	return u.law
}

func (u *Axiom1[E]) Language() *Language[E] {
	return u.language
}

func (u *Axiom1[E]) Rank() int {
	return 1
}

func (u *Axiom1[E]) Equal(other Axiom[E]) bool {
	if u == nil || other == nil {
		return false
	}
	return u.law == other.Law() && u.Rank() == other.Rank() &&
		u.language.Equal(other.Language())
}

func (u *Axiom1[E]) Clone() *Axiom1[E] {
	return &Axiom1[E]{
		law:        u.law,
		language:   u.language.Clone(),
		check:      u.check,
		conditions: slices.Clone(u.conditions),
	}
}

type Axiom2[E Element[E]] struct {
	law        Law
	language   *Language[E]
	check      func(E, E) bool
	conditions []func(E, E) bool
}

func (b *Axiom2[E]) Law() Law {
	return b.law
}

func (b *Axiom2[E]) Language() *Language[E] {
	return b.language
}
func (b *Axiom2[E]) Rank() int {
	return 2
}

func (b *Axiom2[E]) Equal(other Axiom[E]) bool {
	if b == nil || other == nil {
		return false
	}
	return b.law == other.Law() && b.Rank() == other.Rank() &&
		b.language.Equal(other.Language())
}

func (b *Axiom2[E]) Clone() *Axiom2[E] {
	return &Axiom2[E]{
		law:        b.law,
		language:   b.language.Clone(),
		check:      b.check,
		conditions: slices.Clone(b.conditions),
	}
}

type Axiom3[E Element[E]] struct {
	law        Law
	language   *Language[E]
	check      func(E, E, E) bool
	conditions []func(E, E, E) bool
}

func (t *Axiom3[E]) Language() *Language[E] {
	return t.language
}
func (t *Axiom3[E]) Rank() int {
	return 3
}

func (t *Axiom3[E]) Law() Law {
	return t.law
}

func (t *Axiom3[E]) Equal(other Axiom[E]) bool {
	if t == nil || other == nil {
		return false
	}
	return t.law == other.Law() && t.Rank() == other.Rank() &&
		t.language.Equal(other.Language())
}

func (t *Axiom3[E]) Clone() *Axiom3[E] {
	return &Axiom3[E]{
		law:        t.law,
		language:   t.language.Clone(),
		check:      t.check,
		conditions: t.conditions,
	}
}

func NewTheory[E Element[E]](language *Language[E], identities []Axiom[E]) (*Theory[E], error) {
	if language == nil && len(identities) != 0 {
		return nil, errs.NewFailed("language is nil but identities are provided")
	}
	rank1 := make(map[Law]*Axiom1[E], len(identities))
	rank2 := make(map[Law]*Axiom2[E], len(identities))
	rank3 := make(map[Law]*Axiom3[E], len(identities))
	for _, axiom := range identities {
		if axiom == nil {
			return nil, errs.NewIsNil("axiom")
		}
		if !axiom.Language().Equal(language) {
			return nil, errs.NewFailed("axiom language does not match theory language")
		}
		switch a := axiom.(type) {
		case *Axiom1[E]:
			rank1[a.Law()] = a
		case *Axiom2[E]:
			rank2[a.Law()] = a
		case *Axiom3[E]:
			rank3[a.Law()] = a
		default:
			return nil, errs.NewFailed("unknown axiom type: %T with rank %d", a, a.Rank())
		}
	}
	return &Theory[E]{
		language: language,
		rank1:    rank1,
		rank2:    rank2,
		rank3:    rank3,
	}, nil
}

type Theory[E Element[E]] struct {
	language *Language[E]
	rank1    map[Law]*Axiom1[E]
	rank2    map[Law]*Axiom2[E]
	rank3    map[Law]*Axiom3[E]
}

func (t *Theory[E]) Language() *Language[E] {
	return t.language
}

func (t *Theory[E]) Equal(other LStructure[E]) bool {
	otherC, ok := other.(*Theory[E])
	return ok && t.language.Equal(otherC.language) &&
		maps.EqualFunc(t.rank1, otherC.rank1, func(x, y *Axiom1[E]) bool {
			return x.Equal(y)
		}) &&
		maps.EqualFunc(t.rank2, otherC.rank2, func(x, y *Axiom2[E]) bool {
			return x.Equal(y)
		}) &&
		maps.EqualFunc(t.rank3, otherC.rank3, func(x, y *Axiom3[E]) bool {
			return x.Equal(y)
		})
}

func (t *Theory[E]) Clone() *Theory[E] {
	return &Theory[E]{
		language: t.language.Clone(),
		rank1:    maps.Clone(t.rank1),
		rank2:    maps.Clone(t.rank2),
		rank3:    maps.Clone(t.rank3),
	}
}

func NewModel[E Element[E]](algebra *Algebra[E], theory *Theory[E]) (*Model[E], error) {
	if algebra == nil {
		return nil, errs.NewIsNil("algebra")
	}
	if theory == nil {
		return nil, errs.NewIsNil("theory")
	}
	if !theory.language.Equal(algebra.Language()) {
		return nil, errs.NewFailed("theory language does not match algebra language")
	}
	return &Model[E]{
		algebra: algebra,
		theory:  theory,
	}, nil
}

type Model[E Element[E]] struct {
	algebra *Algebra[E]
	theory  *Theory[E]
}

func (m *Model[E]) Clone() *Model[E] {
	return &Model[E]{
		algebra: m.algebra.Clone(),
		theory:  m.theory.Clone(),
	}
}
func (m *Model[E]) setLanguage(langauge *Language[E]) {
	if langauge == nil {
		panic(errs.NewIsNil("language cannot be nil"))
	}
	m.theory.language = langauge
	m.algebra.language = langauge
}

func (m *Model[E]) Language() *Language[E] {
	return m.algebra.language
}

func (m *Model[E]) Algebra() *Algebra[E] {
	return m.algebra
}

func (m *Model[E]) Theory() *Theory[E] {
	return m.theory
}

func (m *Model[E]) DefinitionalExpansion(language *Language[E]) (*Model[E], error) {
	if language == nil {
		return nil, errs.NewIsNil("language")
	}
	expandedAlgebra, err := m.algebra.DefinitionalExpansion(language)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to expand algebra")
	}
	out := m.Clone()
	out.algebra = expandedAlgebra
	out.theory.language = expandedAlgebra.language
	return out, nil
}

// ****** Two sorted

type TwoSortedFunction[E1 Element[E1], E2 Element[E2]] interface {
	Rank() (int, int)
	WithSymbol
	fmt.Stringer
	base.Hashable[TwoSortedFunction[E1, E2]]
}

func NewFirstProjection[E1 Element[E1], E2 Element[E2]](name string, symbol Symbol, f func(E1, E2) E1) (*Projection[E1, E2, E1], error) {
	if utils.IsNil(f) {
		return nil, errs.NewIsNil("f")
	}
	return &Projection[E1, E2, E1]{name: name, symbol: symbol, f: f, t: 1}, nil
}

func NewSecondProjection[E1 Element[E1], E2 Element[E2]](name string, symbol Symbol, f func(E1, E2) E2) (*Projection[E1, E2, E2], error) {
	if utils.IsNil(f) {
		return nil, errs.NewIsNil("f")
	}
	return &Projection[E1, E2, E2]{name: name, symbol: symbol, f: f, t: 2}, nil
}

type Projection[E1 Element[E1], E2 Element[E2], O Element[O]] struct {
	name   string
	symbol Symbol
	f      func(E1, E2) O
	t      int
}

func (m Projection[E1, E2, O]) ProjectionIndex() int {
	return m.t
}

func (m Projection[E1, E2, O]) String() string {
	return m.name
}

func (m Projection[E1, E2, O]) Symbol() Symbol {
	return m.symbol
}

func (m Projection[E1, E2, O]) Rank() (int, int) {
	return 1, 1
}

func (m Projection[E1, E2, O]) Equal(other TwoSortedFunction[E1, E2]) bool {
	m1, m2 := m.Rank()
	o1, o2 := other.Rank()
	return other != nil && m.name == other.String() && m1 == o1 && m2 == o2
}

func (m Projection[E1, E2, O]) HashCode() base.HashCode {
	return base.DeriveHashCode([]byte(m.name))
}

func (m Projection[E1, E2, O]) Clone() *Projection[E1, E2, O] {
	return &Projection[E1, E2, O]{
		name:   m.name,
		symbol: m.symbol,
		f:      m.f,
		t:      m.t,
	}
}

func NewTwoSortedlanguage[E1 Element[E1], E2 Element[E2]](
	first *Language[E1], second *Language[E2], firstProjections []*Projection[E1, E2, E1], secondProjections []*Projection[E1, E2, E2],
) (*TwoSortedlanguage[E1, E2], error) {
	if first == nil || second == nil {
		return nil, errs.NewIsNil("first or second language")
	}
	if firstProjections == nil || secondProjections == nil {
		return nil, errs.NewIsNil("projections")
	}
	pi1 := make(map[Symbol]*Projection[E1, E2, E1], len(firstProjections))
	pi2 := make(map[Symbol]*Projection[E1, E2, E2], len(secondProjections))
	for _, p := range firstProjections {
		if p == nil {
			return nil, errs.NewIsNil("projection")
		}
		if p.ProjectionIndex() != 1 {
			return nil, errs.NewFailed("projection index must be 1 for first projections")
		}
		pi1[p.Symbol()] = p
	}
	for _, p := range secondProjections {
		if p == nil {
			return nil, errs.NewIsNil("projection")
		}
		if p.ProjectionIndex() != 2 {
			return nil, errs.NewFailed("projection index must be 2 for second projections")
		}
		pi2[p.Symbol()] = p
	}
	return &TwoSortedlanguage[E1, E2]{
		first:  first,
		second: second,
		pi1:    pi1,
		pi2:    pi2,
	}, nil
}

type TwoSortedlanguage[E1 Element[E1], E2 Element[E2]] struct {
	first  *Language[E1]
	second *Language[E2]
	pi1    map[Symbol]*Projection[E1, E2, E1]
	pi2    map[Symbol]*Projection[E1, E2, E2]
}

func (s *TwoSortedlanguage[E1, E2]) First() *Language[E1] {
	if s == nil {
		return nil
	}
	return s.first
}

func (s *TwoSortedlanguage[E1, E2]) Second() *Language[E2] {
	if s == nil {
		return nil
	}
	return s.second
}

func (s *TwoSortedlanguage[E1, E2]) FirstProjections() map[Symbol]*Projection[E1, E2, E1] {
	if s == nil {
		return nil
	}
	return s.pi1
}

func (s *TwoSortedlanguage[E1, E2]) SecondProjections() map[Symbol]*Projection[E1, E2, E2] {
	if s == nil {
		return nil
	}
	return s.pi2
}

func (s *TwoSortedlanguage[E1, E2]) Equal(other *TwoSortedlanguage[E1, E2]) bool {
	if s == nil || other == nil {
		return s == other
	}
	return s.first.Equal(other.first) &&
		s.second.Equal(other.second) &&
		maps.EqualFunc(s.pi1, other.pi1, func(x, y *Projection[E1, E2, E1]) bool {
			return x.Equal(y)
		}) &&
		maps.EqualFunc(s.pi2, other.pi2, func(x, y *Projection[E1, E2, E2]) bool {
			return x.Equal(y)
		})
}

func (s *TwoSortedlanguage[E1, E2]) Clone() *TwoSortedlanguage[E1, E2] {
	return &TwoSortedlanguage[E1, E2]{
		first:  s.first.Clone(),
		second: s.second.Clone(),
		pi1:    maps.Clone(s.pi1),
		pi2:    maps.Clone(s.pi2),
	}
}

func NewTwoSortedAlgebra[C1 CarrierSet[E1], C2 CarrierSet[E2], E1 Element[E1], E2 Element[E2]](
	first C1, second C2, language *TwoSortedlanguage[E1, E2],
) (*TwoSortedAlgebra[C1, C2, E1, E2], error) {
	if utils.IsNil(first) || utils.IsNil(second) {
		return nil, errs.NewIsNil("first or second carrier set")
	}
	if language == nil {
		return nil, errs.NewIsNil("language")
	}
	return &TwoSortedAlgebra[C1, C2, E1, E2]{
		first:    first,
		second:   second,
		language: language,
	}, nil
}

type TwoSortedAlgebra[C1 CarrierSet[E1], C2 CarrierSet[E2], E1 Element[E1], E2 Element[E2]] struct {
	first    C1
	second   C2
	language *TwoSortedlanguage[E1, E2]
}

func (t *TwoSortedAlgebra[C1, C2, E1, E2]) First() C1 {
	if t == nil {
		return *new(C1)
	}
	return t.first
}

func (t *TwoSortedAlgebra[C1, C2, E1, E2]) Second() C2 {
	if t == nil {
		return *new(C2)
	}
	return t.second
}

func (t *TwoSortedAlgebra[C1, C2, E1, E2]) Equal(other *TwoSortedAlgebra[C1, C2, E1, E2]) bool {
	if t == nil || other == nil {
		return t == other
	}
	return equalCarrierSet(t.first, other.first) &&
		equalCarrierSet(t.second, other.second) &&
		t.language.Equal(other.language)
}

func (t *TwoSortedAlgebra[C1, C2, E1, E2]) Clone() *TwoSortedAlgebra[C1, C2, E1, E2] {
	return &TwoSortedAlgebra[C1, C2, E1, E2]{
		first:    t.first,
		second:   t.second,
		language: t.language.Clone(),
	}
}

type TwoSortedAxiom[E1 Element[E1], E2 Element[E2]] interface {
	language() *TwoSortedlanguage[E1, E2]
	Rank() (int, int)
	fmt.Stringer
	base.Equatable[TwoSortedAxiom[E1, E2]]
}

type TwoSortedTheory[E1 Element[E1], E2 Element[E2]] struct {
	language     *TwoSortedlanguage[E1, E2]
	firstAxioms  map[string]Axiom[E1]
	secondAxioms map[string]Axiom[E2]
	mixedAxioms  map[string]TwoSortedAxiom[E1, E2]
}

func (t *TwoSortedTheory[E1, E2]) Clone() *TwoSortedTheory[E1, E2] {
	return &TwoSortedTheory[E1, E2]{
		language:     t.language.Clone(),
		firstAxioms:  maps.Clone(t.firstAxioms),
		secondAxioms: maps.Clone(t.secondAxioms),
		mixedAxioms:  maps.Clone(t.mixedAxioms),
	}
}

type TwoSortedModel[C1 CarrierSet[E1], C2 CarrierSet[E2], E1 Element[E1], E2 Element[E2]] struct {
	name    string
	algebra *TwoSortedAlgebra[C1, C2, E1, E2]
	theory  *TwoSortedTheory[E1, E2]
}

func (m *TwoSortedModel[C1, C2, E1, E2]) Clone() *TwoSortedModel[C1, C2, E1, E2] {
	return &TwoSortedModel[C1, C2, E1, E2]{
		name:    m.name,
		algebra: m.algebra.Clone(),
		theory:  m.theory.Clone(),
	}
}

func equalCarrierSet[E Element[E]](a, b CarrierSet[E]) bool {
	if a == nil || b == nil {
		return a == b
	}
	return reflect.ValueOf(a).Pointer() == reflect.ValueOf(b).Pointer()
}
