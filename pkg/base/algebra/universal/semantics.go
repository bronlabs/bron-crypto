package universal

import (
	"maps"
	"slices"

	ds "github.com/bronlabs/bron-crypto/pkg/base/datastructures"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashmap"
	"github.com/bronlabs/bron-crypto/pkg/base/datastructures/hashset"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/iterutils"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/maputils"
)

func NewInterpretation[E Element[E]](sort Sort, nullary []*Constant[E], unary []*UnaryOperator[E], binary []*BinaryOperator[E]) (*Interpretation[E], error) {
	if sort == "" {
		return nil, errs.NewIsNil("sort cannot be empty")
	}
	nullaryMap := map[NullaryFunctionSymbol]*Constant[E]{}
	for _, c := range nullary {
		if c == nil {
			return nil, errs.NewIsNil("nullary constant cannot be nil")
		}
		if _, exists := nullaryMap[c.Symbol()]; exists {
			return nil, errs.NewFailed("duplicate nullary constant symbol: %s", c.Symbol())
		}
		nullaryMap[c.Symbol()] = c
	}

	unaryMap := map[UnaryFunctionSymbol]*UnaryOperator[E]{}
	for _, u := range unary {
		if u == nil {
			return nil, errs.NewIsNil("unary operator cannot be nil")
		}
		if _, exists := unaryMap[u.Symbol()]; exists {
			return nil, errs.NewFailed("duplicate unary operator symbol: %s", u.Symbol())
		}
		unaryMap[u.Symbol()] = u
	}

	binaryMap := map[BinaryFunctionSymbol]*BinaryOperator[E]{}
	for _, b := range binary {
		if b == nil {
			return nil, errs.NewIsNil("binary operator cannot be nil")
		}
		if _, exists := binaryMap[b.Symbol()]; exists {
			return nil, errs.NewFailed("duplicate binary operator symbol: %s", b.Symbol())
		}
		binaryMap[b.Symbol()] = b
	}
	return &Interpretation[E]{
		sort:    sort,
		nullary: nullaryMap,
		unary:   unaryMap,
		binary:  binaryMap,
	}, nil
}

type Interpretation[E Element[E]] struct {
	sort    Sort
	nullary map[NullaryFunctionSymbol]*Constant[E]
	unary   map[UnaryFunctionSymbol]*UnaryOperator[E]
	binary  map[BinaryFunctionSymbol]*BinaryOperator[E]
}

func (t *Interpretation[E]) Sort() Sort {
	if t.sort == "" {
		t.sort = EmptySymbol
	}
	return t.sort
}

func (t *Interpretation[E]) Nullary() map[NullaryFunctionSymbol]*Constant[E] {
	return maps.Clone(t.nullary)
}

func (t *Interpretation[E]) Unary() map[UnaryFunctionSymbol]*UnaryOperator[E] {
	return maps.Clone(t.unary)
}

func (t *Interpretation[E]) Binary() map[BinaryFunctionSymbol]*BinaryOperator[E] {
	return maps.Clone(t.binary)
}

func (t *Interpretation[E]) Signature() *Signature {
	return &Signature{
		sort:    t.Sort(),
		nullary: maputils.MapValues(t.nullary, func(_ NullaryFunctionSymbol, c *Constant[E]) *OperationProfile { return c.Profile() }),
		unary:   maputils.MapValues(t.unary, func(_ UnaryFunctionSymbol, u *UnaryOperator[E]) *OperationProfile { return u.Profile() }),
		binary:  maputils.MapValues(t.binary, func(_ BinaryFunctionSymbol, b *BinaryOperator[E]) *OperationProfile { return b.Profile() }),
	}
}

func (t *Interpretation[E]) Clone() *Interpretation[E] {
	return &Interpretation[E]{
		nullary: maps.Clone(t.nullary),
		unary:   maps.Clone(t.unary),
		binary:  maps.Clone(t.binary),
	}
}

func (t *Interpretation[E]) Merge(other *Interpretation[E]) (*Interpretation[E], error) {
	if other == nil {
		return nil, errs.NewIsNil("other interpretation table cannot be nil")
	}
	if t.Sort() != other.Sort() {
		return nil, errs.NewFailed("cannot merge interpretation tables with different sorts: %s and %s", t.Sort(), other.Sort())
	}

	merged := &Interpretation[E]{
		sort:    t.Sort(),
		nullary: maps.Clone(t.nullary),
		unary:   maps.Clone(t.unary),
		binary:  maps.Clone(t.binary),
	}

	for k, v := range other.Nullary() {
		if vv, exists := merged.nullary[k]; exists && !vv.Equal(v) {
			return nil, errs.NewFailed("duplicate nullary constant symbol with inequal values: %s", k)
		}
		merged.nullary[k] = v
	}

	for k, v := range other.Unary() {
		if vv, exists := merged.unary[k]; exists && !vv.Equal(v) {
			return nil, errs.NewFailed("duplicate unary operator symbol with inequal values: %s", k)
		}
		merged.unary[k] = v
	}

	for k, v := range other.Binary() {
		if vv, exists := merged.binary[k]; exists && !vv.Equal(v) {
			return nil, errs.NewFailed("duplicate binary operator symbol with inequal values: %s", k)
		}
		merged.binary[k] = v
	}

	return merged, nil
}

func (t *Interpretation[E]) IsSubInterpretation(of *Interpretation[E]) bool {
	if of == nil {
		return false
	}
	if t.Sort() != of.Sort() {
		return false
	}
	if len(t.nullary) > len(of.nullary) ||
		len(t.unary) > len(of.unary) ||
		len(t.binary) > len(of.binary) {
		return false
	}
	for k, v := range t.Nullary() {
		if ov, exists := of.Nullary()[k]; !exists || !ov.Equal(v) {
			return false
		}
	}
	for k, v := range t.Unary() {
		if ov, exists := of.Unary()[k]; !exists || !ov.Equal(v) {
			return false
		}
	}
	for k, v := range t.Binary() {
		if ov, exists := of.Binary()[k]; !exists || !ov.Equal(v) {
			return false
		}
	}
	return true
}

func NewTwoSortedInterpretation[E1 Element[E1], E2 Element[E2]](
	first *Interpretation[E1], second *Interpretation[E2],
	mixedUnary12 []*TwoSortedUnaryOperator[E1, E2],
	mixedUnary21 []*TwoSortedUnaryOperator[E2, E1],
	mixedBinary112 []*TwoSortedBinaryOperator[E1, E1, E2],
	mixedBinary221 []*TwoSortedBinaryOperator[E2, E2, E1],
	leftActionsOfFirst []*LeftAction[E1, E2],
	rightActionsOfFirst []*RightAction[E1, E2],
	leftActionsOfSecond []*LeftAction[E2, E1],
	rightActionsOfSecond []*RightAction[E2, E1],
) (*TwoSortedInterpretation[E1, E2], error) {
	if first == nil {
		return nil, errs.NewIsNil("first interpretation table cannot be nil")
	}
	if second == nil {
		return nil, errs.NewIsNil("second interpretation table cannot be nil")
	}
	mixedUnary12Set := hashset.NewHashable[*TwoSortedUnaryOperator[E1, E2]]()
	if mixedUnary12 != nil {
		mixedUnary12Set.AddAll(mixedUnary12...)
	}
	mixedUnary21Set := hashset.NewHashable[*TwoSortedUnaryOperator[E2, E1]]()
	if mixedUnary21 != nil {
		mixedUnary21Set.AddAll(mixedUnary21...)
	}
	mixedBinary112Set := hashset.NewHashable[*TwoSortedBinaryOperator[E1, E1, E2]]()
	if mixedBinary112 != nil {
		mixedBinary112Set.AddAll(mixedBinary112...)
	}
	mixedBinary221Set := hashset.NewHashable[*TwoSortedBinaryOperator[E2, E2, E1]]()
	if mixedBinary221 != nil {
		mixedBinary221Set.AddAll(mixedBinary221...)
	}
	leftActionsOfFirstSet := hashset.NewHashable[*LeftAction[E1, E2]]()
	if leftActionsOfFirst != nil {
		leftActionsOfFirstSet.AddAll(leftActionsOfFirst...)
	}
	rightActionsOfFirstSet := hashset.NewHashable[*RightAction[E1, E2]]()
	if rightActionsOfFirst != nil {
		rightActionsOfFirstSet.AddAll(rightActionsOfFirst...)
	}
	leftActionsOfSecondSet := hashset.NewHashable[*LeftAction[E2, E1]]()
	if leftActionsOfSecond != nil {
		leftActionsOfSecondSet.AddAll(leftActionsOfSecond...)
	}
	rightActionsOfSecondSet := hashset.NewHashable[*RightAction[E2, E1]]()
	if rightActionsOfSecond != nil {
		rightActionsOfSecondSet.AddAll(rightActionsOfSecond...)
	}
	return &TwoSortedInterpretation[E1, E2]{
		first:                first,
		second:               second,
		mixedUnary12:         mixedUnary12Set,
		mixedUnary21:         mixedUnary21Set,
		mixedBinary112:       mixedBinary112Set,
		mixedBinary221:       mixedBinary221Set,
		leftActionsOfFirst:   leftActionsOfFirstSet,
		rightActionsOfFirst:  rightActionsOfFirstSet,
		leftActionsOfSecond:  leftActionsOfSecondSet,
		rightActionsOfSecond: rightActionsOfSecondSet,
	}, nil
}

type TwoSortedInterpretation[E1 Element[E1], E2 Element[E2]] struct {
	first  *Interpretation[E1]
	second *Interpretation[E2]

	mixedUnary12 ds.MutableSet[*TwoSortedUnaryOperator[E1, E2]]
	mixedUnary21 ds.MutableSet[*TwoSortedUnaryOperator[E2, E1]]

	mixedBinary112 ds.MutableSet[*TwoSortedBinaryOperator[E1, E1, E2]]
	mixedBinary221 ds.MutableSet[*TwoSortedBinaryOperator[E2, E2, E1]]

	leftActionsOfFirst  ds.MutableSet[*LeftAction[E1, E2]]
	rightActionsOfFirst ds.MutableSet[*RightAction[E1, E2]]

	leftActionsOfSecond  ds.MutableSet[*LeftAction[E2, E1]]
	rightActionsOfSecond ds.MutableSet[*RightAction[E2, E1]]
}

func (t *TwoSortedInterpretation[E1, E2]) First() *Interpretation[E1] {
	return t.first
}

func (t *TwoSortedInterpretation[E1, E2]) Second() *Interpretation[E2] {
	return t.second
}

func (t *TwoSortedInterpretation[E1, E2]) MixedUnary12() ds.Set[*TwoSortedUnaryOperator[E1, E2]] {
	return t.mixedUnary12.Freeze()
}

func (t *TwoSortedInterpretation[E1, E2]) MixedUnary21() ds.Set[*TwoSortedUnaryOperator[E2, E1]] {
	return t.mixedUnary21.Freeze()
}

func (t *TwoSortedInterpretation[E1, E2]) MixedBinary112() ds.Set[*TwoSortedBinaryOperator[E1, E1, E2]] {
	return t.mixedBinary112.Freeze()
}

func (t *TwoSortedInterpretation[E1, E2]) MixedBinary221() ds.Set[*TwoSortedBinaryOperator[E2, E2, E1]] {
	return t.mixedBinary221.Freeze()
}

func (t *TwoSortedInterpretation[E1, E2]) LeftActionsOfFirst() ds.Set[*LeftAction[E1, E2]] {
	return t.leftActionsOfFirst.Freeze()
}

func (t *TwoSortedInterpretation[E1, E2]) RightActionsOfFirst() ds.Set[*RightAction[E1, E2]] {
	return t.rightActionsOfFirst.Freeze()
}

func (t *TwoSortedInterpretation[E1, E2]) LeftActionsOfSecond() ds.Set[*LeftAction[E2, E1]] {
	return t.leftActionsOfSecond.Freeze()
}

func (t *TwoSortedInterpretation[E1, E2]) RightActionsOfSecond() ds.Set[*RightAction[E2, E1]] {
	return t.rightActionsOfSecond.Freeze()
}

func (t *TwoSortedInterpretation[E1, E2]) Signature() *MultiSortedSignature {
	factors := hashmap.NewComparable[Sort, *Signature]()
	factors.Put(t.first.Sort(), t.first.Signature())
	factors.Put(t.second.Sort(), t.second.Signature())

	mixedUnary := hashset.NewHashable(
		slices.Collect(
			iterutils.Concat(
				iterutils.Map(t.mixedUnary12.Iter(), func(op *TwoSortedUnaryOperator[E1, E2]) *OperationProfile {
					return op.Profile()
				}),
				iterutils.Map(t.mixedUnary21.Iter(), func(op *TwoSortedUnaryOperator[E2, E1]) *OperationProfile {
					return op.Profile()
				}),
			),
		)...,
	)

	mixedBinary := hashset.NewHashable(
		slices.Collect(
			iterutils.Concat(
				iterutils.Map(t.mixedBinary112.Iter(), func(op *TwoSortedBinaryOperator[E1, E1, E2]) *OperationProfile {
					return op.Profile()
				}),
				iterutils.Map(t.mixedBinary221.Iter(), func(op *TwoSortedBinaryOperator[E2, E2, E1]) *OperationProfile {
					return op.Profile()
				}),
				iterutils.Map(t.leftActionsOfFirst.Iter(), func(op *LeftAction[E1, E2]) *OperationProfile {
					return op.Profile()
				}),
				iterutils.Map(t.rightActionsOfFirst.Iter(), func(op *RightAction[E1, E2]) *OperationProfile {
					return op.Profile()
				}),
				iterutils.Map(t.leftActionsOfSecond.Iter(), func(op *LeftAction[E2, E1]) *OperationProfile {
					return op.Profile()
				}),
				iterutils.Map(t.rightActionsOfSecond.Iter(), func(op *RightAction[E2, E1]) *OperationProfile {
					return op.Profile()
				}),
			),
		)...,
	)
	return &MultiSortedSignature{
		factors:     factors,
		mixedUnary:  mixedUnary,
		mixedBinary: mixedBinary,
	}
}

func (t *TwoSortedInterpretation[E1, E2]) Clone() *TwoSortedInterpretation[E1, E2] {
	return &TwoSortedInterpretation[E1, E2]{
		mixedUnary12:         t.mixedUnary12.Clone(),
		mixedUnary21:         t.mixedUnary21.Clone(),
		mixedBinary112:       t.mixedBinary112.Clone(),
		mixedBinary221:       t.mixedBinary221.Clone(),
		leftActionsOfFirst:   t.leftActionsOfFirst.Clone(),
		rightActionsOfFirst:  t.rightActionsOfFirst.Clone(),
		leftActionsOfSecond:  t.leftActionsOfSecond.Clone(),
		rightActionsOfSecond: t.rightActionsOfSecond.Clone(),
	}
}

func (t *TwoSortedInterpretation[E1, E2]) Merge(other *TwoSortedInterpretation[E1, E2]) (*TwoSortedInterpretation[E1, E2], error) {
	if other == nil {
		return nil, errs.NewIsNil("other interpretation table cannot be nil")
	}
	if t.First().Sort() != other.First().Sort() || t.Second().Sort() != other.Second().Sort() {
		return nil, errs.NewFailed("cannot merge two sorted interpretation tables with different sorts")
	}

	merged := &TwoSortedInterpretation[E1, E2]{
		mixedUnary12:         t.mixedUnary12.Union(other.mixedUnary12),
		mixedUnary21:         t.mixedUnary21.Union(other.mixedUnary21),
		mixedBinary112:       t.mixedBinary112.Union(other.mixedBinary112),
		mixedBinary221:       t.mixedBinary221.Union(other.mixedBinary221),
		leftActionsOfFirst:   t.leftActionsOfFirst.Union(other.leftActionsOfFirst),
		rightActionsOfFirst:  t.rightActionsOfFirst.Union(other.rightActionsOfFirst),
		leftActionsOfSecond:  t.leftActionsOfSecond.Union(other.leftActionsOfSecond),
		rightActionsOfSecond: t.rightActionsOfSecond.Union(other.rightActionsOfSecond),
	}
	var err error
	merged.first, err = t.first.Merge(other.First())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to merge first interpretation table")
	}
	merged.second, err = t.second.Merge(other.Second())
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to merge second interpretation table")
	}
	return merged, nil
}

func (t *TwoSortedInterpretation[E1, E2]) IsSubInterpretation(of *TwoSortedInterpretation[E1, E2]) bool {
	if of == nil {
		return false
	}
	if t.First().Sort() != of.First().Sort() || t.Second().Sort() != of.Second().Sort() {
		return false
	}
	if !t.First().IsSubInterpretation(of.First()) || !t.Second().IsSubInterpretation(of.Second()) {
		return false
	}
	if !t.MixedUnary12().IsSubSet(of.MixedUnary12()) || !t.MixedUnary21().IsSubSet(of.MixedUnary21()) {
		return false
	}
	if !t.MixedBinary112().IsSubSet(of.MixedBinary112()) || !t.MixedBinary221().IsSubSet(of.MixedBinary221()) {
		return false
	}
	if !t.LeftActionsOfFirst().IsSubSet(of.LeftActionsOfFirst()) || !t.RightActionsOfFirst().IsSubSet(of.RightActionsOfFirst()) {
		return false
	}
	if !t.LeftActionsOfSecond().IsSubSet(of.LeftActionsOfSecond()) || !t.RightActionsOfSecond().IsSubSet(of.RightActionsOfSecond()) {
		return false
	}
	return true
}
