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

// *** Single Sorted Signature ***

func NewSignature(sort Sort, nullary map[NullaryFunctionSymbol]*OperationProfile, unary map[UnaryFunctionSymbol]*OperationProfile, binary map[BinaryFunctionSymbol]*OperationProfile) (*Signature, error) {
	if sort == "" {
		sort = EmptySymbol
	}
	if sort == EmptySymbol && (len(nullary) > 0 || len(unary) > 0 || len(binary) > 0) {
		return nil, errs.NewFailed("empty sort cannot have operations")
	}
	for prof := range iterutils.Concat(
		maps.Values(nullary),
		maps.Values(unary),
		maps.Values(binary),
	) {
		if prof == nil {
			return nil, errs.NewIsNil("operation profile cannot be nil")
		}
		if !prof.IsSingleSorted() {
			return nil, errs.NewFailed("operation profile must be single sorted")
		}
		if !prof.IsTotal() {
			return nil, errs.NewFailed("operation profile must be total")
		}
		if prof.output != sort {
			return nil, errs.NewFailed("operation profile output sort does not match signature sort")
		}
	}
	return &Signature{
		sort:    sort,
		nullary: nullary,
		unary:   unary,
		binary:  binary,
	}, nil
}

type Signature struct {
	sort    Sort
	nullary map[NullaryFunctionSymbol]*OperationProfile
	unary   map[UnaryFunctionSymbol]*OperationProfile
	binary  map[BinaryFunctionSymbol]*OperationProfile
}

func (sig *Signature) IsImaginary() bool {
	return len(sig.nullary) == 0 &&
		len(sig.unary) == 0 &&
		len(sig.binary) == 0
}

func (sig *Signature) HasNullary(xs ...NullaryFunctionSymbol) bool {
	if sig == nil {
		return false
	}
	for _, x := range xs {
		if _, exists := sig.nullary[x]; !exists {
			return false
		}
	}
	return true
}

func (sig *Signature) HasUnary(xs ...UnaryFunctionSymbol) bool {
	if sig == nil {
		return false
	}
	for _, x := range xs {
		if _, exists := sig.unary[x]; !exists {
			return false
		}
	}
	return true
}

func (sig *Signature) HasBinary(xs ...BinaryFunctionSymbol) bool {
	if sig == nil {
		return false
	}
	for _, x := range xs {
		if _, exists := sig.binary[x]; !exists {
			return false
		}
	}
	return true
}

func (sig *Signature) Sort() Sort {
	return sig.sort
}

func (sig *Signature) Nullary() map[NullaryFunctionSymbol]*OperationProfile {
	return maps.Clone(sig.nullary)
}

func (sig *Signature) Unary() map[UnaryFunctionSymbol]*OperationProfile {
	return maps.Clone(sig.unary)
}

func (sig *Signature) Binary() map[BinaryFunctionSymbol]*OperationProfile {
	return maps.Clone(sig.binary)
}

func (sig *Signature) IsSubSignature(other *Signature) bool {
	if sig == nil || other == nil {
		return sig == other
	}

	if len(sig.nullary) > len(other.nullary) ||
		len(sig.unary) > len(other.unary) ||
		len(sig.binary) > len(other.binary) {
		return false
	}

	return sig.sort == other.sort &&
		maputils.IsSubMap(sig.nullary, other.nullary, func(a, b *OperationProfile) bool { return a.Equal(b) }) &&
		maputils.IsSubMap(sig.unary, other.unary, func(a, b *OperationProfile) bool { return a.Equal(b) }) &&
		maputils.IsSubMap(sig.binary, other.binary, func(a, b *OperationProfile) bool { return a.Equal(b) })
}

func (sig *Signature) Sum(other *Signature) (*Signature, error) {
	if other == nil {
		return sig, nil
	}
	if sig.sort != other.sort {
		return nil, errs.NewFailed("cannot sum signatures with different sorts")
	}
	nullary, err := maputils.JoinError(sig.nullary, other.nullary, func(_ NullaryFunctionSymbol, a, b **OperationProfile) (*OperationProfile, error) {
		if (*a).Equal(*b) {
			return *a, nil
		}
		return nil, errs.NewFailed("cannot sum nullary operations with different symbols")
	})
	if err != nil {
		return nil, err
	}
	unary, err := maputils.JoinError(sig.unary, other.unary, func(_ UnaryFunctionSymbol, a, b **OperationProfile) (*OperationProfile, error) {
		if (*a).Equal(*b) {
			return *a, nil
		}
		return nil, errs.NewFailed("cannot sum unary operations with different symbols")
	})
	if err != nil {
		return nil, err
	}
	binary, err := maputils.JoinError(sig.binary, other.binary, func(_ BinaryFunctionSymbol, a, b **OperationProfile) (*OperationProfile, error) {
		if (*a).Equal(*b) {
			return *a, nil
		}
		return nil, errs.NewFailed("cannot sum binary operations with different symbols")
	})
	if err != nil {
		return nil, err
	}
	return &Signature{
		sort:    sig.sort,
		nullary: nullary,
		unary:   unary,
		binary:  binary,
	}, nil
}

func (sig *Signature) Clone() *Signature {
	return &Signature{
		sort:    sig.sort,
		nullary: maps.Clone(sig.nullary),
		unary:   maps.Clone(sig.unary),
		binary:  maps.Clone(sig.binary),
	}
}

func (sig *Signature) ReSorted(new Sort) (*Signature, error) {
	if new == EmptySymbol {
		return nil, errs.NewFailed("cannot rename sort to empty symbol")
	}
	if new == sig.sort {
		return sig.Clone(), nil
	}
	return &Signature{
		sort: new,
		nullary: maputils.MapValues(sig.nullary, func(_ NullaryFunctionSymbol, prof *OperationProfile) *OperationProfile {
			return prof.renamed(sig.sort, new)
		}),
		unary: maputils.MapValues(sig.unary, func(_ UnaryFunctionSymbol, prof *OperationProfile) *OperationProfile {
			return prof.renamed(sig.sort, new)
		}),
		binary: maputils.MapValues(sig.binary, func(_ BinaryFunctionSymbol, prof *OperationProfile) *OperationProfile {
			return prof.renamed(sig.sort, new)
		}),
	}, nil
}

// *** Multi Sorted Signature ***

func NewMultiSortedSignature(
	factors map[Sort]*Signature,
	mixedUnary ds.Set[*OperationProfile],
	mixedBinary ds.Set[*OperationProfile],
) (*MultiSortedSignature, error) {
	if factors == nil {
		return nil, errs.NewIsNil("factors cannot be nil")
	}
	sorts := maps.Keys(factors)
	if mixedUnary != nil {
		if iterutils.Any(mixedUnary.Iter(), func(prof *OperationProfile) bool {
			return len(prof.inputs) != 1 || !prof.IsMixed() || iterutils.Equal(sorts, slices.Values(prof.Sorts()))
		}) {
			return nil, errs.NewFailed("mixed unary operations must have sorts that are in the factors")
		}
	}
	if mixedBinary != nil {
		if iterutils.Any(mixedBinary.Iter(), func(prof *OperationProfile) bool {
			return len(prof.inputs) != 2 || !prof.IsMixed() || iterutils.Equal(sorts, slices.Values(prof.Sorts()))
		}) {
			return nil, errs.NewFailed("mixed binary operations must have sorts that are in the factors")
		}
	}
	return &MultiSortedSignature{
		factors:     hashmap.NewComparableFromNativeLike(factors),
		mixedUnary:  mixedUnary.Unfreeze(),
		mixedBinary: mixedBinary.Unfreeze(),
	}, nil

}

type MultiSortedSignature struct {
	factors     ds.MutableMap[Sort, *Signature]
	mixedUnary  ds.MutableSet[*OperationProfile]
	mixedBinary ds.MutableSet[*OperationProfile]
}

func (sig *MultiSortedSignature) Factor(sort Sort) (*Signature, bool) {
	return sig.factors.Get(sort)
}

func (sig *MultiSortedSignature) HasMixedUnary(op *OperationProfile) bool {
	return sig.mixedUnary.Contains(op)
}

func (sig *MultiSortedSignature) HasMixedBinary(op *OperationProfile) bool {
	return sig.mixedBinary.Contains(op)
}

func (sig *MultiSortedSignature) Sorts() ds.Set[Sort] {
	return hashset.NewComparable(sig.factors.Keys()...).Freeze()
}

func (sig *MultiSortedSignature) ImaginarySorts() ds.Set[Sort] {
	return hashset.NewComparable(sig.factors.Filter(func(sort Sort) bool {
		out, exists := sig.factors.Get(sort)
		return exists && out.IsImaginary()
	}).Keys()...).Freeze()
}

func (sig *MultiSortedSignature) Clone() *MultiSortedSignature {
	if sig == nil {
		return nil
	}
	return &MultiSortedSignature{
		factors:     sig.factors.Clone(),
		mixedUnary:  sig.mixedUnary.Clone(),
		mixedBinary: sig.mixedBinary.Clone(),
	}
}

func (sig *MultiSortedSignature) Sum(other *MultiSortedSignature) (*MultiSortedSignature, error) {
	if other == nil {
		return sig, nil
	}
	if sig.factors.Size() != other.factors.Size() {
		return nil, errs.NewFailed("cannot sum multi-sorted signatures with different sorts")
	}
	factors := hashmap.NewComparable[Sort, *Signature]()
	for sort, sig1 := range sig.factors.Iter() {
		sig2, exists := other.factors.Get(sort)
		if !exists {
			return nil, errs.NewFailed("cannot sum multi-sorted signatures with different factors")
		}
		sigSum, err := sig1.Sum(sig2)
		if err != nil {
			return nil, errs.WrapFailed(err, "failed to sum signatures for sort %s", sort)
		}
		factors.Put(sort, sigSum)
	}
	if sig.mixedUnary == nil && other.mixedUnary == nil {
		return &MultiSortedSignature{
			factors:     factors,
			mixedUnary:  nil,
			mixedBinary: nil,
		}, nil
	}
	mixedUnary := sig.mixedUnary.Clone()
	if other.mixedUnary != nil {
		mixedUnary = mixedUnary.Union(other.mixedUnary)
	}
	mixedBinary := sig.mixedBinary.Clone()
	if other.mixedBinary != nil {
		mixedBinary = mixedBinary.Union(other.mixedBinary)
	}
	return &MultiSortedSignature{
		factors:     factors,
		mixedUnary:  mixedUnary,
		mixedBinary: mixedBinary,
	}, nil
}

func (sig *MultiSortedSignature) IsSubSignature(other *MultiSortedSignature) bool {
	if sig == nil || other == nil {
		return sig == other
	}
	if sig.factors.Size() > other.factors.Size() ||
		sig.mixedUnary.Size() > other.mixedUnary.Size() ||
		sig.mixedBinary.Size() > other.mixedBinary.Size() {
		return false
	}
	for s, sig := range sig.factors.Iter() {
		if otherSig, exists := other.factors.Get(s); !exists || !sig.IsSubSignature(otherSig) {
			return false
		}
	}
	return sig.mixedUnary.IsSubSet(other.mixedUnary) &&
		sig.mixedBinary.IsSubSet(other.mixedBinary)
}

func (sig *MultiSortedSignature) ReSorted(old, new Sort) (*MultiSortedSignature, error) {
	if new == EmptySymbol {
		return nil, errs.NewFailed("cannot rename sort to empty symbol")
	}
	if old == new {
		return sig.Clone(), nil
	}
	out := &MultiSortedSignature{
		factors: sig.factors.Clone(),
		mixedUnary: hashset.NewHashable(
			slices.Collect(
				iterutils.Map(sig.mixedUnary.Iter(), func(prof *OperationProfile) *OperationProfile { return prof.renamed(old, new) }),
			)...,
		),
		mixedBinary: hashset.NewHashable(
			slices.Collect(
				iterutils.Map(sig.mixedBinary.Iter(), func(prof *OperationProfile) *OperationProfile { return prof.renamed(old, new) }),
			)...,
		),
	}
	factor, exists := sig.factors.Get(old)
	if !exists {
		return nil, errs.NewFailed("signature does not contain the old sort")
	}
	resortedFactor, err := factor.ReSorted(new)
	if err != nil {
		return nil, errs.WrapFailed(err, "failed to re-sort factor for sort %s", old)
	}
	out.factors.Put(new, resortedFactor)
	out.factors.Remove(old)
	return out, nil
}

// *** Misc

func NewTagStore(sorts ...Sort) *TagStore {
	out := &TagStore{v: make(map[Sort]map[OperationTag]Operation[BinaryFunctionSymbol], len(sorts))}
	for _, sort := range sorts {
		out.v[sort] = make(map[OperationTag]Operation[BinaryFunctionSymbol])
	}
	return out
}

type TagStore struct {
	v map[Sort]map[OperationTag]Operation[BinaryFunctionSymbol]
}

func (ts *TagStore) Put(sort Sort, tag OperationTag, op Operation[BinaryFunctionSymbol]) (err error) {
	if op == nil {
		return errs.NewIsNil("operation profile cannot be nil")
	}
	if _, exists := ts.v[sort]; !exists {
		return errs.NewMissing("sort %s does not exist in tag store", sort)
	}
	if old, exists := ts.v[sort][tag]; exists && !OperationsAreEqual(old, op) {
		return errs.NewFailed("a different operation profile with tag %s already exists for sort %s", tag, sort)
	}
	ts.v[sort][tag] = op
	return nil
}

func (ts *TagStore) Get(sort Sort, tag OperationTag) (Operation[BinaryFunctionSymbol], bool) {
	if ops, exists := ts.v[sort]; exists {
		op, exists := ops[tag]
		return op, exists
	}
	return nil, false
}

func (ts *TagStore) Remove(sort Sort, tag OperationTag) {
	if ops, exists := ts.v[sort]; exists {
		delete(ops, tag)
	}
}

func (ts *TagStore) Clone() *TagStore {
	return &TagStore{
		v: maps.Clone(ts.v),
	}
}

func mergeTagStores(x, y *TagStore) (*TagStore, error) {
	if x == nil {
		return nil, errs.NewIsNil("first tag store cannot be nil")
	}
	if y == nil {
		return nil, errs.NewIsNil("second tag store cannot be nil")
	}
	out := x.Clone()
	for sort, ops := range y.v {
		for tag, op := range ops {
			if err := out.Put(sort, tag, op); err != nil {
				return nil, errs.WrapFailed(err, "failed to merge tag store for sort %s and tag %s", sort, tag)
			}
		}
	}
	return out, nil
}
