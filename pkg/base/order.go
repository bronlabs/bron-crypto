package base

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type PartialOrdering int8
type Ordering PartialOrdering

type ComparisonFlag interface {
	bool | ct.Bool
}

const (
	Incomparable PartialOrdering = -2
	LessThan     PartialOrdering = -1
	Equal        PartialOrdering = 0
	GreaterThan  PartialOrdering = 1
)

func orderString(o int) string {
	switch o {
	case -2:
		return "Incomparable"
	case 0:
		return "Equal"
	case -1:
		return "LessThan"
	case 1:
		return "GreaterThan"
	default:
		return "Invalid"
	}
}

func (o PartialOrdering) String() string {
	return orderString(int(o))
}

type BoundedFromBelow[E any] interface {
	Bottom() E
}

type BoundedFromAbove[E any] interface {
	Top() E
}

type Bounded[E any] interface {
	BoundedFromBelow[E]
	BoundedFromAbove[E]
}

type Comparable[E any] interface {
	IsLessThanOrEqual(rhs E) bool
}

type WithInternalPartialCompareMethod[E any] interface {
	PartialCompare(rhs E) PartialOrdering
}

type WithInternalCompareMethod[E any] interface {
	Compare(rhs E) Ordering
}

func PartialCompare[E Comparable[E]](x, y E) PartialOrdering {
	if xx, okx := any(x).(WithInternalPartialCompareMethod[E]); okx {
		return xx.PartialCompare(y)
	}
	if x.IsLessThanOrEqual(y) && y.IsLessThanOrEqual(x) {
		return Equal
	}
	if x.IsLessThanOrEqual(y) {
		return LessThan
	}
	if y.IsLessThanOrEqual(x) {
		return GreaterThan
	}
	return Incomparable
}

func Compare[E Comparable[E]](x, y E) Ordering {
	if xx, okx := any(x).(ct.Comparable[E]); okx {
		lt, eq, gt := xx.Compare(y)
		return Ordering(LessThan*PartialOrdering(lt) + Equal*PartialOrdering(eq) + GreaterThan*PartialOrdering(gt))
	}
	if xx, okx := any(x).(WithInternalCompareMethod[E]); okx {
		return xx.Compare(y)
	}
	out := PartialCompare(x, y)
	if out == Incomparable {
		panic(errs.NewValue("Incomparable"))
	}
	return Ordering(out)
}

func IsEqual[E Comparable[E]](x, y E) bool {
	if xx, okx := any(x).(ct.Equatable[E]); okx {
		return xx.Equal(y) == ct.True
	}
	return PartialCompare(x, y) == Equal
}
