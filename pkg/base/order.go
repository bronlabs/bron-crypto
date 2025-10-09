package base

import (
	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/bron-crypto/pkg/base/errs"
)

type (
	PartialOrdering int8
	Ordering        PartialOrdering
)

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

func (o PartialOrdering) Is(other Ordering) bool {
	return o == PartialOrdering(other)
}

func (o Ordering) Is(other PartialOrdering) bool {
	return other != Incomparable && PartialOrdering(o) == other
}

type BoundedFromBelow[E any] interface {
	Bottom() E
}

type BoundedFromBelowElement interface {
	IsBottom() bool
}

type BoundedFromAbove[E any] interface {
	Top() E
}

type BoundedFromAboveElement interface {
	IsTop() bool
}

type Bounded[E any] interface {
	BoundedFromBelow[E]
	BoundedFromAbove[E]
}

type BoundedElement interface {
	BoundedFromBelowElement
	BoundedFromAboveElement
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
	// If the type implements ct.Comparable, use it for constant-time comparison
	if cmp, ok := any(x).(ct.Comparable[E]); ok {
		lt, eq, gt := cmp.Compare(y)
		return PartialOrdering(LessThan*PartialOrdering(lt) + Equal*PartialOrdering(eq) + GreaterThan*PartialOrdering(gt))
	}
	// Fallback: allow internal PartialCompare
	if xx, okx := any(x).(WithInternalPartialCompareMethod[E]); okx {
		return xx.PartialCompare(y)
	}
	// Constant-time-ish fallback: always evaluate both directions
	xLeY := x.IsLessThanOrEqual(y)
	yLeX := y.IsLessThanOrEqual(x)
	switch {
	case xLeY && yLeX:
		return Equal
	case xLeY:
		return LessThan
	case yLeX:
		return GreaterThan
	default:
		return Incomparable
	}
}

func Compare[E Comparable[E]](x, y E) Ordering {
	// Prefer ct.Comparable if available for constant-time
	if cmp, ok := any(x).(ct.Comparable[E]); ok {
		return EvaluateConstantTimeComparison(cmp.Compare(y))
	}
	// Fallback: allow internal Compare
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

func EvaluateConstantTimeComparison(lt, eq, gt ct.Bool) Ordering {
	return Ordering(LessThan*PartialOrdering(lt) + Equal*PartialOrdering(eq) + GreaterThan*PartialOrdering(gt))
}
