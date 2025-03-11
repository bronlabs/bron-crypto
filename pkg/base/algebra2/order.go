package algebra

import "github.com/bronlabs/krypton-primitives/pkg/base/errs"

type PartialOrdering int
type Ordering uint

const (
	Incomparable PartialOrdering = -1
	LessThan     PartialOrdering = 0
	Equal        PartialOrdering = 1
	GreaterThan  PartialOrdering = 2
)

func orderString(o int) string {
	switch o {
	case -1:
		return "Incomparable"
	case 0:
		return "Equal"
	case 1:
		return "LessThan"
	case 2:
		return "GreaterThan"
	default:
		return "Invalid"
	}
}

func (o PartialOrdering) String() string {
	return orderString(int(o))
}

func (o Ordering) String() string {
	return orderString(int(o))
}

type PartiallyComparable[E any] interface {
	IsLessThanOrEqual(rhs E) bool
}

func PartialCompare[E PartiallyComparable[E]](x, y E) PartialOrdering {
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

func Compare[E PartiallyComparable[E]](x, y E) Ordering {
	out := PartialCompare(x, y)
	if out == Incomparable {
		panic(errs.NewValue("Incomparable"))
	}
	return Ordering(out)
}

type Poset[E PartiallyComparableElement[E]] interface {
	Structure[E]
	PartialCompare(x, y E) PartialOrdering
}

type Chain[E PartiallyComparableElement[E]] interface {
	Poset[E]
	Compare(x, y E) Ordering
}
type PartiallyComparableElement[E interface {
	Element[E]
	PartiallyComparable[E]
}] interface {
	Element[E]
	PartiallyComparable[E]
}
