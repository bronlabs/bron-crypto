package base

import "github.com/bronlabs/bron-crypto/pkg/base/errs"

type PartialOrdering int
type Ordering int

const (
	Incomparable              PartialOrdering = -2
	LessThanOrIncomparable    PartialOrdering = -1
	LessThan                  Ordering        = -1
	EqualOrIncomparable       PartialOrdering = 0
	Equal                     Ordering        = 0
	GreaterThanOrIncomparable PartialOrdering = 1
	GreaterThan               Ordering        = 1
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

func (o Ordering) String() string {
	return orderString(int(o))
}

type Comparable[E any] interface {
	IsLessThanOrEqual(rhs E) bool
}

type internalPartiallyComparable[E any] interface {
	PartialCompare(rhs E) PartialOrdering
}

type internalComparable[E any] interface {
	Compare(rhs E) Ordering
}

func PartialCompare[E Comparable[E]](x, y E) PartialOrdering {
	if xx, okx := any(x).(internalPartiallyComparable[E]); okx {
		return xx.PartialCompare(y)
	}
	if x.IsLessThanOrEqual(y) && y.IsLessThanOrEqual(x) {
		return EqualOrIncomparable
	}
	if x.IsLessThanOrEqual(y) {
		return LessThanOrIncomparable
	}
	if y.IsLessThanOrEqual(x) {
		return GreaterThanOrIncomparable
	}
	return Incomparable
}

func Compare[E Comparable[E]](x, y E) Ordering {
	if xx, okx := any(x).(internalComparable[E]); okx {
		return xx.Compare(y)
	}
	out := PartialCompare(x, y)
	if out == Incomparable {
		panic(errs.NewValue("Incomparable"))
	}
	return Ordering(out)
}
