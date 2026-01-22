package base

import (
	"golang.org/x/exp/constraints"

	"github.com/bronlabs/bron-crypto/pkg/base/ct"
	"github.com/bronlabs/errs-go/errs"
)

type (
	// PartialOrdering represents a partial ordering result.
	// It can take values: Incomparable, LessThan, Equal, GreaterThan.
	PartialOrdering int8
	// Ordering represents a total ordering result.
	// It can take values: LessThan, Equal, GreaterThan.
	Ordering int8
)

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

// String returns the string representation of the PartialOrdering.
func (o PartialOrdering) String() string {
	return orderString(int(o))
}

// String returns the string representation of the Ordering.
func (o Ordering) String() string {
	return orderString(int(o))
}

// Is checks if the PartialOrdering is equal to the given Ordering.
func (o PartialOrdering) Is(other Ordering) bool {
	return o == PartialOrdering(other)
}

// Is checks if the Ordering is equal to the given PartialOrdering.
func (o Ordering) Is(other PartialOrdering) bool {
	return other != Incomparable && PartialOrdering(o) == other
}

// IsLessThan checks if the PartialOrdering represents LessThan.
func (o PartialOrdering) IsLessThan() bool {
	return o == LessThan
}

// IsLessThan checks if the Ordering represents LessThan.
func (o Ordering) IsLessThan() bool {
	return o == Ordering(LessThan)
}

// IsGreaterThan checks if the PartialOrdering represents GreaterThan.
func (o PartialOrdering) IsGreaterThan() bool {
	return o == GreaterThan
}

// IsGreaterThan checks if the Ordering represents GreaterThan.
func (o Ordering) IsGreaterThan() bool {
	return o == Ordering(GreaterThan)
}

// IsEqual checks if the PartialOrdering represents Equal.
func (o PartialOrdering) IsEqual() bool {
	return o == Equal
}

// IsEqual checks if the Ordering represents Equal.
func (o Ordering) IsEqual() bool {
	return o == Ordering(Equal)
}

// IsIncomparable checks if the PartialOrdering represents Incomparable.
func (o PartialOrdering) IsIncomparable() bool {
	return o == Incomparable
}

// Comparable represents types that can be compared.
type Comparable[E any] interface {
	// IsLessThanOrEqual checks if the receiver is less than or equal to rhs.
	IsLessThanOrEqual(rhs E) bool
}

// WithInternalPartialCompareMethod allows types to implement their own PartialCompare method.
type WithInternalPartialCompareMethod[E any] interface {
	// PartialCompare compares the receiver with rhs and returns a PartialOrdering.
	PartialCompare(rhs E) PartialOrdering
}

// WithInternalCompareMethod allows types to implement their own Compare method.
type WithInternalCompareMethod[E any] interface {
	// Compare compares the receiver with rhs and returns an Ordering.
	Compare(rhs E) Ordering
}

// PartialCompare compares two elements and returns their PartialOrdering.
// It prefers ct.Comparable if available for constant-time comparison.
func PartialCompare[E Comparable[E]](x, y E) PartialOrdering {
	// If the type implements ct.Comparable, use it for constant-time comparison
	if cmp, ok := any(x).(ct.Comparable[E]); ok {
		lt, eq, gt := cmp.Compare(y)
		return ParseOrderingFromMasks(lt, eq, gt)
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

// Compare compares two elements and returns their Ordering.
// It panics if the elements are Incomparable.
// It prefers ct.Comparable if available for constant-time comparison.
func Compare[E Comparable[E]](x, y E) Ordering {
	// Prefer ct.Comparable if available for constant-time
	if cmp, ok := any(x).(ct.Comparable[E]); ok {
		out := ParseOrderingFromMasks(cmp.Compare(y))
		if out == Incomparable {
			panic(ErrIsIncomparable)
		}
		return Ordering(out)
	}
	// Fallback: allow internal Compare
	if xx, okx := any(x).(WithInternalCompareMethod[E]); okx {
		return xx.Compare(y)
	}
	out := PartialCompare(x, y)
	if out == Incomparable {
		panic(ErrIsIncomparable)
	}
	return Ordering(out)
}

// ParseOrderingFromMasks parses a PartialOrdering from comparison masks.
func ParseOrderingFromMasks[F constraints.Integer](lt, eq, gt F) PartialOrdering {
	if gt != 0 {
		return GreaterThan
	}
	if eq != 0 {
		return Equal
	}
	if lt != 0 {
		return LessThan
	}
	return Incomparable
}

var (
	ErrIsIncomparable = errs.New("elements are incomparable")
)
