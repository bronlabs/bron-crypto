package ct

type (
	// Choice represents a constant-time boolean choice.
	Choice uint64
	Bool   = Choice // TODO: remove
)

const (
	Zero Choice = 0
	One  Choice = 1

	False Bool = 0
	True  Bool = 1
)

// Not returns the negation of the Choice.
func (c Choice) Not() Choice {
	return c ^ One
}

// Comparable represents types that can be compared in constant time.
type Comparable[E any] interface {
	Compare(rhs E) (gt, eq, lt Bool)
}

// Equatable represents types that can be checked for equality in constant time.
type Equatable[E any] interface {
	Equal(rhs E) Bool
}

// ConditionallySelectable represents types that can be conditionally selected in constant time.
type ConditionallySelectable[E any] interface {
	Select(choice Choice, x0, x1 E)
}

// ConditionallyAssignable represents types that can be conditionally assigned in constant time.
type ConditionallyAssignable[E any] interface {
	CondAssign(Choice, E)
}

// ConditionallyNegatable represents types that can be conditionally negated in constant time.
type ConditionallyNegatable[E any] interface {
	CondNeg(Choice)
}
