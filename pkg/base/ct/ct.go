package ct

type (
	// TODO: remove Bool
	Choice uint64
	Bool   = Choice
)

const (
	Zero Choice = 0
	One  Choice = 1

	False Bool = 0
	True  Bool = 1
)

func (c Choice) Not() Choice {
	return c ^ One
}

type Comparable[E any] interface {
	Compare(rhs E) (gt, eq, lt Bool)
}

type Equatable[E any] interface {
	Equal(rhs E) Bool
}

type ConditionallySelectable[E any] interface {
	Select(choice Choice, x0, x1 E)
}

type ConditionallyAssignable[E any] interface {
	CondAssign(Choice, E)
}

type ConditionallyNegatable[E any] interface {
	CondNeg(Choice)
}
