package properties

import (
	"pgregory.net/rapid"
)

type Structure interface {
	Name() string
}
type Element any

type Carrier[S Structure, E Element] struct {
	Value S
	Dist  *rapid.Generator[E]
}

type Carrier2[
	S1, S2 Structure,
	E1, E2 Element,
] struct {
	First  *Carrier[S1, E1]
	Second *Carrier[S2, E2]
	Action *Action[E2, E1]
}
