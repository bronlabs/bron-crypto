package properties

import (
	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"pgregory.net/rapid"
)

type Carrier[S algebra.Structure[E], E algebra.Element[E]] struct {
	Value S
	Dist  *rapid.Generator[E]
}

type Carrier2[
	S1 algebra.Structure[E1], S2 algebra.Structure[E2],
	E1 algebra.Element[E1], E2 algebra.Element[E2],
] struct {
	First  *Carrier[S1, E1]
	Second *Carrier[S2, E2]
	Action *Action[E2, E1]
}
