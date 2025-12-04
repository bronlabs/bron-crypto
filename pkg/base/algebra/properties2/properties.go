package properties2

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type Property[S algebra.Structure[E], E algebra.Element[E]] struct {
	Name  string
	Check func(t *testing.T, s Structure[S, E])
}

type Property2[
	S1 algebra.Structure[E1], S2 algebra.Structure[E2],
	E1 algebra.Element[E1], E2 algebra.Element[E2],
] struct {
	Name  string
	Check func(t *testing.T, s TwoSortedStructure[S1, S2, E1, E2])
}
