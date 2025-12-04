package properties2

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
)

type Model[S algebra.Structure[E], E algebra.Element[E]] struct {
	Structure[S, E]
	Theory []Property[S, E]
}

func (m *Model[S, E]) Check(t *testing.T) {
	t.Helper()
	for _, prop := range m.Theory {
		t.Run(prop.Name, func(t *testing.T) {
			t.Helper()
			prop.Check(t, m.Structure)
		})
	}
}

type TwoSortedModel[
	S1 algebra.Structure[E1], S2 algebra.Structure[E2],
	E1 algebra.Element[E1], E2 algebra.Element[E2],
] struct {
	TwoSortedStructure[S1, S2, E1, E2]
	Theory []Property2[S1, S2, E1, E2]
}

func (m *TwoSortedModel[S1, S2, E1, E2]) Check(t *testing.T) {
	t.Helper()
	for _, prop := range m.Theory {
		t.Run(prop.Name, func(t *testing.T) {
			t.Helper()
			prop.Check(t, m.TwoSortedStructure)
		})
	}
}
