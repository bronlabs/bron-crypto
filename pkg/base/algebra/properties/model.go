package properties

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

type Model[S Structure, E Element] struct {
	*Carrier[S, E]

	Theory []Axiom
}

func (m *Model[S, E]) Check(t *testing.T) {
	t.Helper()
	check(t, m.Theory...)
}

type TwoSortedModel[
	S1, S2 Structure,
	E1, E2 Element,
] struct {
	*Carrier2[S1, S2, E1, E2]

	Theory []Axiom
}

func (m *TwoSortedModel[S1, S2, E1, E2]) Check(t *testing.T) {
	t.Helper()
	check(t, m.Theory...)
}

func Union[S Structure, E Element](t *testing.T, models ...*Model[S, E]) *Model[S, E] {
	t.Helper()
	require.NotEmpty(t, models)
	for _, m := range models {
		require.Equal(t, models[0].Value.Name(), m.Value.Name())
	}
	return &Model[S, E]{
		Carrier: models[0].Carrier,
		Theory: slices.Concat(
			sliceutils.Map(
				models,
				func(m *Model[S, E]) []Axiom { return m.Theory },
			)...,
		),
	}
}

func Union2[
	S1, S2 Structure,
	E1, E2 Element,
](t *testing.T, models ...*TwoSortedModel[S1, S2, E1, E2]) *TwoSortedModel[S1, S2, E1, E2] {
	t.Helper()
	require.NotEmpty(t, models)
	for _, m := range models {
		require.Equal(t, models[0].First.Value.Name(), m.First.Value.Name())
		require.Equal(t, models[0].Second.Value.Name(), m.Second.Value.Name())
	}
	return &TwoSortedModel[S1, S2, E1, E2]{
		Carrier2: models[0].Carrier2,
		Theory: slices.Concat(
			sliceutils.Map(
				models,
				func(m *TwoSortedModel[S1, S2, E1, E2]) []Axiom { return m.Theory },
			)...,
		),
	}
}

func UnionAlongFirst[
	S1, S2 Structure,
	E1, E2 Element,
](t *testing.T, model *TwoSortedModel[S1, S2, E1, E2], others ...*Model[S1, E1]) *TwoSortedModel[S1, S2, E1, E2] {
	t.Helper()
	require.NotEmpty(t, others)
	for _, m := range others {
		require.Equal(t, model.First.Value.Name(), m.Value.Name())
	}
	return &TwoSortedModel[S1, S2, E1, E2]{
		Carrier2: model.Carrier2,
		Theory: append(
			model.Theory,
			slices.Concat(
				sliceutils.Map(
					others,
					func(m *Model[S1, E1]) []Axiom { return m.Theory },
				)...,
			)...,
		),
	}
}

func UnionAlongSecond[
	S1, S2 Structure,
	E1, E2 Element,
](t *testing.T, model *TwoSortedModel[S1, S2, E1, E2], others ...*Model[S2, E2]) *TwoSortedModel[S1, S2, E1, E2] {
	t.Helper()
	require.NotEmpty(t, others)
	for _, m := range others {
		require.Equal(t, model.Second.Value.Name(), m.Value.Name())
	}
	return &TwoSortedModel[S1, S2, E1, E2]{
		Carrier2: model.Carrier2,
		Theory: append(
			model.Theory,
			slices.Concat(
				sliceutils.Map(
					others,
					func(m *Model[S2, E2]) []Axiom { return m.Theory },
				)...,
			)...,
		),
	}
}

func Pair[
	S1, S2 Structure,
	E1, E2 Element,
](t *testing.T, first *Model[S1, E1], second *Model[S2, E2]) *TwoSortedModel[S1, S2, E1, E2] {
	t.Helper()
	return &TwoSortedModel[S1, S2, E1, E2]{
		Carrier2: &Carrier2[S1, S2, E1, E2]{
			First:  first.Carrier,
			Second: second.Carrier,
			Action: nil,
		},
		Theory: slices.Concat(first.Theory, second.Theory),
	}
}

func PairWithAction[
	S1, S2 Structure,
	E1, E2 Element,
](t *testing.T, first *Model[S1, E1], second *Model[S2, E2], action *Action[E2, E1]) *TwoSortedModel[S1, S2, E1, E2] {
	t.Helper()
	return &TwoSortedModel[S1, S2, E1, E2]{
		Carrier2: &Carrier2[S1, S2, E1, E2]{
			First:  first.Carrier,
			Second: second.Carrier,
			Action: action,
		},
		Theory: slices.Concat(first.Theory, second.Theory),
	}
}

func check(t *testing.T, axioms ...Axiom) {
	t.Helper()
	for _, a := range axioms {
		t.Run(a.Name, func(t *testing.T) {
			t.Parallel()
			a.CheckFunc(t)
		})
	}
}
