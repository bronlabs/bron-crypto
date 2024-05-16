package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type AdditiveGroupInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]] struct{}

func (gi *AdditiveGroupInvariants[G, GE]) IsIdentity(t *testing.T,
	group algebra.AdditiveGroup[G, GE],
	element algebra.AdditiveGroupElement[G, GE],
) {
	t.Helper()
	require.NotNil(t, element)
	isIdentity := element.IsAdditiveIdentity()
	identity := group.AdditiveIdentity()
	equalToIdentity := element.Equal(identity)
	require.Equal(t, equalToIdentity, isIdentity,
		"IsIdentity must match with equality to group's Identity element.")
}

func (gi *AdditiveGroupInvariants[G, GE]) Add(t *testing.T,
	group algebra.AdditiveGroup[G, GE],
	el1 algebra.AdditiveGroupElement[G, GE],
	el2 algebra.AdditiveGroupElement[G, GE],
) {
	t.Helper()
	require.NotNil(t, el1)
	identity := group.AdditiveIdentity()
	require.True(t, el1.Equal(el1.Add(identity)),
		"Addition with identity must be equal to the element itself.")
	require.True(t, el2.Equal(el2.Add(identity)),
		"Addition with identity must be equal to the element itself.")
	sum := el1.Add(el2)
	require.True(t, sum.Equal(group.Add(el1, el2)),
		"Addition must be consistent with group's Add method.")
	require.True(t, group.Contains(sum),
		"Addition must result in an element that is in the group.")
}

// TODO: Write invariants for all the group methods

// TODO: Write invariants for the underlying algebraic structures (monoid, groupoid) and compose them below.

func CheckGroupInvariants[G algebra.AdditiveGroup[G, GE], GE algebra.AdditiveGroupElement[G, GE]](t *testing.T, group G, elementGenerator fu.ObjectGenerator[GE]) {
	t.Helper()
	require.NotNil(t, group)
	require.NotNil(t, elementGenerator)
	invs := &AdditiveGroupInvariants[G, GE]{}
	t.Run("IsIdentity", func(t *testing.T) {
		t.Parallel()
		gen := elementGenerator.Clone()
		isEmpty := gen.Prng().Bool()
		element := gen.Empty()
		if !isEmpty {
			element = gen.GenerateNonZero()
		}
		invs.IsIdentity(t, group, element)
	})
	t.Run("Add", func(t *testing.T) {
		t.Parallel()
		gen1 := elementGenerator.Clone()
		gen2 := elementGenerator.Clone()
		isEmpty1 := gen1.Prng().IntRange(0, 16)
		isEmpty2 := gen2.Prng().IntRange(0, 16)
		el1 := gen1.Empty()
		el2 := gen2.Empty()
		if isEmpty1 != 0 {
			el1 = gen1.GenerateNonZero()
		}
		if isEmpty2 != 0 {
			el2 = gen2.GenerateNonZero()
		}
		invs.Add(t, group, el1, el2)
	})
}
