package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type FieldInvariants[F algebra.Field[F, E], E algebra.FieldElement[F, E]] struct{}

type FieldElementInvariants[F algebra.Field[F, E], E algebra.FieldElement[F, E]] struct{}

type FiniteFieldInvariants[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]] struct{}

type FiniteFieldElementInvariants[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]] struct{}

func (fi *FieldInvariants[F, E]) MultiplicativeGroup(t *testing.T) {
	t.Helper()
	// TODO
}

func CheckFieldInvariants[F algebra.Field[F, E], E algebra.FieldElement[F, E]](t *testing.T, field F, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, field)
	require.NotNil(t, elementGenerator)

	// CheckEuclideanDomainInvariants[F, E](t, field, elementGenerator) // TODO: need to be defined
	CheckMultiplicativeGroupInvariants[F, E](t, field, elementGenerator)

	fi := &FieldInvariants[F, E]{}
	fi.MultiplicativeGroup(t)
}

func CheckFiniteFieldInvariants[F algebra.FiniteField[F, E], E algebra.FiniteFieldElement[F, E]](t *testing.T, field F, elementGenerator fu.ObjectGenerator[E]) {
	t.Helper()
	require.NotNil(t, field)
	require.NotNil(t, elementGenerator)

	// CheckFiniteStructureInvariants[F, E](t, field, elementGenerator)
	CheckFieldInvariants[F, E](t, field, elementGenerator)
	CheckFiniteRingInvariants[F, E](t, field, elementGenerator)
}
