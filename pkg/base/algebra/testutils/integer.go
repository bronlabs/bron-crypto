package curves_testutils

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

type IntegerFiniteFieldInvariants[F algebra.IntegerFiniteField[F, FE], FE algebra.IntegerFiniteFieldElement[F, FE]] struct{}

func CheckIntegerFiniteFieldInvariants[F algebra.IntegerFiniteField[F, FE], FE algebra.IntegerFiniteFieldElement[F, FE]](t *testing.T, f F, elementGenerator fu.ObjectGenerator[FE]) {
	t.Helper()
	require.NotNil(t, f)
	require.NotNil(t, elementGenerator)
	// CheckIntegerRingInvariants[F, FE](t, f, elementGenerator) //TODO
	// CheckEuclideanDomainInvariants[F, FE](t, f, elementGenerator) //TODO
	CheckNatSerializationInvariants[FE](t, elementGenerator)
	CheckBytesSerializationInvariants[FE](t, elementGenerator)
	CheckFiniteFieldInvariants[F, FE](t, f, elementGenerator)
}
