package curves_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	atu "github.com/copperexchange/krypton-primitives/pkg/base/algebra/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	ctu "github.com/copperexchange/krypton-primitives/pkg/base/curves/test/fuzzutils"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
)

func generatorsFactory[E algebra.Element](t *testing.T, adapter fu.ObjectAdapter[E]) []fu.ObjectGenerator[E] {
	t.Helper()

	prng := fu.NewPrng()
	objectGenerator, err := fu.NewObjectGenerator(adapter, prng) // base generator
	require.NoError(t, err)

	// Add more generators here if needed
	gs := []fu.ObjectGenerator[E]{
		fu.NewSkewedObjectGenerator(objectGenerator, 5), // 5% chance of generating a zero element
	}
	return gs
}

func Fuzz_Property_Point_AdditiveGroup(f *testing.F) {
	fu.RunAlgebraPropertyTest(f,
		TestCurves, ctu.NewPointAdapter, generatorsFactory[curves.Point],
		atu.CheckAdditiveGroupInvariants[curves.Curve, curves.Point],
		atu.CheckFiniteStructureInvariants[curves.Curve, curves.Point],
		atu.CheckCyclicGroupInvariants[curves.Curve, curves.Point],
	)
}

func Fuzz_Property_ScalarField_IntegerFiniteField(f *testing.F) {
	scalarFields := make([]curves.ScalarField, len(TestCurves))
	for i, curve := range TestCurves {
		scalarFields[i] = curve.ScalarField()
	}
	fu.RunAlgebraPropertyTest(f,
		scalarFields, ctu.NewScalarAdapter, generatorsFactory[curves.Scalar],
		atu.CheckIntegerFiniteFieldInvariants[curves.ScalarField, curves.Scalar],
	)
}

func Fuzz_Property_BaseField_IntegerFiniteField(f *testing.F) {
	baseFields := make([]curves.BaseField, len(TestCurves))
	for i, curve := range TestCurves {
		baseFields[i] = curve.BaseField()
	}
	fu.RunAlgebraPropertyTest(f,
		baseFields, ctu.NewBaseFieldElementAdapter, generatorsFactory[curves.BaseFieldElement],
		atu.CheckIntegerFiniteFieldInvariants[curves.BaseField, curves.BaseFieldElement],
	)
}
