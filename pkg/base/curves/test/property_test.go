package curves_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	atu "github.com/copperexchange/krypton-primitives/pkg/base/algebra/testutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	ctu "github.com/copperexchange/krypton-primitives/pkg/base/curves/test/fuzzutils"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
)

func pointGeneratorFactory(f *testing.F, curve curves.Curve) fu.ObjectGenerator[curves.Point] {
	f.Helper()

	adapter := &ctu.PointAdapter{Curve: curve}

	prng := fu.NewPrng()
	objectGenerator, err := fu.NewObjectGenerator(adapter, prng)
	require.NoError(f, err)

	return objectGenerator
}

func scalarGeneratorFactory(f *testing.F, curve curves.Curve) fu.ObjectGenerator[curves.Scalar] {
	f.Helper()

	adapter := &ctu.ScalarAdapter{Curve: curve}

	prng := fu.NewPrng()
	objectGenerator, err := fu.NewObjectGenerator(adapter, prng)
	require.NoError(f, err)

	return objectGenerator
}

func baseFieldGeneratorFactory(f *testing.F, curve curves.Curve) fu.ObjectGenerator[curves.BaseFieldElement] {
	f.Helper()

	adapter := &ctu.BaseFieldElementAdapter{Curve: curve}

	prng := fu.NewPrng()
	objectGenerator, err := fu.NewObjectGenerator(adapter, prng)
	require.NoError(f, err)

	return objectGenerator
}

func Fuzz_Property_Point_AdditiveGroup(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckAdditiveGroupInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}

func Fuzz_Property_Point_FiniteStructure(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckFiniteStructureInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}

func Fuzz_Property_Point_SubGroup(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckSubGroupInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}

func Fuzz_Property_ScalarField_FiniteField(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := scalarGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckFiniteFieldInvariants[curves.ScalarField, curves.Scalar], curve.ScalarField(), g)
}
func Fuzz_Property_BaseField_FiniteField(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := baseFieldGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckFiniteFieldInvariants[curves.BaseField, curves.BaseFieldElement], curve.BaseField(), g)
}
