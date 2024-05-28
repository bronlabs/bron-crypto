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

func Fuzz_Property_Point_Group(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckGroupInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}
func Fuzz_Property_Point_SubGroup(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckSubGroupInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}
func Fuzz_Property_Point_AdditiveGroup(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckAdditiveGroupInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}

func Fuzz_Property_Point_MultiplicativeGroup(f *testing.F) {
	curve := edwards25519.NewCurve() // TODO: err `missing method DiscreteExponentiation`
	g := scalarGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckMultiplicativeGroupInvariants[curves.ScalarField, curves.Scalar], curve.ScalarField(), g)
}

func Fuzz_Property_Point_CyclicGroup(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckCyclicGroupInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}

// Set checks
func Fuzz_Property_Point_StructuredSet(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckStructuredSetInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}

func Fuzz_Property_Point_StructuredSetConstant(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckStructuredSetConstant[curves.Curve, curves.Point], curves.Curve(curve), g)
}

func Fuzz_Property_Point_FiniteSet(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckFiniteStructureInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}
func Fuzz_Property_Point_PointedSet(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckPointedSetElementConstant[curves.Curve, curves.Point], curves.Curve(curve), g)
}

// Groupoid Checks
func Fuzz_Property_Point_Groupoid(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckGroupoidInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}
func Fuzz_Property_Point_AddativeGroupoid(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckAdditiveGroupoidInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}

func Fuzz_Property_Point_MultiplicativeGroupoid(f *testing.F) { //Missing Method DiscreteExponentiation
	curve := edwards25519.NewCurve()
	g := scalarGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckMultiplicativeGroupoidInvariants[curves.ScalarField, curves.Scalar], curve.ScalarField(), g)
}

func Fuzz_Property_Point_CyclicGroupoid(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckCyclicGroupoidInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}

// monoid Checks
func Fuzz_Property_Point_Monoid(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckMonoidInvariant[curves.Curve, curves.Point], curves.Curve(curve), g)
}

func Fuzz_Property_Point_AddativeMonoid(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckAdditiveMonoidInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}

func Fuzz_Property_Point_MultiplicativeMonoid(f *testing.F) { //Missing Method DiscreteExponentiation
	curve := edwards25519.NewCurve()
	g := scalarGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckMultiplicativeMonoidInvariants[curves.ScalarField, curves.Scalar], curve.ScalarField(), g)
}

func Fuzz_Property_Point_CyclicMonoid(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckCyclicMonoidInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}
