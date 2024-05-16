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

func Fuzz_Property_Point(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := pointGeneratorFactory(f, curve)
	fu.RunAlgebraPropertyTest(f, atu.CheckGroupInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}
