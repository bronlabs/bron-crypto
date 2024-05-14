package curve_test

import (
	"testing"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	curves_testutils "github.com/copperexchange/krypton-primitives/pkg/base/curves/testutils"
	fu "github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
	"github.com/stretchr/testify/require"
)

func makeGenerator(f *testing.F, curve curves.Curve) fu.ObjectGenerator[curves.Point] {
	f.Helper()

	adapter := curves_testutils.PointAdapter{Curve: curve}

	prng := fu.NewPrng()
	objectGenerator, err := fu.NewObjectGenerator[curves.Point](adapter, prng)
	require.NoError(f, err)

	return objectGenerator
}

func Fuzz_Property_HashableHashSet(f *testing.F) {
	curve := edwards25519.NewCurve()
	g := makeGenerator(f, curve)
	fu.RunAlgebraPropertyTest(f, curves_testutils.CheckGroupInvariants[curves.Curve, curves.Point], curves.Curve(curve), g)
}
