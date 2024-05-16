package curves_testutils

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/curveutils"
	"github.com/copperexchange/krypton-primitives/pkg/base/fuzzutils"
)

var CurveAdapter = fuzzutils.ListElementAdapter[curves.Curve]{
	List: curveutils.GetAllCurves(),
}

func CurveGenerator(f *testing.F) fuzzutils.ObjectGenerator[curves.Curve] {
	f.Helper()
	prng := fuzzutils.NewPrng()
	objectGenerator, err := fuzzutils.NewObjectGenerator[curves.Curve](CurveAdapter, prng)
	require.NoError(f, err)
	return objectGenerator
}
