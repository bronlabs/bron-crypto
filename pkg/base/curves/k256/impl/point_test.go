package impl_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
)

func TestK256PointArithmetic_Map(t *testing.T) {
	t.Parallel()
	sc := impl.PointNew()

	u0 := fp.New().SetUint64(4)
	u1 := fp.New().SetUint64(5)
	err := sc.Arithmetic.Map(u0, u1, sc)

	require.NoError(t, err)
	require.False(t, sc.IsIdentity())
	require.True(t, sc.IsOnCurve())
}
