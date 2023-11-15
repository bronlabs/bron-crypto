package k256arith_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	k256arith "github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256/impl/fp"
)

func TestK256PointArithmetic_Map(t *testing.T) {
	sc := k256arith.PointNew()

	u0 := fp.New().SetUint64(4)
	u1 := fp.New().SetUint64(5)
	err := sc.Arithmetic.Map(u0, u1, sc)

	require.NoError(t, err)
	require.True(t, !sc.IsIdentity())
	require.True(t, sc.IsOnCurve())
}
