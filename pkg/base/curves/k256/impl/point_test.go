package k256arith_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/curves/impl"
	k256arith "github.com/copperexchange/krypton/pkg/base/curves/k256/impl"
)

func TestK256PointArithmetic_Hash(t *testing.T) {
	var b [32]byte
	sc, err := k256arith.PointNew().Hash(b[:], impl.EllipticPointHasherSha256())

	require.NoError(t, err)
	require.True(t, !sc.IsIdentity())
	require.True(t, sc.IsOnCurve())
}
