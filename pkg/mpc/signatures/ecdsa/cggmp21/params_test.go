package cggmp21_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/mpc/signatures/ecdsa/cggmp21"
)

func TestProtocolParameter(t *testing.T) {
	t.Parallel()

	paillierKeyLen := 2048
	k256Params, err := cggmp21.NewParameters(k256.NewCurve(), paillierKeyLen)
	require.NoError(t, err)
	require.Equal(t, 256, k256Params.Kappa())
	require.Equal(t, 256, k256Params.L())
	require.Equal(t, 512, k256Params.Epsilon())
	require.Equal(t, 1280, k256Params.LPrime())
	require.Equal(t, k256Params.LogN(), paillierKeyLen)
}
