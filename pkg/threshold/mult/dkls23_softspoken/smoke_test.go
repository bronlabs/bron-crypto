package dkls23_softspoken_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/threshold/mult/dkls23_softspoken"
)

func TestSmoke(t *testing.T) {
	t.Parallel()

	require.GreaterOrEqual(t, dkls23_softspoken.Lambda, 128, "Ensure a minimum of 128-bit computational security")
	require.GreaterOrEqual(t, dkls23_softspoken.S, 128, "Ensure a minimum of 128-bit computational security (due to use of Fiat-Shamir)")

	require.Equal(t, dkls23_softspoken.Lambda, dkls23_softspoken.LambdaBytes*8, "Ensure bits-bytes matching")
	require.Equal(t, dkls23_softspoken.S, dkls23_softspoken.SBytes*8, "Ensure bits-bytes matching")
	require.Equal(t, dkls23_softspoken.QBitLen, dkls23_softspoken.QBitLenBytes*8, "Ensure bits-bytes matching")
	require.Equal(t, dkls23_softspoken.Xi, dkls23_softspoken.XiBytes*8, "Ensure bits-bytes matching")
	require.Equal(t, dkls23_softspoken.Eta, dkls23_softspoken.EtaBytes*8, "Ensure bits-bytes matching")

	require.Equal(t, dkls23_softspoken.Rho, dkls23_softspoken.QBitLen/dkls23_softspoken.Lambda, "Invalid DKLs23 parameter relationship")
	require.Equal(t, dkls23_softspoken.LOTe, dkls23_softspoken.L+dkls23_softspoken.Rho, "Invalid DKLs23 parameter relationship")
	require.Equal(t, dkls23_softspoken.Xi, dkls23_softspoken.QBitLen+2*dkls23_softspoken.S, "Invalid DKLs23 parameter relationship")
	require.Equal(t, dkls23_softspoken.Eta, dkls23_softspoken.Xi*dkls23_softspoken.L, "Invalid DKLs23 parameter relationship")
}
