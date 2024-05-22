package dkls23_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/threshold/mult/dkls23"
)

func TestSmoke(t *testing.T) {
	t.Parallel()

	require.GreaterOrEqual(t, dkls23.Lambda, 128, "Ensure a minimum of 128-bit computational security")
	require.GreaterOrEqual(t, dkls23.S, 128, "Ensure a minimum of 128-bit computational security (due to use of Fiat-Shamir)")

	require.Equal(t, dkls23.Lambda, dkls23.LambdaBytes*8, "Ensure bits-bytes matching")
	require.Equal(t, dkls23.S, dkls23.SBytes*8, "Ensure bits-bytes matching")
	require.Equal(t, dkls23.QBitLen, dkls23.QBitLenBytes*8, "Ensure bits-bytes matching")
	require.Equal(t, dkls23.Xi, dkls23.XiBytes*8, "Ensure bits-bytes matching")
	require.Equal(t, dkls23.Eta, dkls23.EtaBytes*8, "Ensure bits-bytes matching")

	require.Equal(t, dkls23.Rho, dkls23.QBitLen/dkls23.Lambda, "Invalid DKLs23 parameter relationship")
	require.Equal(t, dkls23.LOTe, dkls23.L+dkls23.Rho, "Invalid DKLs23 parameter relationship")
	require.Equal(t, dkls23.Xi, dkls23.QBitLen+2*dkls23.S, "Invalid DKLs23 parameter relationship")
	require.Equal(t, dkls23.Eta, dkls23.Xi*dkls23.L, "Invalid DKLs23 parameter relationship")
}
