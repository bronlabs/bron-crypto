package randfischlin_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/proofs/sigma/compiler/randfischlin"
)

func TestSmoke(t *testing.T) {
	t.Parallel()

	require.GreaterOrEqual(t, randfischlin.Lambda, 128,
		"Ensure a minimum of 128-bit computational security")
	require.Equal(t, 1<<randfischlin.LambdaLog2, randfischlin.Lambda,
		"Ensure lambdaLog2 matches lambda")

	require.Equal(t, randfischlin.L, randfischlin.LBytes*8, "Ensure bits-bytes matching")
	require.Equal(t, randfischlin.T, randfischlin.TBytes*8, "Ensure bits-bytes matching")

	require.Equal(t, randfischlin.L*randfischlin.R, randfischlin.Lambda,
		"Invalid KS22 parameter relationships, must verify L*R = lambda")
	require.Equal(t, randfischlin.LambdaLog2*randfischlin.L, randfischlin.T,
		"Invalid KS22 parameter relationships, must verify lambdaLog2*L = t")
}
