package softspoken_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/ot/extension/softspoken"
)

func TestSmoke(t *testing.T) {
	t.Parallel()

	require.GreaterOrEqual(t, softspoken.Sigma, 128,
		"Ensure a minimum of 128-bit computational security (due to use of Fiat-Shamir)")

	require.Equal(t, softspoken.Sigma, softspoken.SigmaBytes*8, "Ensure bits-bytes matching")
}
