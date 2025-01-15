package ot_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/ot"
)

func TestSmoke(t *testing.T) {
	t.Parallel()

	require.GreaterOrEqual(t, ot.Kappa, 128,
		"Ensure a minimum of 128-bit computational security")

	require.Equal(t, ot.Kappa, ot.KappaBytes*8, "Ensure bits-bytes matching")

	require.GreaterOrEqual(t, ot.HashFunction().Size(), ot.KappaBytes,
		"hash function output length is too short")
}
