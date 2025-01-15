package randwrap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/base"
	"github.com/bronlabs/krypton-primitives/pkg/csprng/randwrap"
)

func TestSmoke(t *testing.T) {
	t.Parallel()

	require.GreaterOrEqual(t, randwrap.L, randwrap.N-randwrap.LPrime,
		"Invalid randwrap parameters (RFC8937). Must verify L >= N - L'")

	require.Equal(t, randwrap.L, randwrap.LBytes*8, "Ensure L bits-bytes matching")
	require.Equal(t, randwrap.N, randwrap.NBytes*8, "Ensure N bits-bytes matching")
	require.Equal(t, randwrap.LPrime, randwrap.LPrimeBytes*8, "Ensure L' bits-bytes matching")

	require.GreaterOrEqual(t, (randwrap.Counter{}).Structure().ElementSize(), randwrap.LPrimeBytes,
		"Invalid type size for tag2, must be at least L' bytes")

	require.GreaterOrEqual(t, base.RandomOracleHashFunction().Size(), randwrap.NBytes,
		"hash function output length is too short")
	require.GreaterOrEqual(t, randwrap.BlockHasher().Size(), randwrap.NBytes,
		"block hash function output length is too short")
}
