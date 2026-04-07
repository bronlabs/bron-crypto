package csprng_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/csprng"
)

func TestNewThreadSafePrngNilInnerReturnsErrors(t *testing.T) {
	t.Parallel()

	prng, err := csprng.NewThreadSafePrng(nil)
	require.Nil(t, prng)
	require.ErrorIs(t, err, csprng.ErrNil)
}
