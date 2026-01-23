package algebrautils_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
)

func TestRandomNonIdentity_Property(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	prng := pcg.NewRandomised()
	rapid.Check(t, func(t *rapid.T) {
		result, err := algebrautils.RandomNonIdentity(curve, prng)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsOpIdentity())
	})
}
