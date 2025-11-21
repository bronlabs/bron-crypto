package algebrautils_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/algebrautils"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestRandomNonIdentity_Property(t *testing.T) {
	t.Parallel()
	curve := k256.NewCurve()
	prng := crand.Reader
	rapid.Check(t, func(t *rapid.T) {
		result, err := algebrautils.RandomNonIdentity(curve, prng)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.False(t, result.IsOpIdentity())
	})
}
