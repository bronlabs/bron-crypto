package sliceutils_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/base/utils/sliceutils"
)

func TestShuffled_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.SliceOfN(rapid.Int(), 0, 100).Draw(t, "input")

		result, err := sliceutils.Shuffled(input, pcg.NewRandomised())
		require.NoError(t, err)
		require.Len(t, result, len(input))
		require.ElementsMatch(t, input, result, "Shuffled result should have the same elements as input")
	})
}
