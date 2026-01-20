package mathutils_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"

	"github.com/bronlabs/bron-crypto/pkg/base/utils/mathutils"
)

func TestCeilDiv_Property(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		a := rapid.IntRange(0, 1000).Draw(t, "a")
		b := rapid.IntRange(1, 1000).Draw(t, "b") // b must be > 0

		result := mathutils.CeilDiv(a, b)
		require.GreaterOrEqual(t, result*b, a, "CeilDiv result multiplied by b should be >= a")
		require.Less(t, (result-1)*b, a, "One less than CeilDiv result multiplied by b should be < a")
	})
}
