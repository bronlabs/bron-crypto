package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties3"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func TestNPlusLikeProperties3(t *testing.T) {
	t.Parallel()

	properties3.New(t, num.NPlus(), NatPlusGenerator(t)).
		With(properties3.NPlusLikeTraits(num.NPlus())...).
		CheckAll(t)
}

func TestNLikeProperties3(t *testing.T) {
	t.Parallel()

	properties3.New(t, num.N(), NatGenerator(t)).
		With(properties3.NLikeTraits(num.N())...).
		CheckAll(t)
}

// TestNPlus_TrySub_Property3 demonstrates using the suite's context for custom tests.
func TestNPlus_TrySub_Property3(t *testing.T) {
	t.Parallel()

	suite := properties3.New(t, num.NPlus(), NatPlusGenerator(t))

	rapid.Check(t, func(rt *rapid.T) {
		a := suite.Context().Draw(rt, "a")
		b := suite.Context().Draw(rt, "b")

		diff, err := a.TrySub(b)
		if a.IsLessThanOrEqual(b) {
			require.ErrorIs(t, err, num.ErrOutOfRange)
		} else {
			require.NoError(t, err)
			require.True(t, diff.Add(b).Equal(a))
		}
	})
}
