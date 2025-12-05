package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func RatGenerator(t *testing.T) *rapid.Generator[*num.Rat] {
	return rapid.Custom(func(rt *rapid.T) *num.Rat {
		a := IntGenerator(t).Draw(rt, "a")
		b := NatPlusGenerator(t).Draw(rt, "b")
		out, err := num.Q().New(a, b)
		require.NoError(t, err)
		return out
	})
}

func SmallRatGenerator(t *testing.T) *rapid.Generator[*num.Rat] {
	return rapid.Custom(func(rt *rapid.T) *num.Rat {
		a := SmallIntGenerator(t).Draw(rt, "a")
		b := SmallNatPlusGenerator(t).Draw(rt, "b")
		out, err := num.Q().New(a, b)
		require.NoError(t, err)
		return out
	})
}
