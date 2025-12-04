package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func NatPlusGenerator(t *testing.T) *rapid.Generator[*num.NatPlus] {
	return rapid.Custom(func(t *rapid.T) *num.NatPlus {
		n := rapid.Uint64Min(1).Draw(t, "n")
		out, err := num.NPlus().FromUint64(n)
		require.NoError(t, err)
		return out
	})
}

func NatGenerator(t *testing.T) *rapid.Generator[*num.Nat] {
	return rapid.Custom(func(t *rapid.T) *num.Nat {
		n := rapid.Uint64().Draw(t, "n")
		return num.N().FromUint64(n)
	})
}

func TestNPlusLikeProperties(t *testing.T) {
	t.Parallel()
	suite := properties.NewNPlusLikePropertySuite(t, num.NPlus(), NatPlusGenerator(t))
	suite.CheckAll(t)
}

func TestNLikeProperties(t *testing.T) {
	t.Parallel()
	suite := properties.NewNLikePropertySuite(t, num.N(), NatGenerator(t))
	suite.CheckAll(t)
}

func TestNPlus_TrySub_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		a := g.Draw(t, "a")
		b := g.Draw(t, "b")
		diff, err := a.TrySub(b)
		if a.IsLessThanOrEqual(b) {
			require.ErrorIs(t, err, num.ErrOutOfRange)
		} else {
			shouldBeA := diff.Add(b)
			require.True(t, shouldBeA.Equal(a))
		}
	})
}

func TestNPlus_Compare_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		a := g.Draw(t, "a")
		b := g.Draw(t, "b")
		cmp := a.Compare(b)
		if a.Big().Uint64() < b.Big().Uint64() {
			require.True(t, cmp.IsLessThan())
		} else if a.Big().Uint64() > b.Big().Uint64() {
			require.True(t, cmp.IsGreaterThan())
		} else {
			require.True(t, cmp.IsEqual())
		}
	})
}
