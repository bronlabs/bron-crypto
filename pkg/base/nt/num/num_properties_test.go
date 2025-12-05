package num_test

import (
	"math/big"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func FromBigRoundTrip_Property[E interface {
	Big() *big.Int
}](t *testing.T, structure interface {
	FromBig(*big.Int) (E, error)
}, g *rapid.Generator[E]) {
	t.Helper()
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		elem, err := structure.FromBig(n.Big())
		require.NoError(t, err)
		require.EqualValues(t, n.Big().Bytes(), elem.Big().Bytes())
	})
}

func FromNatPlusRoundTrip_Property[E interface {
	Big() *big.Int
}](t *testing.T, structure interface {
	FromNatPlus(*num.NatPlus) (E, error)
}, g *rapid.Generator[*num.NatPlus]) {
	t.Helper()
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		elem, err := structure.FromNatPlus(n)
		require.NoError(t, err)
		require.EqualValues(t, n.Big().Bytes(), elem.Big().Bytes())
	})
}

func FromNatRoundTrip_Property[E interface {
	Big() *big.Int
}](t *testing.T, structure interface {
	FromNat(*num.Nat) (E, error)
}, g *rapid.Generator[*num.Nat], canBeZero bool) {
	t.Helper()
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		elem, err := structure.FromNat(n)
		if !canBeZero && n.IsZero() {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		require.EqualValues(t, n.Big().Bytes(), elem.Big().Bytes())
	})
}

func FromIntRoundTrip_Property[E interface {
	Big() *big.Int
}](t *testing.T, structure interface {
	FromInt(*num.Int) (E, error)
}, g *rapid.Generator[*num.Int], canBeZero, canBeNegative bool) {
	t.Helper()
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		elem, err := structure.FromInt(n)
		if !canBeZero && n.IsZero() {
			require.Error(t, err)
			return
		}
		if !canBeNegative && n.IsNegative() {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		require.EqualValues(t, n.Big().Bytes(), elem.Big().Bytes())
	})
}

func FromRatRoundTrip_Property[E interface {
	Big() *big.Int
}](t *testing.T, structure interface {
	FromRat(*num.Rat) (E, error)
}, g *rapid.Generator[*num.Rat], canBeZero, canBeNegative bool) {
	t.Helper()
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		elem, err := structure.FromRat(n)
		if !canBeZero && n.IsZero() {
			require.Error(t, err)
			return
		}
		if !canBeNegative && n.IsNegative() {
			require.Error(t, err)
			return
		}
		if !n.IsInt() {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		require.EqualValues(t, n.Canonical().Numerator().Big().Bytes(), elem.Big().Bytes())
	})
}

func HashCodeEqualityCorrespondence_Property[E base.Hashable[E]](t *testing.T, g *rapid.Generator[E]) {
	t.Helper()
	rapid.Check(t, func(t *rapid.T) {
		a := g.Draw(t, "a")
		b := g.Draw(t, "b")
		if a.Equal(b) {
			require.Equal(t, a.HashCode(), b.HashCode())
		}
	})
}
