package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

func NatGenerator(t *testing.T) *rapid.Generator[*num.Nat] {
	return rapid.Custom(func(t *rapid.T) *num.Nat {
		n := rapid.Uint64().Draw(t, "n")
		return num.N().FromUint64(n)
	})
}

func TestNLikeProperties(t *testing.T) {
	t.Parallel()
	suite := properties.NLike(t, num.N(), NatGenerator(t))
	suite.Check(t)
}

func TestN_FromBigRoundTrip_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	FromBigRoundTrip_Property(t, num.N(), g)
}

func TestN_FromNatPlus_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	FromNatPlusRoundTrip_Property(t, num.N(), g)
}

func TestN_FromInt_Property(t *testing.T) {
	t.Parallel()
	g := IntGenerator(t)
	FromIntRoundTrip_Property(t, num.N(), g, true, false)
}

func TestN_FromRat_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	FromRatRoundTrip_Property(t, num.N(), g, true, false)
}

func TestN_HashCodeEqualityCorrespondence_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	HashCodeEqualityCorrespondence_Property(t, g)
}

func TestN_LshRshRoundTrip_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		shift := rapid.IntRange(0, 128).Draw(t, "shift")
		lsh := n.Lsh(uint(shift))
		rsh := lsh.Rsh(uint(shift))
		require.EqualValues(t, n.Big().Bytes(), rsh.Big().Bytes())
	})
}

func TestN_TrySub_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		a := g.Draw(t, "a")
		b := g.Draw(t, "b")
		c, err := a.TrySub(b)
		if a.Compare(b).IsLessThan() {
			require.ErrorIs(t, err, num.ErrUndefined)
			return
		}
		require.NoError(t, err)
		shoudBeA := c.Add(b)
		require.True(t, shoudBeA.Equal(a), "a=%s, b=%s, c=%s", a.String(), b.String(), c.String())
	})
}

func TestN_TryInv_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		ni, err := n.TryInv()
		if !n.IsOne() {
			require.ErrorIs(t, err, num.ErrUndefined)
			return
		}
		require.NoError(t, err)
		require.True(t, ni.Mul(n).IsOne())
	})
}

func TestN_TryDiv_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		a := g.Draw(t, "a")
		b := g.Draw(t, "b")
		if b.IsZero() {
			// Division by zero - skip this case
			return
		}
		q, err := a.TryDiv(b)
		// Use EuclideanDiv to check if division is exact
		_, rem, divErr := a.EuclideanDiv(b)
		require.NoError(t, divErr)
		if !rem.IsZero() {
			// Division is not exact, should return error
			require.ErrorIs(t, err, num.ErrInexactDivision)
			return
		}
		// Division is exact
		require.NoError(t, err)
		// Verify: q * b == a
		shouldBeA := q.Mul(b)
		require.True(t, shouldBeA.Equal(a), "a=%s, b=%s, q=%s", a.String(), b.String(), q.String())
	})
}

func TestN_Sqrt_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		shouldBeN, err := n.Square().Sqrt()
		require.NoError(t, err)
		require.True(t, shouldBeN.Equal(n), "n=%s, sqrt(n^2)=%s", n.String(), shouldBeN.String())
	})
}

func TestN_Compare_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
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

func TestN_IncrementDecrement_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		shouldBeN, err := n.Increment().Decrement()
		require.NoError(t, err)
		require.True(t, shouldBeN.Equal(n), "n=%s, inc(dec(n))=%s", n.String(), shouldBeN.String())
	})
}

func TestN_GCD_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		a := g.Draw(t, "a")
		b := g.Draw(t, "b")
		gcd := a.GCD(b)

		// Commutativity: gcd(a, b) == gcd(b, a)
		gcdBA := b.GCD(a)
		require.True(t, gcd.Equal(gcdBA), "gcd(%s, %s) != gcd(%s, %s)", a.String(), b.String(), b.String(), a.String())

		// gcd(a, 0) == a and gcd(0, b) == b
		if b.IsZero() {
			require.True(t, gcd.Equal(a), "gcd(%s, 0) should be %s", a.String(), a.String())
			return
		}
		if a.IsZero() {
			require.True(t, gcd.Equal(b), "gcd(0, %s) should be %s", b.String(), b.String())
			return
		}

		// gcd divides both a and b
		_, remA, err := a.EuclideanDiv(gcd)
		require.NoError(t, err)
		require.True(t, remA.IsZero(), "gcd(%s, %s)=%s should divide %s", a.String(), b.String(), gcd.String(), a.String())

		_, remB, err := b.EuclideanDiv(gcd)
		require.NoError(t, err)
		require.True(t, remB.IsZero(), "gcd(%s, %s)=%s should divide %s", a.String(), b.String(), gcd.String(), b.String())
	})
}

func TestN_ScalarMulIsMul_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		m := g.Draw(t, "m")
		actual := n.ScalarMul(m)
		expected := n.Mul(m)
		require.True(t, actual.Equal(expected), "n=%s, m=%s, scalarMul=%s, mul=%s", n.String(), m.String(), actual.String(), expected.String())
	})
}
