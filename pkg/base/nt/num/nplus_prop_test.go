package num_test

import (
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra/properties"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/num"
	"github.com/bronlabs/bron-crypto/pkg/base/nt/numct"
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

func SmallNatPlusGenerator(t *testing.T) *rapid.Generator[*num.NatPlus] {
	return rapid.Custom(func(t *rapid.T) *num.NatPlus {
		n := rapid.Uint16Min(1).Draw(t, "n")
		out, err := num.NPlus().FromUint64(uint64(n))
		require.NoError(t, err)
		return out
	})
}

func TestNPlusLikeProperties(t *testing.T) {
	t.Parallel()
	suite := properties.NPlusLike(t, num.NPlus(), NatPlusGenerator(t))
	suite.Check(t)
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

func TestNPlus_FromBigRoundTrip_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	FromBigRoundTrip_Property(t, num.NPlus(), g)
}

func TestNPlus_FromNat_Property(t *testing.T) {
	t.Parallel()
	g := NatGenerator(t)
	FromNatRoundTrip_Property(t, num.NPlus(), g, false)
}

func TestNPlus_FromInt_Property(t *testing.T) {
	t.Parallel()
	g := IntGenerator(t)
	FromIntRoundTrip_Property(t, num.NPlus(), g, false, false)
}

func TestNPlus_FromRat_Property(t *testing.T) {
	t.Parallel()
	g := SmallRatGenerator(t)
	FromRatRoundTrip_Property(t, num.NPlus(), g, false, false)
}

func TestNPlus_HashcodeEqualityCorrespondence_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	HashCodeEqualityCorrespondence_Property(t, g)
}

func TestNPlus_Lsh_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		shift := rapid.UintRange(0, 128).Draw(t, "shift")
		lsh := n.Lsh(shift)
		var expected numct.Nat
		expected.Lsh(n.Value(), shift)
		require.EqualValues(t, expected.Big().Bytes(), lsh.Big().Bytes())
	})
}

func TestNPlus_Rsh_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		shift := rapid.UintRange(0, 128).Draw(t, "shift")
		rsh, err := n.TryRsh(shift)
		var expected numct.Nat
		expected.Rsh(n.Value(), shift)
		if expected.Big().Sign() == 0 {
			// Shifting to zero should return an error for NatPlus
			require.ErrorIs(t, err, num.ErrOutOfRange)
		} else {
			require.NoError(t, err)
			require.EqualValues(t, expected.Big().Bytes(), rsh.Big().Bytes())
		}
	})
}

func TestNPlus_Bit_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		bitIndex := rapid.UintRange(0, 256).Draw(t, "bitIndex")
		bit := n.Bit(bitIndex)
		expected := numct.NewNatFromBig(n.Big(), n.Big().BitLen())
		expectedBit := expected.Bit(bitIndex)
		require.Equal(t, expectedBit, bit, "bit(%d) of %s should be %d", bitIndex, n.String(), expectedBit)
	})
}

func TestNPlus_Byte_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		byteIndex := rapid.UintRange(0, 32).Draw(t, "byteIndex")
		b := n.Byte(byteIndex)
		expected := numct.NewNatFromBig(n.Big(), n.Big().BitLen())
		expectedByte := expected.Byte(byteIndex)
		require.Equal(t, expectedByte, b, "byte(%d) of %s should be %d", byteIndex, n.String(), expectedByte)
	})
}

func TestNPlus_IncrementDecrement_Property(t *testing.T) {
	t.Parallel()
	g := NatPlusGenerator(t)
	rapid.Check(t, func(t *rapid.T) {
		n := g.Draw(t, "n")
		shouldBeN, err := n.Increment().Decrement()
		require.NoError(t, err)
		require.True(t, shouldBeN.Equal(n), "n=%s, inc(dec(n))=%s", n.String(), shouldBeN.String())
	})
}
