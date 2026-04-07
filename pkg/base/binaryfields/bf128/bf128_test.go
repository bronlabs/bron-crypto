package bf128_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/binaryfields/bf128"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
)

const reps = 128

func TestZero(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	zero := bf128.NewField().Zero()
	require.True(t, zero.IsZero())
	require.False(t, zero.IsOne())
	_, err := zero.TryInv()
	require.Error(t, err)
	for range reps {
		x, err := bf128.NewField().Random(prng)
		require.NoError(t, err)
		require.True(t, x.Add(zero).Equal(x))
		require.True(t, x.Mul(zero).Equal(zero))
	}
}

func TestOne(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	one := bf128.NewField().One()
	require.False(t, one.IsZero())
	require.True(t, one.IsOne())
	for range reps {
		x, err := bf128.NewField().RandomNonZero(prng)
		require.NoError(t, err)
		require.True(t, x.Mul(one).Equal(x))
	}
}

func TestInv(t *testing.T) {
	t.Parallel()
	prng := pcg.NewRandomised()

	for range reps {
		x, err := bf128.NewField().RandomNonZero(prng)
		require.NoError(t, err)
		xInv, err := x.TryInv()
		require.NoError(t, err)
		y := x.Mul(xInv)
		require.True(t, y.IsOne())
	}
}

func TestInvOne(t *testing.T) {
	t.Parallel()
	f := bf128.NewField()
	one := f.One()
	inv, err := one.TryInv()
	require.NoError(t, err)
	require.True(t, inv.IsOne(), "inv(1) must be 1, got %s", inv)
	require.True(t, one.Mul(inv).IsOne())
}

func TestStringFixedWidth(t *testing.T) {
	t.Parallel()
	f := bf128.NewField()

	// "F2e128(" = 7 chars, ")" = 1 char, 32 hex chars = 40 total
	expected := 40

	require.Len(t, f.Zero().String(), expected)
	require.Len(t, f.One().String(), expected)

	el, err := f.FromBytes([]byte{
		0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	})
	require.NoError(t, err)
	require.Len(t, el.String(), expected)
}

func TestComponentsBytesHardcoded(t *testing.T) {
	t.Parallel()
	f := bf128.NewField()

	// helper: build 128 zero components, then set specific bit positions to 1
	makeComponents := func(onesAt ...int) [][]byte {
		c := make([][]byte, 128)
		for i := range c {
			c[i] = []byte{0}
		}
		for _, pos := range onesAt {
			c[pos] = []byte{1}
		}
		return c
	}

	t.Run("value 1 is 0...01", func(t *testing.T) {
		t.Parallel()
		// 1 in binary is ...0001, big-endian components: 127 zeros then 1
		one := f.One()
		components := one.ComponentsBytes()
		require.Equal(t, makeComponents(127), components)

		reconstructed, err := f.FromComponentsBytes(makeComponents(127))
		require.NoError(t, err)
		require.True(t, one.Equal(reconstructed))
	})

	t.Run("value 5 is 0...0101", func(t *testing.T) {
		t.Parallel()
		// 5 = 0b101, big-endian: 125 zeros, then 1, 0, 1
		five, err := f.FromBytes(make128(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5))
		require.NoError(t, err)

		components := five.ComponentsBytes()
		expected := makeComponents(125, 127) // bits at positions 2 and 0 → components 125 and 127
		require.Equal(t, expected, components)

		reconstructed, err := f.FromComponentsBytes(expected)
		require.NoError(t, err)
		require.True(t, five.Equal(reconstructed))
	})

	t.Run("value 0xFF is 0...011111111", func(t *testing.T) {
		t.Parallel()
		// 0xFF = 8 ones in the low byte
		val, err := f.FromBytes(make128(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF))
		require.NoError(t, err)

		components := val.ComponentsBytes()
		expected := makeComponents(120, 121, 122, 123, 124, 125, 126, 127)
		require.Equal(t, expected, components)
	})

	t.Run("high bit set", func(t *testing.T) {
		t.Parallel()
		// 2^127 = MSB only, big-endian: component[0] = 1, rest zero
		val, err := f.FromBytes(make128(0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
		require.NoError(t, err)

		components := val.ComponentsBytes()
		expected := makeComponents(0)
		require.Equal(t, expected, components)

		reconstructed, err := f.FromComponentsBytes(expected)
		require.NoError(t, err)
		require.True(t, val.Equal(reconstructed))
	})

	t.Run("zero", func(t *testing.T) {
		t.Parallel()
		zero := f.Zero()
		components := zero.ComponentsBytes()
		expected := makeComponents() // no bits set
		require.Equal(t, expected, components)

		reconstructed, err := f.FromComponentsBytes(expected)
		require.NoError(t, err)
		require.True(t, zero.Equal(reconstructed))
	})
}

// make128 builds a 16-byte big-endian slice from individual bytes.
func make128(b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 byte) []byte {
	return []byte{b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15}
}

func TestComponentsBytesRoundtrip(t *testing.T) {
	t.Parallel()
	f := bf128.NewField()
	prng := pcg.NewRandomised()

	for range reps {
		x, err := f.Random(prng)
		require.NoError(t, err)

		components := x.ComponentsBytes()
		require.Len(t, components, 128)
		for _, c := range components {
			require.Len(t, c, 1)
			require.True(t, c[0] == 0 || c[0] == 1)
		}

		reconstructed, err := f.FromComponentsBytes(components)
		require.NoError(t, err)
		require.True(t, x.Equal(reconstructed))
	}
}

func TestSelectSemantics(t *testing.T) {
	t.Parallel()

	f := bf128.NewField()
	x, err := f.FromBytes(make128(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1))
	require.NoError(t, err)
	y, err := f.FromBytes(make128(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2))
	require.NoError(t, err)

	require.True(t, f.Select(0, x, y).Equal(x))
	require.True(t, f.Select(1, x, y).Equal(y))
}

func TestEqualNilSemantics(t *testing.T) {
	t.Parallel()

	f := bf128.NewField()
	x, err := f.FromBytes(make128(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5))
	require.NoError(t, err)

	require.False(t, x.Equal(nil))
	require.False(t, ((*bf128.FieldElement)(nil)).Equal(x))
	require.True(t, ((*bf128.FieldElement)(nil)).Equal(nil))
}

func TestBytesRoundtrip(t *testing.T) {
	t.Parallel()

	f := bf128.NewField()
	prng := pcg.NewRandomised()

	for range reps {
		x, err := f.Random(prng)
		require.NoError(t, err)

		roundtrip, err := f.FromBytes(x.Bytes())
		require.NoError(t, err)
		require.True(t, x.Equal(roundtrip))
	}
}

func TestFromBytesInvalidLength(t *testing.T) {
	t.Parallel()

	_, err := bf128.NewField().FromBytes(make([]byte, bf128.FieldElementSize-1))
	require.ErrorIs(t, err, bf128.ErrInvalidLength)
}

func TestFromComponentsBytesInvalidInput(t *testing.T) {
	t.Parallel()

	f := bf128.NewField()

	_, err := f.FromComponentsBytes(make([][]byte, 127))
	require.ErrorIs(t, err, bf128.ErrInvalidLength)

	components := make([][]byte, 128)
	for i := range components {
		components[i] = []byte{0}
	}
	components[7] = []byte{0, 1}
	_, err = f.FromComponentsBytes(components)
	require.ErrorIs(t, err, bf128.ErrInvalidLength)

	components[7] = []byte{2}
	_, err = f.FromComponentsBytes(components)
	require.ErrorIs(t, err, bf128.ErrInvalidLength)
}
