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

func TestComponentsBytesRoundtrip(t *testing.T) {
	t.Parallel()
	f := bf128.NewField()
	prng := pcg.NewRandomised()

	for range reps {
		x, err := f.Random(prng)
		require.NoError(t, err)

		components := x.ComponentsBytes()
		require.Len(t, components, 1)

		reconstructed, err := f.FromComponentsBytes(components)
		require.NoError(t, err)
		require.True(t, x.Equal(reconstructed))
	}
}
