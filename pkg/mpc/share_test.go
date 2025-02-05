package mpc_test

import (
	crand "crypto/rand"
	"math/bits"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/krypton-primitives/pkg/mpc"
)

func Test_BinaryXor(t *testing.T) {
	t.Parallel()

	prng := crand.Reader

	secretA := randomUint64(t, prng)
	secretB := randomUint64(t, prng)
	expected := secretA ^ secretB

	dealer := mpc.NewDealer()
	sharesA := dealer.Share(secretA, prng)
	sharesB := dealer.Share(secretB, prng)
	sharesC := []*mpc.BinaryShare{
		sharesA[1].Xor(sharesB[1]),
		sharesA[2].Xor(sharesB[2]),
		sharesA[3].Xor(sharesB[3]),
	}

	actual, err := dealer.Open(sharesC...)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func Test_BinaryShl(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	secretA := randomUint64(t, prng)
	shift := int(randomUint64(t, prng) % 64)
	expected := secretA << shift

	dealer := mpc.NewDealer()
	sharesA := dealer.Share(secretA, prng)
	sharesC := []*mpc.BinaryShare{
		sharesA[1].Shl(shift),
		sharesA[2].Shl(shift),
		sharesA[3].Shl(shift),
	}

	actual, err := dealer.Open(sharesC...)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func Test_BinaryShr(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	secretA := randomUint64(t, prng)
	shift := int(randomUint64(t, prng) % 64)
	expected := secretA >> shift

	dealer := mpc.NewDealer()
	sharesA := dealer.Share(secretA, prng)
	sharesC := []*mpc.BinaryShare{
		sharesA[1].Shr(shift),
		sharesA[2].Shr(shift),
		sharesA[3].Shr(shift),
	}

	actual, err := dealer.Open(sharesC...)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func Test_BinaryRol(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	secretA := randomUint64(t, prng)
	shift := int(randomUint64(t, prng) % 64)
	expected := bits.RotateLeft64(secretA, shift)

	dealer := mpc.NewDealer()
	sharesA := dealer.Share(secretA, prng)
	sharesC := []*mpc.BinaryShare{
		sharesA[1].Rol(shift),
		sharesA[2].Rol(shift),
		sharesA[3].Rol(shift),
	}

	actual, err := dealer.Open(sharesC...)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func Test_BinaryRor(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	secretA := randomUint64(t, prng)
	shift := int(randomUint64(t, prng) % 64)
	expected := bits.RotateLeft64(secretA, -shift)

	dealer := mpc.NewDealer()
	sharesA := dealer.Share(secretA, prng)
	sharesC := []*mpc.BinaryShare{
		sharesA[1].Ror(shift),
		sharesA[2].Ror(shift),
		sharesA[3].Ror(shift),
	}

	actual, err := dealer.Open(sharesC...)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func Test_BinaryXorPlain(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	secretA := randomUint64(t, prng)
	plainB := randomUint64(t, prng)
	expected := secretA ^ plainB

	dealer := mpc.NewDealer()
	sharesA := dealer.Share(secretA, prng)
	sharesC := []*mpc.BinaryShare{
		sharesA[1].XorPlain(plainB),
		sharesA[2].XorPlain(plainB),
		sharesA[3].XorPlain(plainB),
	}

	actual, err := dealer.Open(sharesC...)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func Test_BinaryAndPlain(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	secretA := randomUint64(t, prng)
	plainB := randomUint64(t, prng)
	expected := secretA & plainB

	dealer := mpc.NewDealer()
	sharesA := dealer.Share(secretA, prng)
	sharesC := []*mpc.BinaryShare{
		sharesA[1].AndPlain(plainB),
		sharesA[2].AndPlain(plainB),
		sharesA[3].AndPlain(plainB),
	}

	actual, err := dealer.Open(sharesC...)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func Test_BinaryNot(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	secretA := randomUint64(t, prng)
	expected := ^secretA

	dealer := mpc.NewDealer()
	sharesA := dealer.Share(secretA, prng)
	sharesC := []*mpc.BinaryShare{
		sharesA[1].Not(),
		sharesA[2].Not(),
		sharesA[3].Not(),
	}

	actual, err := dealer.Open(sharesC...)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}
