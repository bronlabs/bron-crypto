package uints_test

import (
	crand "crypto/rand"
	"github.com/bronlabs/bron-crypto/pkg/num/uints"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func Test_U128Add(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	boundInt := new(big.Int)
	boundInt.SetBit(boundInt, 128, 1)

	for range 128 * 1024 {
		xInt, err := crand.Int(prng, boundInt)
		require.NoError(t, err)
		yInt, err := crand.Int(prng, boundInt)
		require.NoError(t, err)
		zInt := new(big.Int).Add(xInt, yInt)
		zInt.Mod(zInt, boundInt)
		var zIntBytes [16]byte
		zInt.FillBytes(zIntBytes[:])

		x, err := uints.NewU128FromBytes(xInt.Bytes())
		require.NoError(t, err)
		y, err := uints.NewU128FromBytes(yInt.Bytes())
		require.NoError(t, err)
		z := x.Add(y)

		require.Equal(t, zIntBytes, z.Bytes())
	}
}

func Test_U128Sub(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	boundInt := new(big.Int)
	boundInt.SetBit(boundInt, 128, 1)

	for range 128 * 1024 {
		xInt, err := crand.Int(prng, boundInt)
		require.NoError(t, err)
		yInt, err := crand.Int(prng, boundInt)
		require.NoError(t, err)
		zInt := new(big.Int).Sub(xInt, yInt)
		zInt.Add(zInt, boundInt)
		zInt.Mod(zInt, boundInt)
		var zIntBytes [16]byte
		zInt.FillBytes(zIntBytes[:])

		x, err := uints.NewU128FromBytes(xInt.Bytes())
		require.NoError(t, err)
		y, err := uints.NewU128FromBytes(yInt.Bytes())
		require.NoError(t, err)
		z := x.Sub(y)

		require.Equal(t, zIntBytes, z.Bytes())
	}
}

func Test_U128Neg(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	boundInt := new(big.Int)
	boundInt.SetBit(boundInt, 128, 1)

	for range 128 * 1024 {
		xInt, err := crand.Int(prng, boundInt)
		require.NoError(t, err)
		zInt := new(big.Int).Neg(xInt)
		zInt.Add(zInt, boundInt)
		zInt.Mod(zInt, boundInt)
		var zIntBytes [16]byte
		zInt.FillBytes(zIntBytes[:])

		x, err := uints.NewU128FromBytes(xInt.Bytes())
		require.NoError(t, err)
		z := x.Neg()

		require.Equal(t, zIntBytes, z.Bytes())
	}
}

func Test_U128Mul(t *testing.T) {
	prng := crand.Reader
	boundInt := new(big.Int)
	boundInt.SetBit(boundInt, 128, 1)

	for range 128 * 1024 {
		xInt, err := crand.Int(prng, boundInt)
		require.NoError(t, err)
		yInt, err := crand.Int(prng, boundInt)
		require.NoError(t, err)
		zInt := new(big.Int).Mul(xInt, yInt)
		zInt.Mod(zInt, boundInt)
		var zIntBytes [16]byte
		zInt.FillBytes(zIntBytes[:])

		x, err := uints.NewU128FromBytes(xInt.Bytes())
		require.NoError(t, err)
		y, err := uints.NewU128FromBytes(yInt.Bytes())
		require.NoError(t, err)
		z := x.Mul(y)

		require.Equal(t, zIntBytes, z.Bytes())
	}
}

func Test_U128Square(t *testing.T) {
	prng := crand.Reader
	boundInt := new(big.Int)
	boundInt.SetBit(boundInt, 128, 1)

	for range 128 * 1024 {
		xInt, err := crand.Int(prng, boundInt)
		require.NoError(t, err)
		zInt := new(big.Int).Mul(xInt, xInt)
		zInt.Mod(zInt, boundInt)
		var zIntBytes [16]byte
		zInt.FillBytes(zIntBytes[:])

		x, err := uints.NewU128FromBytes(xInt.Bytes())
		require.NoError(t, err)
		z := x.Square()

		require.Equal(t, zIntBytes, z.Bytes())
	}
}
