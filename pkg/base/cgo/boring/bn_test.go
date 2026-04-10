//go:build !purego && !nobignum

package boring_test

import (
	"math/big"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/cgo/boring"
)

func TestBigNumSetBytesEmptyResetsToZero(t *testing.T) {
	bn, err := boring.NewBigNum().SetBytes([]byte{0xde, 0xad, 0xbe, 0xef})
	require.NoError(t, err)

	_, err = bn.SetBytes(nil)
	require.NoError(t, err)

	out, err := bn.Bytes()
	require.NoError(t, err)
	require.Zero(t, len(out))
}

func TestBigNumSetBytesReuseRoundtrip(t *testing.T) {
	testCases := [][]byte{
		nil,
		{},
		{0},
		{1},
		{0, 1},
		{0xde, 0xad, 0xbe, 0xef},
		{0xff, 0x00, 0x01, 0x02, 0x03, 0x04},
	}

	bn := boring.NewBigNum()
	for _, tc := range testCases {
		_, err := bn.SetBytes(tc)
		require.NoError(t, err)

		out, err := bn.Bytes()
		require.NoError(t, err)
		require.Zero(t, new(big.Int).SetBytes(tc).Cmp(new(big.Int).SetBytes(out)))
	}
}

func TestBigNumFinalizerAfterGC(t *testing.T) {
	for i := 0; i < 256; i++ {
		bn, err := boring.NewBigNum().SetBytes([]byte{byte(i), byte(i >> 1), 0xaa, 0x55})
		require.NoError(t, err)

		_, err = bn.SetBytes(nil)
		require.NoError(t, err)

		_, err = bn.SetBytes([]byte{byte(i + 1)})
		require.NoError(t, err)
	}

	runtime.GC()
	runtime.GC()
}
