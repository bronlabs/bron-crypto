package safecast_test

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/utils/safecast"
)

func TestToUint8(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  int64
		out uint8
		err error
	}{
		{math.MaxInt64, math.MaxUint8, safecast.ErrOutOfBounds},
		{0, 0, nil},
		{math.MaxUint8, math.MaxUint8, nil},
		{math.MinInt64, 0, safecast.ErrOutOfBounds},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ToUint8 overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToUint8(tc.in)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.out, out)
		})
	}
}

func TestToInt(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  int64
		out uint
		err error
	}{
		{0, 0, nil},
		{math.MaxInt, math.MaxInt, nil},
		{math.MinInt64, 0, safecast.ErrOutOfBounds},
	}

	for _, tc := range testCases {
		t.Parallel()
		t.Run(fmt.Sprintf("ToInt overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToInt(tc.in)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.out, out)
		})
	}

	// t.Run(fmt.Sprintf("ToInt overflow"), func(t *testing.T) {
	// 	t.Parallel()
	// 	out, err := ToInt(math.MaxUint64)
	// 	require.Equal(t, ErrOutOfBounds, err)
	// 	require.Equal(t, math.MaxInt, out)
	// })
}

func TestToUInt(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  int64
		out uint
		err error
	}{
		{math.MaxInt, math.MaxUint8, safecast.ErrOutOfBounds},
		{0, 0, nil},
		{math.MaxUint8, math.MaxUint8, nil},
		{math.MinInt64, 0, safecast.ErrOutOfBounds},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ToUintUint overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToUint(tc.in)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.out, out)
		})
	}

	// Need to test if 64bit vs 32 bit.
	// t.Run(fmt.Sprintf("ToUintUint overflow"), func(t *testing.T) {
	// 	out, err := ToUint(math.MaxInt + 1)
	// 	require.Equal(t, ErrOutOfBounds, err)
	// 	require.Equal(t, math.MaxUint, out)
	// })
}

func TestToUint32(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  int64
		out uint8
		err error
	}{
		{math.MaxInt64, math.MaxUint8, safecast.ErrOutOfBounds},
		{0, 0, nil},
		{math.MaxUint8, math.MaxUint8, nil},
		{math.MinInt64, 0, safecast.ErrOutOfBounds},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ToUint32 overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToUint8(tc.in)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.out, out)
		})
	}
}

func TestMust(t *testing.T) {
	t.Parallel()
	t.Run("out of bounds, panic", func(t *testing.T) {
		t.Parallel()
		require.Panics(t,
			func() { safecast.Must(safecast.ToUint8(uint64(math.MaxUint64))) })
	})

	t.Run("in bounds, no panic", func(t *testing.T) {
		t.Parallel()
		require.NotPanics(t,
			func() { safecast.Must(safecast.ToUint8(uint64(math.MaxInt8))) })
	})
}
