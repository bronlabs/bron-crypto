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

func TestToUint16(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  int64
		out uint16
		err error
	}{
		{math.MaxInt64, math.MaxUint16, safecast.ErrOutOfBounds},
		{0, 0, nil},
		{math.MaxUint8, math.MaxUint8, nil},
		{math.MinInt64, 0, safecast.ErrOutOfBounds},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ToUint16 overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToUint16(tc.in)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.out, out)
		})
	}
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

func TestToUint64(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  uint64
		out uint64
		err error
	}{
		{math.MaxInt64, math.MaxInt64, nil},
		{0, 0, nil},
		{math.MaxUint8, math.MaxUint8, nil},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ToUint64 overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToUint64(tc.in)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.out, out)
		})
	}

	t.Run("ToUint64 underflow", func(t *testing.T) {
		t.Parallel()
		out, err := safecast.ToUint64(math.MinInt64)
		require.Equal(t, safecast.ErrOutOfBounds, err)
		require.Equal(t, uint64(0x8000000000000000), out)
	})
}

func TestToUInt(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  int64
		out uint
		err error
	}{
		{math.MaxInt, math.MaxInt, nil},
		{0, 0, nil},
		{math.MinInt64, 0x8000000000000000, safecast.ErrOutOfBounds},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ToUintUint overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToUint(tc.in)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.out, out)
		})
	}
}

func TestToInt32(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  int64
		out int32
		err error
	}{
		{0, 0, nil},
		{math.MaxInt64, -1, safecast.ErrOutOfBounds},
		{math.MinInt64, 0, safecast.ErrOutOfBounds},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ToInt32 overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToInt32(tc.in)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.out, out)
		})
	}
}

func TestToInt64(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  int64
		out int64
		err error
	}{
		{0, 0, nil},
		{math.MaxInt, math.MaxInt, nil},
		{math.MinInt64, math.MinInt, safecast.ErrOutOfBounds},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ToInt64 overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToInt64(tc.in)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.out, out)
		})
	}
}

func TestToInt(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		in  int64
		out int
		err error
	}{
		{0, 0, nil},
		{math.MaxInt, math.MaxInt, nil},
		{math.MinInt64, math.MinInt, safecast.ErrOutOfBounds},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("ToInt overflow in %d out %d err %#v", tc.in, tc.out, tc.err), func(t *testing.T) {
			t.Parallel()
			out, err := safecast.ToInt(tc.in)
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
