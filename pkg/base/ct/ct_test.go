package ct_test

// import (
// 	"bytes"
// 	"encoding/binary"
// 	"math/rand"
// 	"testing"

// 	"github.com/stretchr/testify/require"

// 	"github.com/bronlabs/bron-crypto/pkg/base/ct"
// )

// const ctTrue = uint64(1)
// const ctFalse = uint64(0)
// const ctLess = int64(-1)
// const ctEqual = int64(0)
// const ctGreater = int64(1)

// const reps = 128

// func Test_ConstantTimeEq(t *testing.T) {
// 	t.Parallel()
// 	// Try all combinations of x and y in [0, 20].
// 	for x := uint64(0); x < 20; x++ {
// 		for y := uint64(0); y < 20; y++ {
// 			eq := x == y
// 			ctEq := ct.Equal(x, y)
// 			require.Equal(t, eq, ctEq == ctTrue)
// 		}
// 	}
// 	// Try reps random samples of x and y.
// 	for i := 0; i < reps; i++ {
// 		x, y := rand.Uint64(), rand.Uint64()
// 		eq := x == y
// 		ctEq := ct.Equal(x, y)
// 		require.Equal(t, eq, ctEq == ctTrue)
// 	}
// }

// func Test_ConstantTimeGreater(t *testing.T) {
// 	t.Parallel()
// 	// Try all combinations of x and y in [0, 20].
// 	for x := uint64(0); x < 20; x++ {
// 		for y := uint64(0); y < 20; y++ {
// 			gt := x > y
// 			gtCt := ct.Greater(x, y)
// 			require.Equal(t, gt, gtCt == ctTrue)
// 		}
// 	}
// 	// Try reps random samples of x and y.
// 	for i := 0; i < reps; i++ {
// 		x, y := rand.Uint64(), rand.Uint64()
// 		gt := x > y
// 		ctGt := ct.Greater(x, y)
// 		require.Equal(t, gt, ctGt == ctTrue)
// 	}
// }

// func Test_ConstantTimeGreaterOrEqual(t *testing.T) {
// 	t.Parallel()
// 	// Try all combinations of x and y in [0, 20].
// 	for x := uint64(0); x < 20; x++ {
// 		for y := uint64(0); y < 20; y++ {
// 			gtEq := x >= y
// 			gtEqCt := ct.GreaterOrEqual(x, y)
// 			require.Equal(t, gtEq, gtEqCt == ctTrue)
// 		}
// 	}

// 	// Try reps random samples of x and y.
// 	for i := 0; i < reps; i++ {
// 		x, y := rand.Uint64(), rand.Uint64()
// 		gtEq := x >= y
// 		gtEqCt := ct.GreaterOrEqual(x, y)
// 		require.Equal(t, gtEq, gtEqCt == ctTrue)
// 	}
// }

// func Test_ConstantTimeLess(t *testing.T) {
// 	t.Parallel()
// 	// Try all combinations of x and y in [0, 20].
// 	for x := uint64(0); x < 20; x++ {
// 		for y := uint64(0); y < 20; y++ {
// 			lt := x < y
// 			ltCt := ct.Less(x, y)
// 			require.Equal(t, lt, ltCt == ctTrue)
// 		}
// 	}
// 	// Try reps random samples of x and y.
// 	for i := 0; i < reps; i++ {
// 		x, y := rand.Uint64(), rand.Uint64()
// 		lt := x < y
// 		ltCt := ct.Less(x, y)
// 		require.Equal(t, lt, ltCt == ctTrue)
// 	}
// }

// func Test_ConstantTimeLessOrEqual(t *testing.T) {
// 	t.Parallel()
// 	// Try all combinations of x and y in [0, 20].
// 	for x := uint64(0); x < 20; x++ {
// 		for y := uint64(0); y < 20; y++ {
// 			ltEq := x <= y
// 			ltEqCt := ct.LessOrEqual(x, y)
// 			require.Equal(t, ltEq, ltEqCt == ctTrue)
// 		}
// 	}

// 	// Try 128 random samples of x and y.
// 	for i := 0; i < reps; i++ {
// 		x, y := rand.Uint64(), rand.Uint64()
// 		ltEq := x <= y
// 		ltEqCt := ct.LessOrEqual(x, y)
// 		require.Equal(t, ltEq, ltEqCt == ctTrue)
// 	}
// }

// func Test_ConstantTimeSliceGreater(t *testing.T) {
// 	t.Parallel()
// 	for x := 0xf0; x < 0x800; x++ {
// 		for y := 0xf0; y < 0x800; y++ {
// 			xBytes := binary.LittleEndian.AppendUint16([]byte{}, uint16(x))
// 			yBytes := binary.LittleEndian.AppendUint16([]byte{}, uint16(y))
// 			gt := x > y
// 			gtCt := ct.SliceGreaterLE(xBytes, yBytes)
// 			require.Equal(t, gt, gtCt == ctTrue)
// 		}
// 	}
// 	// Try reps random samples of x and y.
// 	for i := 0; i < reps; i++ {
// 		x, y := rand.Uint64(), rand.Uint64()
// 		xBytes := binary.LittleEndian.AppendUint64([]byte{}, x)
// 		yBytes := binary.LittleEndian.AppendUint64([]byte{}, y)
// 		gt := x > y
// 		gtCt := ct.SliceGreaterLE(xBytes, yBytes)
// 		require.Equal(t, gt, gtCt == ctTrue)
// 	}
// }

// func Test_ConstantTimeSliceCmp(t *testing.T) {
// 	t.Parallel()
// 	for x := 0xf0; x < 0x800; x++ {
// 		for y := 0xf0; y < 0x800; y++ {
// 			xBytes := binary.LittleEndian.AppendUint16([]byte{}, uint16(x))
// 			yBytes := binary.LittleEndian.AppendUint16([]byte{}, uint16(y))
// 			gt := x > y
// 			eq := x == y
// 			lt := x < y
// 			orderCt := ct.SliceCmpLE(xBytes, yBytes)
// 			require.Equal(t, gt, orderCt == ctGreater)
// 			require.Equal(t, eq, orderCt == ctEqual)
// 			require.Equal(t, lt, orderCt == ctLess)
// 		}
// 	}
// 	// Try reps random samples of x and y.
// 	for i := 0; i < reps; i++ {
// 		x, y := rand.Uint64(), rand.Uint64()
// 		xBytes := binary.LittleEndian.AppendUint64([]byte{}, x)
// 		yBytes := binary.LittleEndian.AppendUint64([]byte{}, y)
// 		gt := x > y
// 		eq := x == y
// 		lt := x < y
// 		orderCt := ct.SliceCmpLE(xBytes, yBytes)
// 		require.Equal(t, gt, orderCt == ctGreater)
// 		require.Equal(t, eq, orderCt == ctEqual)
// 		require.Equal(t, lt, orderCt == ctLess)
// 	}
// }

// func TestConstantTimeIsAllEqualNZero(t *testing.T) {
// 	t.Parallel()
// 	zero := make([]byte, 32)
// 	require.Equal(t, ctTrue, ct.SliceEachEqual(zero, 0))
// 	require.Equal(t, ctFalse, ct.SliceEachEqual([]byte("something"), 0))
// 	require.Equal(t, ctTrue, ct.SliceIsZero(zero))
// 	require.Equal(t, ctFalse, ct.SliceIsZero([]byte("something")))

// 	nonZero := bytes.ReplaceAll(make([]byte, 32), []byte{0}, []byte{0xF3})
// 	require.Equal(t, ctTrue, ct.SliceEachEqual(nonZero[:], 0xF3))
// 	require.Equal(t, ctFalse, ct.SliceEachEqual(nonZero[:], 0))
// 	require.Equal(t, ctFalse, ct.SliceIsZero(nonZero))
// }
