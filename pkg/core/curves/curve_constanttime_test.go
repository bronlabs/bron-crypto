package curves_test

import (
	crand "crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/knox-primitives/internal"
	"github.com/copperexchange/knox-primitives/pkg/core/bitstring"
	"github.com/copperexchange/knox-primitives/pkg/core/curves"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/edwards25519"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/k256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/p256"
	"github.com/copperexchange/knox-primitives/pkg/core/curves/pallas"
)

func test_MeasureConstantTime_ScalarRandom(curve curves.Curve) {
	internal.RunMeasurement(500, fmt.Sprintf("%s_ScalarRandom", curve.Name()), func(i int) {
	}, func() {
		curve.Scalar().Random(crand.Reader)
	})
}

func test_MeasureConstantTime_ScalarHash(curve curves.Curve) {
	internal.RunMeasurement(500, fmt.Sprintf("%s_ScalarHash", curve.Name()), func(i int) {
	}, func() {
		curve.Scalar().Random(crand.Reader)
	})
}

func test_MeasureConstantTime_ScalarSquare(t *testing.T, curve curves.Curve) {
	t.Helper()
	v := curve.Scalar().New(3)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarSquare", curve.Name()), func(i int) {
		v, err = curve.Scalar().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Square()
	})
}

func test_MeasureConstantTime_ScalarCube(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarCube", curve.Name()), func(i int) {
		v, err = curve.Scalar().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Cube()
	})
}

func test_MeasureConstantTime_ScalarDouble(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarDouble", curve.Name()), func(i int) {
		v, err = curve.Scalar().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Double()
	})
}

func test_MeasureConstantTime_ScalarNeg(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarNeg", curve.Name()), func(i int) {
		v, err = curve.Scalar().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Neg()
	})
}

func test_MeasureConstantTime_ScalarInvert(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarNeg", curve.Name()), func(i int) {
		v, err = curve.Scalar().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Invert()
	})
}

func test_MeasureConstantTime_ScalarSqrt(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarNeg", curve.Name()), func(i int) {
		v, err = curve.Scalar().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Sqrt()
	})
}

func test_MeasureConstantTime_ScalarAdd(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_Add", curve.Name()), func(i int) {
		v, err = curve.Scalar().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Add(v)
	})
}

func test_MeasureConstantTime_ScalarSub(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_Sub", curve.Name()), func(i int) {
		v, err = curve.Scalar().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Sub(v)
	})
}

func test_MeasureConstantTime_ScalarMul(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_Mul", curve.Name()), func(i int) {
		v, err = curve.Scalar().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Mul(v)
	})
}

func test_MeasureConstantTime_ScalarDiv(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarDiv", curve.Name()), func(i int) {
		v = curve.Scalar().New(uint64(i + 1))
		require.NoError(t, err)
	}, func() {
		v.Div(v)
	})
}

func test_MeasureConstantTime_ScalarExp(t *testing.T, curve curves.Curve) {

	t.Helper()
	c := curve.Scalar().New(9)
	v := curve.Scalar().New(1)
	var err error
	internal.RunMeasurement(20, fmt.Sprintf("%s_ScalarExp", curve.Name()), func(i int) {
		c = curve.Scalar().New(9)
		v, err = curve.Scalar().SetBytes(bitstring.ReverseBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i)))
		require.NoError(t, err)
	}, func() {
		c.Exp(v)
	})
}

func test_MeasureConstantTime_PointRandom(curve curves.Curve) {

	internal.RunMeasurement(500, fmt.Sprintf("%s_PointRandom", curve.Name()), func(i int) {
	}, func() {
		curve.Point().Random(crand.Reader)
	})
}

func test_MeasureConstantTime_PointHash(curve curves.Curve) {

	var b []byte
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointHash", curve.Name()), func(i int) {
		b = internal.GetBigEndianBytesWithLowestBitsSet(32, i)
	}, func() {
		curve.Point().Hash(b[:])
	})
}

func test_MeasureConstantTime_PointDouble(curve curves.Curve) {

	p := curve.Point().Identity()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointDouble", curve.Name()), func(i int) {
		g := curve.Point().Generator()
		p = g.Mul(curve.Scalar().New(uint64(i)))
	}, func() {
		p.Double()
	})
}

func test_MeasureConstantTime_PointNeg(curve curves.Curve) {

	p := curve.Point().Identity()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointNeg", curve.Name()), func(i int) {
		g := curve.Point().Generator()
		p = g.Mul(curve.Scalar().New(uint64(i)))
	}, func() {
		p.Neg()
	})
}

func test_MeasureConstantTime_PointAdd(curve curves.Curve) {

	p := curve.Point().Identity()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointAdd", curve.Name()), func(i int) {
		g := curve.Point().Generator()
		p = g.Mul(curve.Scalar().New(uint64(i)))
	}, func() {
		p.Add(p)
	})
}

func test_MeasureConstantTime_PointSub(curve curves.Curve) {

	p := curve.Point().Identity()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointSub", curve.Name()), func(i int) {
		g := curve.Point().Generator()
		p = g.Mul(curve.Scalar().New(uint64(i)))
	}, func() {
		p.Sub(p)
	})
}

func test_MeasureConstantTime_PointMul(curve curves.Curve) {

	p := curve.Point().Identity()
	sc := curve.Scalar()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointMul", curve.Name()), func(i int) {
		g := curve.Point().Generator()
		p = g.Mul(curve.Scalar().New(uint64(i)))
		sc = curve.Scalar().New(uint64(i))
	}, func() {
		p.Mul(sc)
	})
}

var allCurves = []curves.Curve{
	edwards25519.New(),
	k256.New(),
	p256.New(),
	pallas.New(),
}

func Test_MeasureConstantTime_ScalarRandom(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarRandom(curve)
		})
	}
}

func Test_MeasureConstantTime_ScalarHash(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}

	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarHash(curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarSquare(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarSquare(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarCube(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarCube(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarDouble(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarDouble(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarNeg(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarNeg(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarInvert(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarInvert(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarSqrt(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarSqrt(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarAdd(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarAdd(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarSub(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarSub(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarMul(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarMul(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarDiv(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarDiv(t, curve)
		})
	}
}
func Test_MeasureConstantTime_ScalarExp(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_ScalarExp(t, curve)
		})
	}
}
func Test_MeasureConstantTime_PointRandom(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_PointRandom(curve)
		})
	}
}
func Test_MeasureConstantTime_PointHash(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_PointHash(curve)
		})
	}
}
func Test_MeasureConstantTime_PointDouble(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_PointDouble(curve)
		})
	}
}
func Test_MeasureConstantTime_PointNeg(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_PointNeg(curve)
		})
	}
}
func Test_MeasureConstantTime_PointAdd(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_PointAdd(curve)
		})
	}
}
func Test_MeasureConstantTime_PointSub(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_PointSub(curve)
		})
	}
}
func Test_MeasureConstantTime_PointMul(t *testing.T) {
	if os.Getenv("EXEC_TIME_TEST") == "" {
		t.Skip("Skipping test because EXEC_TIME_TEST is not set")
	}
	for _, curve := range allCurves {
		t.Run(curve.Name(), func(t *testing.T) {
			test_MeasureConstantTime_PointMul(curve)
		})
	}
}
