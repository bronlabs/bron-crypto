package curves_test

import (
	crand "crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/internal"
	"github.com/copperexchange/krypton-primitives/pkg/base/bitstring"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
)

func test_MeasureConstantTime_ScalarRandom(curve curves.Curve) {
	internal.RunMeasurement(500, fmt.Sprintf("%s_ScalarRandom", curve.Name()), func(i int) {
	}, func() {
		curve.ScalarField().Random(crand.Reader)
	})
}

func test_MeasureConstantTime_ScalarHash(curve curves.Curve) {
	internal.RunMeasurement(500, fmt.Sprintf("%s_ScalarHash", curve.Name()), func(i int) {
	}, func() {
		curve.ScalarField().Random(crand.Reader)
	})
}

func test_MeasureConstantTime_ScalarSquare(t *testing.T, curve curves.Curve) {
	t.Helper()
	v := curve.ScalarField().New(3)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarSquare", curve.Name()), func(i int) {
		v, err = curve.ScalarField().Element().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Square()
	})
}

func test_MeasureConstantTime_ScalarCube(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarCube", curve.Name()), func(i int) {
		v, err = curve.ScalarField().Element().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Cube()
	})
}

func test_MeasureConstantTime_ScalarDouble(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarDouble", curve.Name()), func(i int) {
		v, err = curve.ScalarField().Element().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Double()
	})
}

func test_MeasureConstantTime_ScalarNeg(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarNeg", curve.Name()), func(i int) {
		v, err = curve.ScalarField().Element().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Neg()
	})
}

func test_MeasureConstantTime_ScalarInvert(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarNeg", curve.Name()), func(i int) {
		v, err = curve.ScalarField().Element().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.MultiplicativeInverse()
	})
}

func test_MeasureConstantTime_ScalarSqrt(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarNeg", curve.Name()), func(i int) {
		v, err = curve.ScalarField().Element().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Sqrt()
	})
}

func test_MeasureConstantTime_ScalarAdd(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_Add", curve.Name()), func(i int) {
		v, err = curve.ScalarField().Element().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Add(v)
	})
}

func test_MeasureConstantTime_ScalarSub(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_Sub", curve.Name()), func(i int) {
		v, err = curve.ScalarField().Element().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Sub(v)
	})
}

func test_MeasureConstantTime_ScalarMul(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_Mul", curve.Name()), func(i int) {
		v, err = curve.ScalarField().Element().SetBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i))
		require.NoError(t, err)
	}, func() {
		v.Mul(v)
	})
}

func test_MeasureConstantTime_ScalarDiv(t *testing.T, curve curves.Curve) {

	t.Helper()
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(32*8, fmt.Sprintf("%s_ScalarDiv", curve.Name()), func(i int) {
		v = curve.ScalarField().New(uint64(i + 1))
		require.NoError(t, err)
	}, func() {
		v.Div(v)
	})
}

func test_MeasureConstantTime_ScalarExp(t *testing.T, curve curves.Curve) {

	t.Helper()
	c := curve.ScalarField().New(9)
	v := curve.ScalarField().New(1)
	var err error
	internal.RunMeasurement(20, fmt.Sprintf("%s_ScalarExp", curve.Name()), func(i int) {
		c = curve.ScalarField().New(9)
		v, err = curve.ScalarField().Element().SetBytes(bitstring.ReverseBytes(internal.GetBigEndianBytesWithLowestBitsSet(32, i)))
		require.NoError(t, err)
	}, func() {
		c.Exp(v.Nat())
	})
}

func test_MeasureConstantTime_PointRandom(curve curves.Curve) {

	internal.RunMeasurement(500, fmt.Sprintf("%s_PointRandom", curve.Name()), func(i int) {
	}, func() {
		curve.Random(crand.Reader)
	})
}

func test_MeasureConstantTime_PointHash(curve curves.Curve) {

	var b []byte
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointHash", curve.Name()), func(i int) {
		b = internal.GetBigEndianBytesWithLowestBitsSet(32, i)
	}, func() {
		curve.Hash(b[:])
	})
}

func test_MeasureConstantTime_PointDouble(curve curves.Curve) {

	p := curve.AdditiveIdentity()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointDouble", curve.Name()), func(i int) {
		g := curve.Generator()
		p = g.ScalarMul(curve.ScalarField().New(uint64(i)))
	}, func() {
		p.Double()
	})
}

func test_MeasureConstantTime_PointNeg(curve curves.Curve) {

	p := curve.AdditiveIdentity()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointNeg", curve.Name()), func(i int) {
		g := curve.Generator()
		p = g.ScalarMul(curve.ScalarField().New(uint64(i)))
	}, func() {
		p.Neg()
	})
}

func test_MeasureConstantTime_PointAdd(curve curves.Curve) {

	p := curve.AdditiveIdentity()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointAdd", curve.Name()), func(i int) {
		g := curve.Generator()
		p = g.ScalarMul(curve.ScalarField().New(uint64(i)))
	}, func() {
		p.Add(p)
	})
}

func test_MeasureConstantTime_PointSub(curve curves.Curve) {

	p := curve.AdditiveIdentity()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointSub", curve.Name()), func(i int) {
		g := curve.Generator()
		p = g.ScalarMul(curve.ScalarField().New(uint64(i)))
	}, func() {
		p.Sub(p)
	})
}

func test_MeasureConstantTime_PointMul(curve curves.Curve) {

	p := curve.AdditiveIdentity()
	sc := curve.ScalarField().Element()
	internal.RunMeasurement(500, fmt.Sprintf("%s_PointMul", curve.Name()), func(i int) {
		g := curve.Generator()
		p = g.ScalarMul(curve.ScalarField().New(uint64(i)))
		sc = curve.ScalarField().New(uint64(i))
	}, func() {
		p.ScalarMul(sc)
	})
}

var allCurves = []curves.Curve{
	edwards25519.NewCurve(),
	k256.NewCurve(),
	p256.NewCurve(),
	pallas.NewCurve(),
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
