package fuzz

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/curves/k256"
	"github.com/copperexchange/krypton/pkg/base/curves/p256"
	"github.com/copperexchange/krypton/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton/pkg/base/errs"
)

var allCurves = []curves.Curve{
	edwards25519.New(),
	k256.New(),
	p256.New(),
	pallas.New(),
}

func Fuzz_Test_ScalarRandom(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, randSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randSeed))
		curve.Scalar().Random(prng)
	})
}

func Fuzz_Test_ScalarHash(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, b []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		curve.Scalar().Hash(b)
	})
}

func Fuzz_Test_ScalarSquare(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		v.Square()
	})
}

func Fuzz_Test_ScalarCube(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		v.Cube()
	})
}

func Fuzz_Test_ScalarDouble(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		v.Double()
	})
}

func Fuzz_Test_ScalarNeg(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		require.Equal(t, 0, v.Neg().Neg().Cmp(v))
	})
}

func Fuzz_Test_ScalarInvert(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		_, err := v.Invert()
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func Fuzz_Test_ScalarSqrt(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		_, err := v.Sqrt()
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func Fuzz_Test_ScalarAdd(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		v.Add(v)
	})
}

func Fuzz_Test_ScalarSub(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		require.Equal(t, 0, v.Sub(v).Cmp(curve.Scalar().Zero()))
	})
}

func Fuzz_Test_ScalarMul(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		v.Mul(v)
	})
}

func Fuzz_Test_ScalarDiv(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		if v.IsZero() {
			t.Skip()
		}
		v.Div(v)
	})
}

func Fuzz_Test_ScalarExp(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64, e uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		exp := curve.Scalar().New(e)
		v.Exp(exp)
	})
}

func Fuzz_Test_PointRandom(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, randSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randSeed))
		curve.Point().Random(prng)
	})
}

func Fuzz_Test_PointHash(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p := curve.Point().Hash(h)
		pp := curve.Point().Hash(h)
		require.True(t, len(p.ToAffineCompressed()) > 0)
		require.True(t, len(p.ToAffineUncompressed()) > 0)
		pp, err := pp.FromAffineCompressed(p.ToAffineCompressed())
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		require.True(t, p.Equal(pp))
		pp, err = pp.FromAffineUncompressed(p.ToAffineUncompressed())
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
		require.True(t, p.Equal(pp))
	})
}

func Fuzz_Test_PointDouble(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p := curve.Point().Hash(h)
		p.Double()
	})
}

func Fuzz_Test_PointNeg(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p := curve.Point().Hash(h)
		p.Neg()
	})
}

func Fuzz_Test_PointAdd(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p := curve.Point().Hash(h)
		p.Add(p)
	})
}

func Fuzz_Test_PointSub(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p := curve.Point().Hash(h)
		p.Sub(p)
	})
}

func Fuzz_Test_PointMul(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.Scalar().New(i)
		p := curve.Point().Hash(h)
		p.Mul(v)
	})
}
