package fuzz

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base/algebra"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/k256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/pallas"
	"github.com/copperexchange/krypton-primitives/pkg/base/errs"
)

var allCurves = []curves.Curve{
	edwards25519.NewCurve(),
	k256.NewCurve(),
	p256.NewCurve(),
	pallas.NewCurve(),
}

func Fuzz_Test_ScalarRandom(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, randSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randSeed))
		curve.ScalarField().Random(prng)
	})
}

func Fuzz_Test_ScalarHash(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, b []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		curve.ScalarField().Hash(b)
	})
}

func Fuzz_Test_ScalarSquare(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		v.Square()
	})
}

func Fuzz_Test_ScalarCube(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		v.Cube()
	})
}

func Fuzz_Test_ScalarDouble(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		v.Double()
	})
}

func Fuzz_Test_ScalarNeg(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		require.Equal(t, algebra.Equal, v.Neg().Neg().Cmp(v))
	})
}

func Fuzz_Test_ScalarSqrt(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		_, err := v.Sqrt()
		if err != nil && !errs.IsKnownError(err) {
			require.NoError(t, err)
		}
	})
}

func Fuzz_Test_ScalarAdd(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		v.Add(v)
	})
}

func Fuzz_Test_ScalarSub(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		require.Equal(t, algebra.Equal, v.Sub(v).Cmp(curve.ScalarField().Zero()))
	})
}

func Fuzz_Test_ScalarMul(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		v.Mul(v)
	})
}

func Fuzz_Test_ScalarDiv(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		if v.IsZero() {
			t.Skip()
		}
		v.Div(v)
	})
}

func Fuzz_Test_ScalarExp(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, i uint64, e uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		exp := curve.ScalarField().New(e)
		v.Exp(exp)
	})
}

func Fuzz_Test_PointRandom(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, randSeed int64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		prng := rand.New(rand.NewSource(randSeed))
		curve.Random(prng)
	})
}

func Fuzz_Test_PointHash(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p, err := curve.Hash(h)
		require.NoError(t, err)
		pp, err := curve.Hash(h)
		require.NoError(t, err)
		require.True(t, len(p.ToAffineCompressed()) > 0)
		require.True(t, len(p.ToAffineUncompressed()) > 0)
		pp, err = pp.FromAffineCompressed(p.ToAffineCompressed())
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
		p, err := curve.Hash(h)
		require.NoError(t, err)
		p.Double()
	})
}

func Fuzz_Test_PointNeg(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p, err := curve.BaseField().Hash(h)
		require.NoError(t, err)
		p.Neg()
	})
}

func Fuzz_Test_PointAdd(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p, err := curve.Hash(h)
		require.NoError(t, err)
		p.Add(p)
	})
}

func Fuzz_Test_PointSub(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		p, err := curve.Hash(h)
		require.NoError(t, err)
		p.Sub(p)
	})
}

func Fuzz_Test_PointMul(f *testing.F) {
	f.Fuzz(func(t *testing.T, curveIndex uint, hashIndex uint, h []byte, i uint64) {
		curve := allCurves[int(curveIndex)%len(allCurves)]
		v := curve.ScalarField().New(i)
		p, err := curve.Hash(h)
		require.NoError(t, err)
		p.Mul(v)
	})
}
