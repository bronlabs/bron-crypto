package curves_test

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton-primitives/pkg/base"
)

func Test_ScalarCmp(t *testing.T) {
	t.Parallel()
	for _, c := range TestCurves {
		curve := c
		t.Run(fmt.Sprintf("%s scalar comparison", curve.Name()), func(t *testing.T) {
			t.Parallel()

			s := curve.ScalarField().New(10)
			m := curve.ScalarField().New(100)
			l := curve.ScalarField().New(1000)

			require.NotEqualValues(t, s.Bytes(), m.Bytes())
			require.NotEqualValues(t, s.Bytes(), l.Bytes())
			require.NotEqualValues(t, m.Bytes(), l.Bytes())

			_, eq, _ := s.Nat().Cmp(s.Nat())
			require.Equal(t, 1, int(eq))
			require.Zero(t, int(s.Cmp(s)))

			_, eq, _ = m.Nat().Cmp(m.Nat())
			require.Equal(t, 1, int(eq))
			require.Zero(t, int(m.Cmp(m)))

			_, eq, _ = l.Nat().Cmp(l.Nat())
			require.Equal(t, 1, int(eq))
			require.Zero(t, int(l.Cmp(l)))

			_, _, le := s.Nat().Cmp(m.Nat())
			require.Equal(t, 1, int(le))
			require.Equal(t, -1, int(s.Cmp(m)))

			_, _, le = s.Nat().Cmp(l.Nat())
			require.Equal(t, 1, int(le))
			require.Equal(t, -1, int(s.Cmp(l)))

			_, _, le = m.Nat().Cmp(l.Nat())
			require.Equal(t, 1, int(le))
			require.Equal(t, -1, int(m.Cmp(l)))

			gt, _, _ := l.Nat().Cmp(m.Nat())
			require.Equal(t, 1, int(gt))
			require.Equal(t, 1, int(l.Cmp(m)))

			gt, _, _ = l.Nat().Cmp(s.Nat())
			require.Equal(t, 1, int(gt))
			require.Equal(t, 1, int(l.Cmp(s)))

			gt, _, _ = m.Nat().Cmp(s.Nat())
			require.Equal(t, 1, int(gt))
			require.Equal(t, 1, int(m.Cmp(s)))
		})
	}
}

func Test_ScalarSetNat_BigEndian(t *testing.T) {
	t.Parallel()
	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(boundedCurve.Name(), func(t *testing.T) {
			t.Parallel()
			oneBigEndian := make([]byte, base.FieldBytes)
			oneBigEndian[len(oneBigEndian)-1] = 0x1 // 0x000000...0001
			oneNat := new(saferith.Nat).SetUint64(1)
			// Check cast from-to Nat
			scalarOne := boundedCurve.ScalarField().Element().SetNat(oneNat)
			require.EqualValues(t, oneBigEndian, scalarOne.Bytes())
			require.EqualValues(t, oneBigEndian, scalarOne.Nat().Bytes())
			// Check if the internal value is treated as a one
			identityTimesGenerator := boundedCurve.ScalarBaseMult(scalarOne)
			require.True(t, identityTimesGenerator.Equal(boundedCurve.Generator()))
			identityTimesIdentity := scalarOne.Mul(scalarOne)
			require.True(t, identityTimesIdentity.IsOne())
		})
	}
}
func Test_ScalarSetBytes_BigEndian(t *testing.T) {
	t.Parallel()
	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(boundedCurve.Name(), func(t *testing.T) {
			t.Parallel()
			oneBigEndian := make([]byte, base.FieldBytes)
			oneBigEndian[len(oneBigEndian)-1] = 0x1 // 0x000000...0001
			// Check cast from-to bytes
			scalarOne, err := boundedCurve.Scalar().SetBytes(oneBigEndian)
			require.NoError(t, err)
			require.EqualValues(t, oneBigEndian, scalarOne.Bytes())
			// Check if the internal value is treated as a one
			identityTimesGenerator := boundedCurve.ScalarBaseMult(scalarOne)
			require.True(t, identityTimesGenerator.Equal(boundedCurve.Generator()))
			identityTimesIdentity := scalarOne.Mul(scalarOne)
			require.True(t, identityTimesIdentity.IsOne())
		})
	}
}

func Test_ScalarSetBytesWide_BigEndian(t *testing.T) {
	t.Parallel()
	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(boundedCurve.Name(), func(t *testing.T) {
			t.Parallel()
			oneBigEndian := make([]byte, base.WideFieldBytes)
			oneBigEndian[len(oneBigEndian)-1] = 0x1 // 0x000000...0001
			// Check cast from-to widebytes
			scalarOne, err := boundedCurve.Scalar().SetBytesWide(oneBigEndian)
			require.NoError(t, err)
			require.EqualValues(t, scalarOne.Bytes(), oneBigEndian[base.FieldBytes:])
			// Check if the internal value is treated as a one
			identityTimesGenerator := boundedCurve.ScalarBaseMult(scalarOne)
			require.True(t, identityTimesGenerator.Equal(boundedCurve.Generator()))
			identityTimesIdentity := scalarOne.Mul(scalarOne)
			require.True(t, identityTimesIdentity.IsOne())
		})
	}
}

func Test_ScalarIncrementDecrement(t *testing.T) {
	t.Parallel()
	for _, curve := range TestCurves {
		boundedCurve := curve
		t.Run(boundedCurve.Name(), func(t *testing.T) {
			t.Parallel()
			sc, err := boundedCurve.ScalarField().Random(crand.Reader)
			require.NoError(t, err)
			initial := sc.Clone()
			sc.Increment()
			require.True(t, sc.Equal(initial.Add(boundedCurve.ScalarField().One())))
			sc.Decrement()
			require.True(t, sc.Equal(initial))
		})
	}
}
