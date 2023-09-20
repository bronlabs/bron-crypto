package curves_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/copperexchange/krypton/pkg/base/curves"
	"github.com/copperexchange/krypton/pkg/base/curves/edwards25519"
	"github.com/copperexchange/krypton/pkg/base/curves/k256"
	"github.com/copperexchange/krypton/pkg/base/curves/p256"
	"github.com/copperexchange/krypton/pkg/base/curves/pallas"
)

func Test_ScalarCmp(t *testing.T) {
	t.Parallel()

	supportedCurves := []curves.Curve{
		k256.New(),
		p256.New(),
		edwards25519.New(),
		pallas.New(),
	}

	for _, c := range supportedCurves {
		curve := c
		t.Run(fmt.Sprintf("%s scalar comparison", curve.Name()), func(t *testing.T) {
			t.Parallel()

			s := curve.Scalar().New(10)
			m := curve.Scalar().New(100)
			l := curve.Scalar().New(1000)

			_, eq, _ := s.Nat().Cmp(s.Nat())
			require.Equal(t, 1, int(eq))
			require.Zero(t, s.Cmp(s))

			_, eq, _ = m.Nat().Cmp(m.Nat())
			require.Equal(t, 1, int(eq))
			require.Zero(t, m.Cmp(m))

			_, eq, _ = l.Nat().Cmp(l.Nat())
			require.Equal(t, 1, int(eq))
			require.Zero(t, l.Cmp(l))

			_, _, le := s.Nat().Cmp(m.Nat())
			require.Equal(t, 1, int(le))
			require.Equal(t, -1, s.Cmp(m))

			_, _, le = s.Nat().Cmp(l.Nat())
			require.Equal(t, 1, int(le))
			require.Equal(t, -1, s.Cmp(l))

			_, _, le = m.Nat().Cmp(l.Nat())
			require.Equal(t, 1, int(le))
			require.Equal(t, -1, m.Cmp(l))

			gt, _, _ := l.Nat().Cmp(m.Nat())
			require.Equal(t, 1, int(gt))
			require.Equal(t, 1, l.Cmp(m))

			gt, _, _ = l.Nat().Cmp(s.Nat())
			require.Equal(t, 1, int(gt))
			require.Equal(t, 1, l.Cmp(s))

			gt, _, _ = m.Nat().Cmp(s.Nat())
			require.Equal(t, 1, int(gt))
			require.Equal(t, 1, m.Cmp(s))
		})
	}
}
