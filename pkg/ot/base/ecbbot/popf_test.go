package ecbbot_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

func Test_PopfHappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		popfHappyHapy(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		popfHappyHapy(t, p256.NewCurve())
	})
}

func popfHappyHapy[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](tb testing.TB, curve algebra.PrimeGroup[GE, SE]) {
	prng := crand.Reader
	tag0 := []byte("tag0")
	tag1 := []byte("tag1")

	f, err := ecbbot.NewPopf(curve, tag0, tag1)
	require.NoError(tb, err)

	x := byte(0)
	y, err := curve.Random(prng)
	require.NoError(tb, err)
	s0, s1, err := f.Program(x, y, prng)
	require.NoError(tb, err)
	y2, err := f.Eval(s0, s1, x)
	require.NoError(tb, err)
	require.True(tb, y.Equal(y2))
	y3, err := f.Eval(s0, s1, 1-x)
	require.NoError(tb, err)
	require.False(tb, y.Equal(y3))

	x = byte(1)
	y, err = curve.Random(prng)
	require.NoError(tb, err)
	s0, s1, err = f.Program(x, y, prng)
	require.NoError(tb, err)
	y2, err = f.Eval(s0, s1, x)
	require.NoError(tb, err)
	require.True(tb, y.Equal(y2))

	y3, err = f.Eval(s0, s1, 1-x)
	require.NoError(tb, err)
	require.False(tb, y.Equal(y3))
}
