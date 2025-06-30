package ecbbot_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

func Test_PopfHappyPath(t *testing.T) {
	t.Parallel()

	prng := crand.Reader
	curve := k256.NewCurve()
	tag0 := []byte("tag0")
	tag1 := []byte("tag1")

	f, err := ecbbot.NewPopf(tag0, tag1)
	require.NoError(t, err)

	x := byte(0)
	y, err := curve.Random(prng)
	require.NoError(t, err)
	s0, s1, err := f.Program(x, y, prng)
	require.NoError(t, err)
	y2, err := f.Eval(s0, s1, x)
	require.NoError(t, err)
	require.True(t, y.Equal(y2))
	y3, err := f.Eval(s0, s1, 1-x)
	require.NoError(t, err)
	require.False(t, y.Equal(y3))

	x = byte(1)
	y, err = curve.Random(prng)
	require.NoError(t, err)
	s0, s1, err = f.Program(x, y, prng)
	require.NoError(t, err)
	y2, err = f.Eval(s0, s1, x)
	require.NoError(t, err)
	require.True(t, y.Equal(y2))

	y3, err = f.Eval(s0, s1, 1-x)
	require.NoError(t, err)
	require.False(t, y.Equal(y3))
}
