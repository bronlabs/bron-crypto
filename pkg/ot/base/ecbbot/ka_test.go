package ecbbot_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/algebra"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
	"github.com/bronlabs/bron-crypto/pkg/base/prng/pcg"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

func Test_TaggedKeyAgreementHappyPath(t *testing.T) {
	t.Parallel()

	t.Run("k256", func(t *testing.T) {
		t.Parallel()
		kaHappyPath(t, k256.NewCurve())
	})
	t.Run("p256", func(t *testing.T) {
		t.Parallel()
		kaHappyPath(t, p256.NewCurve())
	})
}

func kaHappyPath[GE algebra.PrimeGroupElement[GE, SE], SE algebra.PrimeFieldElement[SE]](tb testing.TB, group algebra.PrimeGroup[GE, SE]) {
	tb.Helper()

	tag := []byte("test_tag")
	prng := pcg.NewRandomised()

	tka, err := ecbbot.NewTaggedKeyAgreement(group)
	require.NoError(tb, err)

	a, err := tka.R(prng)
	require.NoError(tb, err)
	ms, err := tka.Msg1(a)
	require.NoError(tb, err)
	b, err := tka.R(prng)
	require.NoError(tb, err)
	mr, err := tka.Msg2(b, ms)
	require.NoError(tb, err)
	k1, err := tka.Key1(a, mr, tag)
	require.NoError(tb, err)
	k2, err := tka.Key2(b, ms, tag)
	require.NoError(tb, err)

	require.True(tb, k1.Equal(k2))
}
