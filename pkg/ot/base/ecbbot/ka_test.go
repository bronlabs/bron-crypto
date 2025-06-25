package ecbbot_test

import (
	crand "crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/ot/base/ecbbot"
)

func Test_TaggedKeyAgreementHappyPath(t *testing.T) {
	t.Parallel()

	curve := k256.NewCurve()
	tag := []byte("test_tag")
	prng := crand.Reader

	ka, err := ecbbot.NewTaggedKeyAgreement(curve)
	require.NoError(t, err)

	a, err := ka.R(prng)
	require.NoError(t, err)
	ms, err := ka.Msg1(a)
	require.NoError(t, err)
	b, err := ka.R(prng)
	require.NoError(t, err)
	mr, err := ka.Msg2(b, ms)
	require.NoError(t, err)
	k1, err := ka.Key1(a, mr, tag)
	require.NoError(t, err)
	k2, err := ka.Key2(b, ms, tag)
	require.NoError(t, err)

	require.True(t, k1.Equal(k2))
}
