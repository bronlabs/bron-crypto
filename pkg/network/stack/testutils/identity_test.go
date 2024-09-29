package testutils_test

import (
	crand "crypto/rand"
	"github.com/copperexchange/krypton-primitives/pkg/base/curves/p256"
	"github.com/copperexchange/krypton-primitives/pkg/network/stack/testutils"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_IdentitySignVerify(t *testing.T) {
	curve := p256.NewCurve()
	prng := crand.Reader
	sk, err := curve.ScalarField().Random(prng)
	require.NoError(t, err)
	pk := curve.ScalarBaseMult(sk)
	message := []byte("hello world")

	identityKey := testutils.NewTestIdentityKey(pk)
	authKey := testutils.NewTestAuthKey(sk)

	signature := authKey.Sign(message)
	err = authKey.Verify(signature, message)
	require.NoError(t, err)
	err = identityKey.Verify(signature, message)
	require.NoError(t, err)
}
