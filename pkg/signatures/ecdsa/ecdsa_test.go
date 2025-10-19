package ecdsa_test

import (
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/k256"
	"github.com/bronlabs/bron-crypto/pkg/signatures/ecdsa"
)

func Test_HappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	curve := k256.NewCurve()
	hashFunc := sha256.New
	suite, err := ecdsa.NewSuite(curve, hashFunc)
	require.NoError(t, err)
	var message [64]byte
	_, err = io.ReadFull(prng, message[:])
	require.NoError(t, err)

	skValue, err := k256.NewScalarField().Random(prng)
	require.NoError(t, err)
	pkValue := k256.NewCurve().ScalarBaseMul(skValue)

	pk, err := ecdsa.NewPublicKey(pkValue)
	require.NoError(t, err)
	sk, err := ecdsa.NewPrivateKey(skValue, pk)
	require.NoError(t, err)

	scheme, err := ecdsa.NewScheme(suite, prng)
	require.NoError(t, err)
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature, err := signer.Sign(message[:])
	require.NoError(t, err)
	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature, pk, message[:])
	require.NoError(t, err)

	recoveredPk, err := ecdsa.RecoverPublicKey(suite, signature, message[:])
	require.NoError(t, err)
	require.True(t, recoveredPk.Equal(pk))
}
