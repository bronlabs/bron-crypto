package ecdsa_test

import (
	"crypto"
	crand "crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/p256"
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

func Test_DeterministicHappyPath(t *testing.T) {
	t.Parallel()
	prng := crand.Reader
	hashId := crypto.SHA256
	suite, err := ecdsa.NewDeterministicSuite(hashId)
	require.NoError(t, err)
	var message [64]byte
	_, err = io.ReadFull(prng, message[:])
	require.NoError(t, err)

	skValue, err := p256.NewScalarField().Random(prng)
	require.NoError(t, err)
	pkValue := p256.NewCurve().ScalarBaseMul(skValue)

	pk, err := ecdsa.NewPublicKey(pkValue)
	require.NoError(t, err)
	sk, err := ecdsa.NewPrivateKey(skValue, pk)
	require.NoError(t, err)

	scheme, err := ecdsa.NewScheme(suite, prng)
	require.NoError(t, err)
	signer, err := scheme.Signer(sk)
	require.NoError(t, err)
	signature1, err := signer.Sign(message[:])
	require.NoError(t, err)
	signature2, err := signer.Sign(message[:])

	verifier, err := scheme.Verifier()
	require.NoError(t, err)
	err = verifier.Verify(signature1, pk, message[:])
	require.NoError(t, err)
	err = verifier.Verify(signature2, pk, message[:])
	require.NoError(t, err)

	require.True(t, signature1.Equal(signature2))

	recoveredPk1, err := ecdsa.RecoverPublicKey(suite, signature1, message[:])
	require.NoError(t, err)
	require.True(t, recoveredPk1.Equal(pk))

	recoveredPk2, err := ecdsa.RecoverPublicKey(suite, signature2, message[:])
	require.NoError(t, err)
	require.True(t, recoveredPk2.Equal(pk))
}
